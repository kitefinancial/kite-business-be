from typing import Annotated

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette import status
from models import Business, BusinessMembers, Wallet, OTCRate, OTCFEE
from database import SessionLocal
from .auth import get_current_user
from .users import get_otp
from utils.auth import get_auth_code, get_random_str, sign_record, verify_sig
from datetime import datetime


router = APIRouter(
    prefix='/settings',
    tags=['settings']
)

SECRET_KEY = '40de7e2a4658627eba27255bbe67152e3eca39bf4bc3f7279c643ce63401b7b8'
ALGORITHM = 'HS256'
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


class UserVerification(BaseModel):
    password: str
    new_password: str = Field(min_length=6)


class OtpRequest(BaseModel):
    code_1: str # email
    code_2: str # sms, optional only for actions that requires email and sms verification
    action: str
    reason: str

class GetOtpRequest(BaseModel):
    action: str
    reason: str

class AddMemberRequest(BaseModel):
    email: str
    first_name: str
    last_name: str
    job_title: str
    role: str


class BasicInfoRequest(BaseModel):
    business_name: str
    region: str
    link: str
    phone_number: str
    phone_code: str


class WalletRequest(BaseModel):
    nickname: str
    provider: str
    asset: str
    network: str
    address: str
    code_1: str
    code_2: str

class SetRateRequest(BaseModel):
    wallet: int
    asset: str
    min_amount: int
    max_amount: int
    sell: int
    buy: int


class SetOtcFee(BaseModel):
    split_fee: bool
    charge_customer: bool
    charge_me: bool
    merchant_pay: int
    customer_pay: int



@router.put("/basic-info", status_code=status.HTTP_200_OK)
async def update_info(db: db_dependency, user: user_dependency, info_request: BasicInfoRequest):
    if user.get('user_role') != 'owner':
        raise HTTPException(status_code=403, detail="Permission denied.")
    user_model = db.query(Business).filter(Business.id == user.get('id')).first()
    user_model.business_name = info_request.business_name
    user_model.region = info_request.region
    user_model.link = info_request.link
    otp = False
    if user_model.phone_number != info_request.phone_number:
        user_model.tmp_value = info_request.phone_number
        otp = True

    db.add(user_model)
    db.commit()
    if otp:
        code_1 = get_auth_code()
        code_1_plain = code_1['code_plain']
        code_1_hashed = code_1['code_hashed']
        user_model.sms_auth_code = code_1_hashed
        user_model.auth_stamp = datetime.today().strftime('%Y-%m-%-d %H-%M-%S')
        db.add(user_model)
        db.commit()

        # Todo: send sms to phone number

    return {'status': 'success', 'message': 'update was successful'}


@router.post("/add-wallet", status_code=status.HTTP_201_CREATED)
async def add_wallet(user: user_dependency, db: db_dependency, wallet_request: WalletRequest):
    if user.get('user_role') != 'owner':
        raise HTTPException(status_code=403, detail="Permission denied")
    user_model = db.query(Business).filter(Business.id == user.get('id')).first()
    if user_model.sms_auth_code == '' or user_model.email_auth_code == '':
        raise HTTPException(status_code=403, detail="Permission denied")
    if not bcrypt_context.verify(wallet_request.code_1, user_model.email_auth_code):
        return {'status': 'failed', 'message': 'Invalid email code'}
    if not bcrypt_context.verify(wallet_request.code_2, user_model.sms_auth_code):
        return {'status': 'failed', 'message': 'Invalid sms code'}

    data = {'owner': user.get('id'), 'nickname': wallet_request.nickname, 'provider': wallet_request.provider,\
            'asset': wallet_request.asset, 'network': wallet_request.network, 'address': wallet_request.address}
    signature = sign_record(user.get('id'), data, 'wallet')
    new_wallet = Wallet(
        owner=user.get('id'),
        nickname=wallet_request.nickname,
        provider=wallet_request.provider,
        asset=wallet_request.asset,
        network=wallet_request.network,
        address=wallet_request.address,
        date_created=datetime.today().strftime('%Y-%m-%d %H-%M-%S'),
        sig=signature,
        flag='no'
    )

    db.add(new_wallet)
    db.commit()

    user_model.email_auth_code=''
    user_model.sms_auth_code=''
    db.add(user_model)
    db.commit()

    return {'status': 'success', 'message': 'Wallet successfully added'}


@router.get("/get-wallets", status_code=status.HTTP_200_OK)
async def get_wallets(user: user_dependency, db: db_dependency):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    wallets = db.query(Wallet).filter(Wallet.owner == user.get('bid')).all()
    owner = user.get('bid')
    type = 'wallet'
    all_wallets = {}
    i=0
    for row in wallets:
        data = {'nickname': row.nickname, 'provider': row.provider, 'asset': row.asset,\
                                 'network': row.network, 'address': row.address}
        data2 = {'id': row.id, 'nickname': row.nickname, 'provider': row.provider, 'asset': row.asset,\
                                 'network': row.network, 'address': row.address}
        current_sig = row.sig
        if not verify_sig(current_sig, owner, data, type):
            continue
        all_wallets.update({i: data2})
        i=i+1

    return all_wallets


@router.delete("/delete-wallet/{wallet_id}", status_code=status.HTTP_200_OK)
async def delete_rate(user: user_dependency, db: db_dependency, wallet_id: int = Path(gt=0)):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")
    wallet = db.query(Wallet).filter(Wallet.id == wallet_id).first()
    if wallet is None:
        raise HTTPException(status_code=404, detail="Not found")
    db.query(Wallet).filter(Wallet.id == wallet_id).delete()
    db.commit()

    return {'status': 'success', 'message': 'Wallet deleted'}


@router.post("/set-rate", status_code=status.HTTP_201_CREATED)
async def set_rate(user: user_dependency, db: db_dependency, rate_request: SetRateRequest):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")
    if not user:
        raise HTTPException(status_code=403, detail="Permission denied")

    if rate_request.min_amount >= rate_request.max_amount:
        return {'status': 'failed', 'message': 'Minimum amount must be less than maximum'}

    set_rate = OTCRate(
        owner=user.get('bid'),
        wallet=rate_request.wallet,
        asset=rate_request.asset,
        min_amount=rate_request.min_amount,
        max_amount=rate_request.max_amount,
        sell=rate_request.sell,
        buy=rate_request.buy,
        date_created=datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    )

    db.add(set_rate)
    db.commit()

    return {'status': 'success', 'message': 'Rate successfully set'}


@router.get("/get-rates", status_code=status.HTTP_200_OK)
async def get_rates(user: user_dependency, db: db_dependency):
    rates = db.query(OTCRate).filter(OTCRate.owner == user.get('bid')).all()
    return rates


@router.put("/edit-rate/{rate_id}", status_code=status.HTTP_200_OK)
async def edit_rate(user: user_dependency, db: db_dependency,
                    edit_rate_request: SetRateRequest,
                    rate_id: int = Path(gt=0)):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    rate = db.query(OTCRate).filter(OTCRate.id == rate_id).first()
    if rate is None:
        raise HTTPException(status_code=404, detail="Not found")
    rate.wallet=edit_rate_request.wallet
    rate.asset=edit_rate_request.asset
    rate.min_amount=edit_rate_request.min_amount
    rate.max_amount=edit_rate_request.max_amount
    rate.sell=edit_rate_request.sell
    rate.buy=edit_rate_request.buy

    db.add(rate)
    db.commit()

    return {'status': 'success', 'message': 'Rate edited'}


@router.delete("/delete-rate/{rate_id}", status_code=status.HTTP_200_OK)
async def delete_rate(user: user_dependency, db: db_dependency, rate_id: int = Path(gt=0)):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    rate = db.query(OTCRate).filter(OTCRate.id == rate_id).first()
    if rate is None:
        raise HTTPException(status_code=404, detail="Not found")
    db.query(OTCRate).filter(OTCRate.id == rate_id).delete()
    db.commit()

    return {'status': 'success', 'message': 'Rate deleted'}



@router.post("/otc-fee", status_code=status.HTTP_200_OK)
async def set_otc_fee(user: user_dependency, db: db_dependency, set_otc_fee: SetOtcFee):
    if user.get('user_role') != 'owner':
        raise HTTPException(status_code=403, detail="Permission denied")

    if set_otc_fee.split_fee:
        if set_otc_fee.customer_pay+set_otc_fee.merchant_pay != 100:
            return {'status': 'When splitting fees you and customer must make up 100% of fees'}
    otc_fee = OTCFEE(
        owner=user.get('id'),
        kite_fee=0.5,
        split_fee=set_otc_fee.split_fee,
        charge_customer=set_otc_fee.charge_customer,
        charge_me=set_otc_fee.charge_me,
        merchant_pay=set_otc_fee.merchant_pay,
        customer_pay=set_otc_fee.customer_pay,
        date_created=datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    )

    db.add(otc_fee)
    db.commit()

    return {'status': 'success', 'message': 'OTC Fees updated'}


@router.get("/otc-fee", status_code=status.HTTP_200_OK)
async def get_otc_fee(user: user_dependency, db: db_dependency):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")
    otc_fee = db.query(OTCFEE).filter(OTCFEE.owner == user.get('bid')).first()

    if otc_fee is None:
        return {'status': 'success', 'message': 'no records'}
    return otc_fee

@router.put("/otc-fee/{otc_fee_id}", status_code=status.HTTP_201_CREATED)
async def update_otc_fee(user: user_dependency, db: db_dependency, set_otc_fee: SetOtcFee, otc_fee_id: int = Path(gt=0)):
    if user.get('user_role') != 'owner':
        raise HTTPException(status_code=403, detail="Permission denied")

    if set_otc_fee.split_fee:
        if set_otc_fee.customer_pay+set_otc_fee.merchant_pay != 100:
            return {'status': 'When splitting fees you and customer must make up 100% of fees'}

    otc_fee = db.query(OTCFEE).filter(OTCFEE.id == otc_fee_id).first()

    otc_fee.split_fee = set_otc_fee.split_fee
    otc_fee.charge_customer = set_otc_fee.charge_customer
    otc_fee.charge_me = set_otc_fee.charge_me
    otc_fee.merchant_pay = set_otc_fee.merchant_pay
    otc_fee.customer_pay = set_otc_fee.customer_pay
    otc_fee.date_created = datetime.today().strftime('%Y-%m-%d %H-%M-%S')

    db.add(otc_fee)
    db.commit()

    return {'status': 'success', 'message': 'OTC fee updated'}
