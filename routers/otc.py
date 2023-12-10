from typing import Annotated

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette import status
from models import Business, BusinessMembers, Wallet, OTCRate, OTCFEE, OTCORDERS
from database import SessionLocal
from .auth import get_current_user
from .users import get_otp
from utils.auth import get_auth_code, get_random_str, sign_record, verify_sig
from datetime import datetime


router = APIRouter(
    prefix='/otc',
    tags=['otc']
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


class CreateOrder(BaseModel):
    currency: str
    trade_option: str
    amount: float
    amount_usd: int
    asset: str
    rate: int
    merchant_fee: int
    customer_fee: int
    wallet: int
    payment_details: str




@router.get("/{business_id}", status_code=status.HTTP_200_OK)
async def otc_details(db: db_dependency, business_id: int = Path(gt=0)):
    business = db.query(Business).filter(Business.id == business_id).first()

    if business is None:
        raise HTTPException(status_code=404, detail="Business not found")
    otc_fee = db.query(OTCFEE).filter(OTCFEE.owner == business_id).first()
    otc_rate = db.query(OTCRate).filter(OTCRate.owner == business_id).all()

    assets = {}
    a = 0
    for i in otc_rate:
        rates = {'asset': i.asset, 'wallet': i.wallet, 'min_amount': i.min_amount,\
                       'max_amount': i.max_amount, 'sell': i.sell, 'buy': i.buy}
        assets.update({a: rates})
        a=a+1

    otc_data = {'kite_fee': otc_fee.kite_fee, 'split_fee': otc_fee.split_fee,\
                'charge_customer': otc_fee.charge_customer, 'charge_me': otc_fee.charge_me, 'merchant_pay': otc_fee.merchant_pay\
                ,'customer_pay': otc_fee.customer_pay, 'assets': assets}

    return otc_data


@router.post("otc/create-order", status_code=status.HTTP_201_CREATED)
async def create_order(user: user_dependency, db: db_dependency, order_req: CreateOrder):
    if user.get('user_role') != 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    if order_req.trade_option == 'buy':
        buyer = user.get('id')
        seller = user.get('bid')
    if order_req.trade_option == 'sell':
        buyer = user.get('bid')
        seller = user.get('id')
    order = OTCORDERS(
        business_id=user.get('bid'),
        wallet=order_req.wallet,
        buyer=buyer,
        seller=seller,
        trade_option=order_req.trade_option,
        currency=order_req.currency,
        asset=order_req.asset,
        rate=order_req.rate,
        amount=order_req.amount,
        amount_usd=order_req.amount_usd,
        merchant_fee=order_req.merchant_fee,
        customer_fee=order_req.customer_fee,
        payment_details=order_req.payment_details,
        time_started=stamp,
        status='open'
    )