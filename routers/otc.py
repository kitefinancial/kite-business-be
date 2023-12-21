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
    wallet: int
    payment_details: str


class PaidReq(BaseModel):
    hash: str
    fileUrl: str


class AdjustReq(BaseModel):
    amount_received: int


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


@router.post("/create-order", status_code=status.HTTP_201_CREATED)
async def create_order(user: user_dependency, db: db_dependency, order_req: CreateOrder):
    if user.get('user_role') != 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    if order_req.amount < 0 or order_req.amount_usd < 0:
        raise HTTPException(status_code=400, detail="amount must be less than 0")

    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    if order_req.trade_option == 'buy':
        buyer = user.get('id')
        seller = user.get('bid')
    if order_req.trade_option == 'sell':
        buyer = user.get('bid')
        seller = user.get('id')
    # calculate fees
    otc_fee = db.query(OTCFEE).filter(OTCFEE.owner == user.get('bid')).\
        filter(OTCFEE.min < order_req.amount_usd).filter(OTCFEE.max > order_req.amount_usd).first()
    if otc_fee is None:
        customer_fee = 0
        merchant_fee = (order_req.amount_usd*(otc_fee.kite_fee/100))
    if otc_fee.split_fee:
        customer_fee = (order_req.amount_usd*(otc_fee.kite_fee/100))*(otc_fee.customer_pay/100)
        merchant_fee = (order_req.amount_usd*(otc_fee.kite_fee/100))*(otc_fee.merchant_pay/100)
    if otc_fee.charge_me:
        customer_fee = 0
        merchant_fee = (order_req.amount_usd*(otc_fee.kite_fee/100))
    if otc_fee.charge_customer:
        customer_fee = (order_req.amount_usd*(otc_fee.kite_fee/100))
        merchant_fee = 0

    # Get wallet details
    wallet = db.query(Wallet).filter(Wallet.id == order_req.wallet).filter(Wallet.owner == user.get('bid')).first()
    if wallet is None:
        raise HTTPException(status_code=404, detail="Error in required info")
    # check wallet is not altered
    data = {'nickname': wallet.nickname, 'provider': wallet.provider, 'asset': wallet.asset, \
             'network': wallet.network, 'address': wallet.address}
    type = 'wallet'
    if not verify_sig(wallet.sig, user.get('bid'), data, type):
        raise HTTPException(status_code=402, detail="An error was encountered")
    address = wallet.address
    network = wallet.network

    order = OTCORDERS(
        business_id=user.get('bid'),
        wallet=order_req.wallet,
        network=network,
        address=address,
        buyer=buyer,
        seller=seller,
        trade_option=order_req.trade_option,
        currency=order_req.currency,
        asset=order_req.asset,
        rate=order_req.rate,
        amount=order_req.amount,
        amount_usd=order_req.amount_usd,
        merchant_fee=merchant_fee,
        customer_fee=customer_fee,
        payment_details=order_req.payment_details,
        time_started=stamp,
        status='open'
    )

    db.add(order)
    db.commit()
    insert_id = order.id

    return {'status': 'success', 'message': 'order created', 'id': insert_id}


@router.put("/paid/{order_id}", status_code=status.HTTP_200_OK)
async def paid(user: user_dependency, db: db_dependency, paid_req: PaidReq, order_id : int = Path(gt=0)):
    if user.get('user_role') != 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")
    order = db.query(OTCORDERS).filter(OTCORDERS.id == order_id).first()
    if order.trade_option == 'sell' and user.get('id') != order.seller:
        raise HTTPException(status_code=403, detail="Permission denied")
    if order.trade_option == 'buy' and user.get('id') != order.buyer:
        raise HTTPException(status_code=403, detail="Permission denied")
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    if order.trade_option == 'sell':
        order.crypto_pop = paid_req.fileUrl
        order.tx_hash = paid_req.hash

    if order.trade_option == 'buy':
        order.cash_pop = paid_req.fileUrl

    order.time_paid = stamp
    order.status = "waiting_1"
    db.add(order)
    db.commit()

    return {'status': 'success', 'message': 'Trade marked as paid'}


@router.put("/adjust/{order_id}", status_code=status.HTTP_200_OK)
async def adjust_order(user: user_dependency, db: db_dependency, adjust_req: AdjustReq, order_id : int = Path(gt=0)):
    if user.get('user_role') != 'owner':
        raise HTTPException(status_code=403, detail="Permission denied.")
    order = db.query(OTCORDERS).filter(OTCORDERS.id == order_id).first()
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    order.amount_received = adjust_req.amount_received
    order.time_adjusted = stamp

    db.add(order)
    db.commit()

    return {'status': 'success', 'message': 'Order price adjusted'}


@router.put("/settled/{order_id}", status_code=status.HTTP_200_OK)
async def settled(user: user_dependency, db: db_dependency, paid_req: PaidReq, order_id : int = Path(gt=0)):

    order = db.query(OTCORDERS).filter(OTCORDERS.id == order_id).first()
    if order.trade_option == 'sell' and user.get('id') != order.buyer:
        raise HTTPException(status_code=403, detail="Permission denied")
    if order.trade_option == 'buy' and user.get('id') != order.seller:
        raise HTTPException(status_code=403, detail="Permission denied")
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    if order.trade_option == 'sell':
        order.cash_pop = paid_req.fileUrl

    if order.trade_option == 'buy':
        order.crypto_pop = paid_req.fileUrl
        order.tx_hash = paid_req.hash

    order.time_settled = stamp
    order.time_completed = stamp
    order.status = "completed"
    db.add(order)
    db.commit()

    remit = db.query(Business).filter(Business.id == user.get('bid')).first()
    remit.kite_fee = (order.merchant_fee+order.customer_fee)
    db.add(remit)
    db.commit()
    return {'status': 'success', 'message': 'Trade marked as completed'}


@router.get("/all-orders/{business_id}", status_code=status.HTTP_200_OK)
async def all_orders(user: user_dependency, db: db_dependency, business_id: int = Path(gt=0)):
    if user.get('user_role') != 'owner' and user.get('id') != business_id:
        raise HTTPException(status_code=403, detail="Permission denied")

    orders = db.query(OTCORDERS).filter(OTCORDERS.business_id == business_id).all()

    return orders
