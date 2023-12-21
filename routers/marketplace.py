from typing import Annotated

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette import status
from models import Business, BusinessMembers, Wallet, Adverts, MPFees, CustomersBalance, MerchantBalance
from database import SessionLocal
from .auth import get_current_user
from .users import get_otp
from utils.auth import get_auth_code, get_random_str, sign_record, verify_sig, balance_log, market_prices
from datetime import datetime


router = APIRouter(
    prefix='/marketplace',
    tags=['marketplace']
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


class CreateAdvert(BaseModel):
    asset: str
    trade_option: str
    rate: int
    min: int
    max: int
    payment_method: str
    payment_details: str
    payment_window: str


class EditAdvert(BaseModel):
    rate: int
    min: int
    max: int
    payment_method: str
    payment_details: str
    payment_window: str


class SellRequest(BaseModel):
            amount: int

@router.post("/create-advert", status_code=status.HTTP_201_CREATED)
async def create_advert(user: user_dependency, db: db_dependency, create_advert: CreateAdvert):

    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    advert = Adverts(
        business_id=user.get('bid'),
        inputter=user.get('id'),
        asset=create_advert.asset,
        trade_option=create_advert.trade_option,
        rate=create_advert.rate,
        min=create_advert.min,
        max=create_advert.max,
        created_by=user.get('user_role'),
        payment_method=create_advert.payment_method,
        payment_details=create_advert.payment_details,
        payment_window=create_advert.payment_window,
        date_created=stamp
    )

    db.add(advert)
    db.commit()

    return {'status': 'success', 'message': 'Advert successfully created'}


@router.get("/my-adverts", status_code=status.HTTP_200_OK)
async def my_adverts(user: user_dependency, db: db_dependency):
    if user.get('user_role') == 'owner':
        raise HTTPException(status_code=401, detail="Customers only")
    advert = db.query(Adverts).filter(Adverts.inputter == user.get('id')).all()

    return advert


@router.put("/edit-advert/{advert_id}", status_code=status.HTTP_200_OK)
async def edit_advert(user: user_dependency, db: db_dependency, edit_advert: EditAdvert, advert_id: int = Path(gt=0)):
    advert = db.query(Adverts).filter(Adverts.id == advert_id).filter(Adverts.inputter == user.get('id')).first()

    if advert is None:
        raise HTTPException(status_code=404, detail="Advert not found")

    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    advert.rate = edit_advert.rate
    advert.min = edit_advert.min
    advert.max = edit_advert.max
    advert.payment_method = edit_advert.payment_method
    advert.payment_details = edit_advert.payment_details
    advert.payment_window = edit_advert.payment_window

    db.add(advert)
    db.commit()

    return {'status': 'success', 'message': 'Advert edited'}


@router.delete("/delete-advert/{advert_id}", status_code=status.HTTP_200_OK)
async def delete_advert(user: user_dependency, db: db_dependency, advert_id: int = Path(gt=0)):

    advert = db.query(Adverts).filter(Adverts.id == advert_id).first()
    if advert is None:
        raise HTTPException(status_code=404, detail="Not found")

    if user.get('id') != advert.inputter and user.get('id') != advert.business_id:
        raise HTTPException(status_code=401, detail="Permission denied")

    db.query(Adverts).filter(Adverts.id == advert_id).delete()
    db.commit()

    return {'status': 'success', 'message': 'Advert deleted'}


@router.get("/all-adverts/{business_id}", status_code=status.HTTP_200_OK)
async def all_adverts(db: db_dependency, business_id: int = Path(gt=0)):
    adverts = db.query(Adverts).filter(Adverts.business_id == business_id).all()

    return adverts


@router.post("/sell/{advert_id}", status_code=status.HTTP_200_OK)
async def sell(user: user_dependency, db: db_dependency, sell_request: SellRequest, advert_id: int = Path(gt=0)):
    if sell_request.amount < 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than 0")
    advert = db.query(Adverts).filter(Adverts.id == advert_id).first()
    # validations
    if advert.created_by == 'customer' and user.get('user_role') == 'customer':
        if user.get('id') == advert.inputter:
            return {'status': 'fail', 'message': 'You cannot sell to your own advert'}
    if advert.created_by == 'owner' and user.get('user_role') == 'owner':
        if user.get('id') == advert.inputter:
            return {'status': 'fail', 'message': 'You cannot sell to your own advert'}
    if sell_request.amount < advert.min:
        return {'status': 'fail', 'message': 'Amount less than minimum accepted $%s by this order' % advert.min}
    if sell_request.amount > advert.max:
        return {'status': 'fail', 'message': 'Amount greater than maximum accepted $%s by this order' % advert.max}

    # Get fees
    mp_fees = db.query(MPFees).filter(MPFees.business_id == user.get('bid'))\
        .filter(MPFees.min < sell_request.amount).filter(MPFees.max > sell_request.amount).first()

    if mp_fees is None:
        mp_fees = db.query(MPFees).filter(MPFees.business_id == user.get('bid')) \
            .filter(MPFees.min < sell_request.amount).first()
    fee = sell_request.amount*(mp_fees.fee/100)
    maker = fee*(mp_fees.maker/100)
    taker = fee*(mp_fees.taker/100)
    prices = market_prices()

    # Check balance
    if user.get('user_role') == 'customer':
        balance = db.query(CustomersBalance).filter(CustomersBalance.customer_id == user.get('bid'))\
            .filter(CustomersBalance.asset == advert.asset).first()
    if user.get('user_role') == 'owner':
        balance = db.query(MerchantBalance).filter(MerchantBalance.business_id == user.get('bid'))\
            .filter(MerchantBalance.asset == advert.asset).first()
    if balance is None:
        return {'status': 'fail', 'message': 'insufficient funds, top up and try again.'}
    usd_bal = float(balance.balance)*float(prices[advert.asset])
    print(usd_bal)
    if not balance_log(db, balance.balance, user.get('id'), user.get('user_role'), advert.asset):
        return {'status': 'fail', 'message': 'Could not sync balance. If this continues please report the issue.'}
    if usd_bal < sell_request.amount:
        return {'status': 'fail', 'message': 'insufficient funds, top up and try again!'}
    return {'status': 'success', 'message': 'Placed on sell, waiting settlement'}
