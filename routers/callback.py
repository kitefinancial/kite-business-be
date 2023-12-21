from typing import Annotated

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette import status
from models import Business, BusinessMembers, Wallet, Adverts, MPFees, Customers, CustomersBalance, MerchantBalance, CustomerActivity, MerchantActivity
from database import SessionLocal
from .auth import get_current_user
from .users import get_otp
from utils.auth import get_auth_code, get_random_str, sign_record, verify_sig, balance_log, market_prices, top_up
from datetime import datetime


router = APIRouter(
    prefix='/callback',
    tags=['callback']
)

SECRET_KEY = '40de7e2a4658627eba27255bbe67152e3eca39bf4bc3f7279c643ce63401b7b8'
ALGORITHM = 'HS256'
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
app_token = '357b5b619bd20d1b379a1bc5db54506b5e93cf45cb4c45af17eba6273bf6c1a1'

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


class CryptoDeposit(BaseModel):
    asset: str
    address: str
    amount: float
    confirmations: int
    hash: str
    app_token: str


@router.post("/crypto-deposit", status_code=status.HTTP_200_OK)
async def deposit(db: db_dependency, crypto_deposit: CryptoDeposit):
    if crypto_deposit.app_token != app_token:
        raise HTTPException(status_code=403, detail="Permission denied")
    stamp = datetime.today().strftime('%Y-%m-%d %H-M-%S')
    activity = db.query(CustomerActivity).filter(CustomerActivity.address == crypto_deposit.address)\
        .order_by(CustomerActivity.id.desc()).first()

    if activity is None:
        activity = db.query(MerchantActivity).filter(MerchantActivity.address == crypto_deposit.address)\
            .order_by(MerchantActivity.id.desc()).first()
        user = db.query(Business).filter(Business.id == activity.business_id).first()
        business_id = user.id
        role = 'owner'
    else:
        user = db.query(Customers).filter(Customers.id == activity.customer_id).first()
        business_id = user.business_id
        role = 'customer'
    if activity is None:
        raise HTTPException(status_code=400, detail="Address not found")
    # validation
    # check if transaction already credited using tx hash
    if activity.tx_hash == crypto_deposit.hash:
        return {'status': 'already credited'}
    # check for an empty invoice, else create one
    insert_id = activity.id
    if activity.sent_notify:
        # create an empty invoice with same address
        if not verify_sig(activity.sig, user.id, activity, 'activity'):
            raise HTTPException(status_code=400, detail="Bad request at invoice creation")
        if role == 'owner':

            invoice = MerchantActivity(
                business_id=business_id,
                asset=activity.asset,
                activity_type='receive',
                amount=0.0,
                rate_usd=0.0,
                address=activity.address,
                network=activity.network,
                memo='',
                fee=0.0,
                status='pending',
                confirmations=0,
                date_created=stamp,
                conf_notify=False,
                sent_notify=False,
                flag=False
            )
            db.add(invoice)
            db.commit()
            insert_id = invoice.id
            # update sig
            data = db.query(MerchantActivity).filter(MerchantActivity.id == insert_id).first()
            sig = sign_record(business_id, data, 'activity')
            data.sig = sig
            db.add(data)
            db.commit()

        if role == 'customer':
            invoice = CustomerActivity(
                business_id=business_id,
                customer_id=user.id,
                asset=activity.asset,
                activity_type='receive',
                amount=0.0,
                rate_usd=0.0,
                address=activity.address,
                network=activity.network,
                memo='',
                fee=0.0,
                status='pending',
                confirmations=0,
                date_created=stamp,
                conf_notify=False,
                sent_notify=False,
                flag=False
            )
            db.add(invoice)
            db.commit()
            insert_id = invoice.id
            # update sig
            data = db.query(CustomerActivity).filter(CustomerActivity.id == insert_id).first()
            sig = sign_record(user.id, data, 'activity')
            data.sig = sig
            db.add(data)
            db.commit()

    if role == 'owner':
        row = db.query(MerchantActivity).filter(MerchantActivity.id == insert_id).first()
    if role == 'customer':
        row = db.query(CustomerActivity).filter(CustomerActivity.id == insert_id).first()
    current_sig = row.sig
    if crypto_deposit.confirmations == 1:
        status = 'pending'
        if not verify_sig(current_sig,user.id,row, "activity"):
            raise HTTPException(status_code=400, detail="Bad request")
        # mark as confirming
        row.conf_notify=True
        row.amount = crypto_deposit.amount
        row.confirmations=1
        sig = sign_record(user.id, row, 'activity')
        row.sig = sig
        db.add(row)
        db.commit()

        # Todo: send notification to user

    if crypto_deposit.confirmations == 2:
        status = 'success'
        if not verify_sig(current_sig, user.id, row, "activity"):
            raise HTTPException(status_code=400, detail="Bad request")
        # mark as confirmed
        prices = market_prices()
        row.conf_notify = True
        row.sent_notify = True
        row.amount = crypto_deposit.amount
        row.status = status
        row.tx_hash = crypto_deposit.hash
        row.rate_usd = prices[row.asset]
        row.confirmations = 6
        sig = sign_record(user.id, row, 'activity')
        row.sig = sig
        db.add(row)
        db.commit()

        # Todo: send notification to user

        # add balance
        if not top_up(db, business_id, user.id, role, crypto_deposit.asset, crypto_deposit.amount):
            raise HTTPException(status_code=400, detail="Could not complete")

            # Todo: send notification

    return {'status': 'success', 'message': 'OK***'}

