from typing import Annotated

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette import status
from models import Business, BusinessMembers, Earnings, Adverts, MPFees, CustomersBalance, MerchantBalance, MarketPlaceOrders
from database import SessionLocal
from .auth import get_current_user
from .users import get_otp
from utils.auth import get_kite_mpfee, debit, sign_record, verify_sig, balance_log, market_prices, top_up, get_round_value
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
    payment_details: int
    payment_window: str


class EditAdvert(BaseModel):
    rate: int
    min: int
    max: int
    payment_method: str
    payment_details: int
    payment_window: str


class SellRequest(BaseModel):
    amount: int
    payment_details: int


class BuyRequest(BaseModel):
    amount: int


class PaidReq(BaseModel):
    fileUrl: str


class CompleteReq(BaseModel):
    confirm: bool

@router.post("/create-advert", status_code=status.HTTP_201_CREATED)
async def create_advert(user: user_dependency, db: db_dependency, create_advert: CreateAdvert):
    prices = market_prices()
    if create_advert.trade_option == 'sell':
        # Check balance
        if user.get('user_role') == 'customer':
            balance = db.query(CustomersBalance).filter(CustomersBalance.customer_id == user.get('id'))\
                .filter(CustomersBalance.business_id == user.get('bid')).filter(CustomersBalance.asset == create_advert.asset).first()
        if user.get('user_role') == 'owner':
            balance = db.query(MerchantBalance).filter(MerchantBalance.business_id == user.get('bid'))\
                .filter(MerchantBalance.asset == create_advert.asset).first()
        if balance is None:
            return {'status': 'fail', 'message': 'insufficient funds, top up and try again.'}
        usd_bal = float(balance.balance)*float(prices[create_advert.asset])
        #print(usd_bal)
        if not balance_log(db, balance.balance, user.get('bid'), user.get('id'), user.get('user_role'), create_advert.asset):
            return {'status': 'fail', 'message': 'Could not sync balance. If this continues please report the issue.'}
        if usd_bal < create_advert.max:
            return {'status': 'fail', 'message': 'insufficient funds, top up and try again!'}

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

    prices = market_prices()
    if advert.trade_option == 'sell':
        # Check balance
        if user.get('user_role') == 'customer':
            balance = db.query(CustomersBalance).filter(CustomersBalance.customer_id == user.get('id'))\
                .filter(CustomersBalance.business_id == user.get('bid')).filter(CustomersBalance.asset == advert.asset).first()
        if user.get('user_role') == 'owner':
            balance = db.query(MerchantBalance).filter(MerchantBalance.business_id == user.get('bid'))\
                .filter(MerchantBalance.asset == advert.asset).first()
        if balance is None:
            return {'status': 'fail', 'message': 'insufficient funds, top up and try again.'}
        usd_bal = float(balance.balance)*float(prices[advert.asset])
        if not balance_log(db, balance.balance, user.get('bid'), user.get('id'), user.get('user_role'), advert.asset):
            return {'status': 'fail', 'message': 'Could not sync balance. If this continues please report the issue.'}
        if usd_bal < edit_advert.max:
            return {'status': 'fail', 'message': 'insufficient funds, top up and try again!'}

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
        return {'status': 'fail', 'message': 'Amount less than minimum accepted $%s for this order' % advert.min}
    if sell_request.amount > advert.max:
        return {'status': 'fail', 'message': 'Amount greater than maximum accepted $%s for this order' % advert.max}

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
        balance = db.query(CustomersBalance).filter(CustomersBalance.customer_id == user.get('id'))\
            .filter(CustomersBalance.business_id == user.get('bid')).filter(CustomersBalance.asset == advert.asset).first()
    if user.get('user_role') == 'owner':
        balance = db.query(MerchantBalance).filter(MerchantBalance.business_id == user.get('bid'))\
            .filter(MerchantBalance.asset == advert.asset).first()
    if balance is None:
        return {'status': 'fail', 'message': 'insufficient funds, top up and try again.'}
    usd_bal = float(balance.balance)*float(prices[advert.asset])
    if not balance_log(db, balance.balance, user.get('bid'),user.get('id'), user.get('user_role'), advert.asset):
        return {'status': 'fail', 'message': 'Could not sync balance. If this continues please report the issue.'}
    if usd_bal < sell_request.amount:
        return {'status': 'fail', 'message': 'insufficient funds, top up and try again!'}
    # create the order
    order = MarketPlaceOrders(
        business_id=user.get('bid'),
        buyer=advert.inputter,
        seller=user.get('id'),
        created_by=advert.created_by,
        engaged_by=user.get('user_role'),
        trade_option='sell',
        currency='',
        asset=advert.asset,
        rate=advert.rate,
        amount=float(sell_request.amount)/float(prices[advert.asset]),
        amount_usd=sell_request.amount,
        taker_fee=taker,
        maker_fee=maker,
        payment_method=advert.payment_method,
        payment_details=sell_request.payment_details,
        time_started=datetime.today().strftime('%Y-%m-%d %H-%M-%S'),
        status='open'
    )
    db.add(order)
    db.commit()
    insert_id = order.id
    sig = sign_record(order.seller, order, 'trade')
    order.sig=sig
    db.add(order)
    db.commit()

    return {'status': 'success', 'message': 'Placed on sell, waiting settlement'}


@router.post("/buy/{advert_id}", status_code=status.HTTP_200_OK)
async def sell(user: user_dependency, db: db_dependency, buy_request: BuyRequest, advert_id: int = Path(gt=0)):
    if buy_request.amount < 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than 0")
    advert = db.query(Adverts).filter(Adverts.id == advert_id).first()
    # validations
    if advert.created_by == 'customer' and user.get('user_role') == 'customer':
        if user.get('id') == advert.inputter:
            return {'status': 'fail', 'message': 'You cannot buy your own advert'}
    if advert.created_by == 'owner' and user.get('user_role') == 'owner':
        if user.get('id') == advert.inputter:
            return {'status': 'fail', 'message': 'You cannot buy your own advert'}
    if buy_request.amount < advert.min:
        return {'status': 'fail', 'message': 'Amount less than minimum accepted $%s for this order' % advert.min}
    if buy_request.amount > advert.max:
        return {'status': 'fail', 'message': 'Amount greater than maximum accepted $%s for this order' % advert.max}

    # Get fees
    mp_fees = db.query(MPFees).filter(MPFees.business_id == user.get('bid'))\
        .filter(MPFees.min < buy_request.amount).filter(MPFees.max > buy_request.amount).first()

    if mp_fees is None:
        mp_fees = db.query(MPFees).filter(MPFees.business_id == user.get('bid')) \
            .filter(MPFees.min < buy_request.amount).first()
    fee = buy_request.amount*(mp_fees.fee/100)
    maker = fee*(mp_fees.maker/100)
    taker = fee*(mp_fees.taker/100)
    prices = market_prices()

    # Check balance of advert creator to know if advert is still valid
    if advert.created_by == 'customer':
        balance = db.query(CustomersBalance).filter(CustomersBalance.customer_id == advert.inputter).filter(CustomersBalance.asset == advert.asset)\
            .filter(CustomersBalance.business_id == user.get('bid')).first()
    if advert.created_by == 'owner':
        balance = db.query(MerchantBalance).filter(MerchantBalance.business_id == advert.inputter)\
            .filter(MerchantBalance.asset == advert.asset).first()
    if balance is None:
        return {'status': 'fail', 'message': 'advert is no longer valid.'}
    usd_bal = float(balance.balance)*float(prices[advert.asset])
    if not balance_log(db, balance.balance, advert.business_id, advert.inputter, advert.created_by, advert.asset):
        return {'status': 'fail', 'message': 'Advert validation failed.'}
    if usd_bal < buy_request.amount:
        return {'status': 'fail', 'message': 'Advert is no longer available!'}
    # create the order
    order = MarketPlaceOrders(
        business_id=user.get('bid'),
        buyer=user.get('id'),
        seller=advert.inputter,
        created_by=advert.created_by,
        engaged_by=user.get('user_role'),
        trade_option='buy',
        currency='',
        asset=advert.asset,
        rate=advert.rate,
        amount=float(buy_request.amount)/float(prices[advert.asset]),
        amount_usd=buy_request.amount,
        taker_fee=taker,
        maker_fee=maker,
        payment_method=advert.payment_method,
        payment_details=advert.payment_details,
        time_started=datetime.today().strftime('%Y-%m-%d %H-%M-%S'),
        status='open'
    )
    db.add(order)
    db.commit()
    insert_id = order.id
    sig = sign_record(order.seller, order, 'trade')
    order.sig=sig
    db.add(order)
    db.commit()

    return {'status': 'success', 'message': 'Order placed, waiting your payment'}


@router.put("/paid/{order_id}", status_code=status.HTTP_200_OK)
async def paid(user: user_dependency, db: db_dependency, paid_req: PaidReq, order_id : int = Path(gt=0)):

    order = db.query(MarketPlaceOrders).filter(MarketPlaceOrders.id == order_id).first()
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.trade_option == 'sell' and user.get('id') != order.buyer:
        raise HTTPException(status_code=403, detail="Permission denied")
    if order.trade_option == 'buy' and user.get('id') != order.buyer:
        raise HTTPException(status_code=403, detail="Permission denied")
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')

    order.cash_pop = paid_req.fileUrl
    order.time_settled = stamp
    order.status = "waiting_1"
    sig = sign_record(user.get('id'), order, 'trade')
    order.sig = sig
    db.add(order)
    db.commit()

    return {'status': 'success', 'message': 'Trade marked as paid'}


@router.put("/complete/{order_id}", status_code=status.HTTP_200_OK)
async def confirm_trade(user: user_dependency, db: db_dependency, complete_req: CompleteReq, order_id: int = Path(gt=0)):
    if not complete_req.confirm:
        return {'status': 'fail', 'message': 'Confirmation was terminated'}

    order = db.query(MarketPlaceOrders).filter(MarketPlaceOrders.id == order_id).first()
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.status == 'completed':
        return {'status': 'fail', 'message': 'Order already completed'}

    if order.trade_option == 'sell' and user.get('id') != order.seller:
        raise HTTPException(status_code=403, detail="Permission denied")
    if order.trade_option == 'buy' and user.get('id') != order.seller:
        raise HTTPException(status_code=403, detail="Permission denied")
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')

    if not verify_sig(order.sig, order.buyer, order, 'trade'):
        raise HTTPException(status_code=400, detail="Could not complete trade")

    # commence credit & debit
    if order.trade_option == 'sell':
        role = order.created_by
    if order.trade_option == 'buy':
        role = order.engaged_by

    # remove fees
    # identify taker and maker
    if order.trade_option == 'sell':
        maker = order.buyer
        taker = order.seller
    if order.trade_option == 'buy':
        maker = order.seller
        taker = order.buyer
    maker_fee = order.maker_fee #usd
    taker_fee = order.taker_fee #usd
    total_fee = maker_fee+taker_fee #usd
    asset_rate_usd = round(order.amount_usd/order.amount, 2)
    round_value = get_round_value(order.asset)
    amount_after_fee = round(order.amount - round(total_fee/asset_rate_usd, round_value), round_value)

    # credit buyer
    if order.buyer == maker:
        credit_amount = round(amount_after_fee - (round(maker_fee/asset_rate_usd, round_value)), round_value)
    if order.buyer == taker:
        credit_amount = round(amount_after_fee - (round(taker_fee/asset_rate_usd, round_value)), round_value)
    top_up(db, order.business_id, order.buyer, role, order.asset, credit_amount)

    # debit seller
    if order.trade_option == 'sell':
        role = order.engaged_by
    if order.trade_option == 'buy':
        role = order.created_by
    debit(db, order.business_id, order.seller, role, order.asset, order.amount)

    # mark as completed
    order.status = 'completed'
    order.time_completed = stamp
    sig = sign_record(user.get('id'), order, 'trade')
    order.sig = sig

    db.add(order)
    db.commit()

    # credit merchant
    kite_fee = get_kite_mpfee(db, order.business_id)
    earned = round((total_fee - total_fee*kite_fee)/asset_rate_usd, round_value) #subtract Kite fee
    top_up(db, order.business_id, order.business_id, 'owner', order.asset, earned)

    # log earning
    narration = "Revenue from trade #MP000"+str(order.id)
    new_earning = Earnings(
        business_id=order.business_id,
        asset=order.asset,
        amount=earned,
        narration=narration,
        date_created=stamp
    )
    db.add(new_earning)
    db.commit()
    sig = sign_record(order.business_id, new_earning, 'earning')
    new_earning.sig = sig
    db.add(new_earning)
    db.commit()

    return {'status': 'success', 'message': 'Trade successfully completed!'}



