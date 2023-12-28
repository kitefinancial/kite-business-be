from typing import Annotated
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, Path
from database import SessionLocal
import re
from models import Business, BusinessMembers, CustomersBalance, CustomerActivity, MerchantBalance, MerchantActivity, MarketPlaceOrders
from random import randint
from datetime import datetime
from passlib.context import CryptContext
import random
import string
import requests

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
sig_secret = '3f67b18883328f69e6372a4b5ba556b9d41ac31364f82befd62f3b1041b156e5'

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'

# Function to validate the password
def password_check(passwd):
    SpecialSym = ['$', '@', '#', '%', '!', '&', '$', '^', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '|', ';', ':', '?', '<', '>', '.', ',']
    val = True

    if len(passwd) < 8:
        msg = 'length should be at least 8'
        val = False

    if not any(char.isdigit() for char in passwd):
        msg = 'Password should have at least one numeral'
        val = False

    if not any(char.isupper() for char in passwd):
        msg = 'Password should have at least one uppercase letter'
        val = False

    if not any(char.islower() for char in passwd):
        msg = 'Password should have at least one lowercase letter'
        val = False

    if not any(char in SpecialSym for char in passwd):
        msg = 'Password should have at least one special character'
        val = False
    if val:
        return {'valid': val}
    else:
        return {'valid': val, 'message': msg}


def email_check(db: db_dependency, email):
    if re.search(regex,email):
        check = db.query(Business).filter(Business.email == email).first()
        if check:
            return {'valid': False, 'message': 'User already exists', 'account_status': check.account_status}
        else:
            return {'valid': True}

    else:
        return {'valid': False, 'message': 'Invalid email provided'}


def get_auth_code():
    code_plain = 123456 #randint(100000,999999)
    code_hashed = str(code_plain)
    code_hashed = bcrypt_context.hash(code_hashed)

    return {'code_plain': code_plain, 'code_hashed': code_hashed}


def get_random_str(size):
    rand_string = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(size))
    return rand_string


def send2fa(code, email, type, action):
    return True
    #send code to user


def sign_record(owner, data, type):

    if type == 'wallet':
        records = str(owner)+""+data['nickname']+""+data['provider']+""+data['asset']+""+data['network']+\
                  ""+data['address']+""+""+sig_secret
        sig = bcrypt_context.hash(records)
    if type == 'activity':
        records = str(data.confirmations)+str(data.business_id)+str(data.amount)+""+data.status+""+data.address+""+data.asset+data.activity_type+sig_secret
        sig = bcrypt_context.hash(records)

    if type == 'trade':
        records = str(data.business_id)+str(data.buyer)+str(data.seller)+str(data.created_by)+data.trade_option+data.asset+str(data.rate)\
        +str(data.amount)+str(data.amount_usd)+data.payment_method+data.payment_details+str(data.time_started)+str(data.time_completed)+data.status+sig_secret
        sig = bcrypt_context.hash(records)

    if type == 'payment_details':
        records = str(data.business_id)+str(data.inputter)+data.role+data.payment_method+data.payment_details+str(data.date_created)+sig_secret
        sig = bcrypt_context.hash(records)

    if type == 'earning':
        records = str(data.business_id)+str(data.amount)+data.asset+str(data.date_created)+sig_secret
        sig = bcrypt_context.hash(records)

    return sig


def verify_sig(current_sig, owner, data, type):

    if type == 'wallet':
        records = str(owner)+""+data['nickname']+""+data['provider']+""+data['asset']+""+data['network']+\
                  ""+data['address']+""+""+sig_secret

    if type == 'activity':
        records = str(data.confirmations)+str(data.business_id)+str(data.amount)+""+data.status+""+data.address+""+data.asset+data.activity_type+sig_secret

    if type == 'trade':
        records = str(data.business_id)+str(data.buyer)+str(data.seller)+str(data.created_by)+data.trade_option+data.asset+str(data.rate)\
        +str(data.amount)+str(data.amount_usd)+data.payment_method+data.payment_details+str(data.time_started)+str(data.time_completed)+data.status+sig_secret

    if type == 'payment_details':
        records = str(data.business_id)+str(data.inputter)+data.role+data.payment_method+data.payment_details+str(data.date_created)+sig_secret

    if type == 'earning':
        records = str(data.business_id)+str(data.amount)+data.asset+str(data.date_created)+sig_secret

    if not bcrypt_context.verify(records, current_sig):
        return False
    return True


def balance_log(db: db_dependency, balance, business_id, user_id, role, asset):
    if role == 'customer':
        deposits = db.query(CustomerActivity).filter(CustomerActivity.customer_id == user_id).filter(CustomerActivity.business_id == business_id)\
            .filter(CustomerActivity.activity_type == 'receive').filter(CustomerActivity.asset == asset).all()
        receive = 0
        for i in deposits:
            if i.status != 'success':
                continue
            if i.flag:
                continue
            receive = receive+i.amount

        bought = db.query(MarketPlaceOrders).filter(MarketPlaceOrders.buyer == user_id).filter(MarketPlaceOrders.business_id == business_id)\
            .filter(MarketPlaceOrders.status == 'completed').filter(MarketPlaceOrders.asset == asset).all()
        for i in bought:
            if i.flag:
                continue
            receive = receive+i.amount

        withdraws = db.query(CustomerActivity).filter(CustomerActivity.customer_id == user_id).filter(CustomerActivity.business_id == business_id)\
            .filter(CustomerActivity.activity_type == 'send').filter(CustomerActivity.asset == asset).all()
        send = 0
        for i in withdraws:
            if i.status != 'success':
                continue
            if i.flag:
                continue
            send = send+i.amount

        sold = db.query(MarketPlaceOrders).filter(MarketPlaceOrders.seller == user_id).filter(MarketPlaceOrders.business_id == business_id)\
            .filter(MarketPlaceOrders.status != 'cancelled').filter(MarketPlaceOrders.asset == asset).all()
        for i in sold:
            if i.flag:
                continue
            send = send+i.amount

        sys_balance = receive-send

        if sys_balance < balance:
            return False
        return True

    if role == 'owner':
        deposits = db.query(MerchantActivity).filter(MerchantActivity.business_id == user_id) \
            .filter(MerchantActivity.activity_type == 'receive').filter(MerchantActivity.asset == asset).all()
        receive = 0
        for i in deposits:
            if i.status != 'success':
                continue
            if i.flag == 'yes':
                continue
            receive = receive + i.amount

        bought = db.query(MarketPlaceOrders).filter(MarketPlaceOrders.buyer == user_id).filter(MarketPlaceOrders.business_id == business_id)\
            .filter(MarketPlaceOrders.status == 'completed').filter(MarketPlaceOrders.asset == asset).all()
        for i in bought:
            if i.flag:
                continue
            receive = receive+i.amount

        withdraws = db.query(MerchantActivity).filter(MerchantActivity.business_id == user_id)\
            .filter(MerchantActivity.activity_type == 'send').filter(MerchantActivity.asset == asset).all()
        send = 0
        for i in withdraws:
            if i.status != 'success':
                continue
            if i.flag == 'yes':
                continue
            send = send + i.amount

        sold = db.query(MarketPlaceOrders).filter(MarketPlaceOrders.seller == user_id).filter(MarketPlaceOrders.business_id == business_id)\
            .filter(MarketPlaceOrders.status == 'completed').filter(MarketPlaceOrders.asset == asset).all()
        for i in sold:
            if i.flag:
                continue
            send = send+i.amount

        sys_balance = receive - send

        if sys_balance < balance:
            return False
        return True


def market_prices():
    r = requests.get('https://kitefinancial.io/data')
    if r.status_code !=200:
        raise HTTPException(status_code=400, detail="Bad request on market data")
    return r.json()


def generate_address(db: db_dependency, asset, business_id, user_id, role):
    address = "393q6VBUG8aZNC1GLHJ6tMvP4nLfzrgubo"
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    if role == 'customer':
        address = "3E18uogb8VDPdg7hBJfkdq7bHXggc8bhRf"
        create_activity = CustomerActivity(
            business_id=business_id,
            customer_id=user_id,
            asset=asset,
            activity_type='receive',
            amount=0.0,
            rate_usd=0.0,
            address=address,
            network='bitcoin',
            memo='',
            fee=0.0,
            status='pending',
            confirmations=0,
            date_created=stamp,
            conf_notify=False,
            sent_notify=False,
            flag=False
        )
        db.add(create_activity)
        db.commit()
        insert_id = create_activity.id
        # update sig
        data = db.query(CustomerActivity).filter(CustomerActivity.id == insert_id).first()
        sig = sign_record(user_id, data, 'activity')
        data.sig = sig
        db.add(data)
        db.commit()

        return address

    if role == 'owner':
        create_activity = MerchantActivity(
            business_id=business_id,
            asset=asset,
            activity_type='receive',
            amount=0.0,
            rate_usd=0.0,
            address=address,
            network='bitcoin',
            memo='',
            fee=0.0,
            status='pending',
            confirmations=0,
            date_created=stamp,
            conf_notify=False,
            sent_notify=False,
            flag=False
        )
        db.add(create_activity)
        db.commit()
        insert_id = create_activity.id
        # update sig
        data = db.query(MerchantActivity).filter(MerchantActivity.id == insert_id).first()
        sig = sign_record(user_id, data, 'activity')
        data.sig = sig
        db.add(data)
        db.commit()

        return address


def get_address(db: db_dependency, asset, business_id, user_id, role):
    type = "activity"
    if role == 'customer':
        activity = db.query(CustomerActivity).filter(CustomerActivity.customer_id == user_id)\
            .filter(CustomerActivity.business_id == business_id)\
            .filter(CustomerActivity.activity_type == 'receive').order_by(CustomerActivity.id.desc()).first()
        if activity is None:
            address = generate_address(db, asset, business_id, user_id, role)
            return address

        # verify sig
        current_sig = activity.sig
        if not verify_sig(current_sig, user_id, activity, type):
            address = generate_address(db, asset, business_id, user_id, role)
            return address
        return activity.address

    if role == 'owner':
        activity = db.query(MerchantActivity).filter(MerchantActivity.business_id == user_id)\
            .filter(MerchantActivity.business_id == business_id)\
            .filter(MerchantActivity.activity_type == 'receive').order_by(MerchantActivity.id.desc()).first()
        if activity is None:
            address = generate_address(db, asset, business_id, user_id, role)
            return address

        # verify sig
        current_sig = activity.sig
        if not verify_sig(current_sig, user_id, activity, 'activity'):
            address = generate_address(db, asset, business_id, user_id, role)
            return address
        return activity.address


def top_up(db: db_dependency, business_id, user_id, role, asset, amount):
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    if role == 'customer':
        balance = db.query(CustomersBalance).filter(CustomersBalance.customer_id == user_id)\
            .filter(CustomersBalance.business_id == business_id).filter(CustomersBalance.asset == asset).first()
        if balance is None:
            # create balance for asset
            new_balance = CustomersBalance(
                business_id=business_id,
                customer_id=user_id,
                asset=asset,
                balance=amount,
                last_balance=0.0,
                last_updated=stamp,
                date_created=stamp
            )
            db.add(new_balance)
            db.commit()

            return True
        # check that balance is still valid.
        round_value = get_round_value(asset)
        balance.last_balance = round(balance.balance, round_value)
        balance.balance = round(balance.balance+amount, round_value)
        balance.last_updated = stamp
        db.add(balance)
        db.commit()

    if role == 'owner':
        balance = db.query(MerchantBalance).filter(MerchantBalance.business_id == user_id).filter(MerchantBalance.asset == asset).first()
        if balance is None:
            # create balance for asset
            new_balance = MerchantBalance(
                business_id=user_id,
                asset=asset,
                balance=amount,
                last_balance=0.0,
                last_updated=stamp,
                date_created=stamp
            )
            db.add(new_balance)
            db.commit()

            return True
        round_value = get_round_value(asset)
        balance.last_balance = round(balance.balance, round_value)
        balance.balance = round(balance.balance+amount, round_value)
        balance.last_updated = stamp
        db.add(balance)
        db.commit()

    return True


def debit(db: db_dependency, business_id, user_id, role, asset, amount):
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    if role == 'customer':
        balance = db.query(CustomersBalance).filter(CustomersBalance.customer_id == user_id) \
            .filter(CustomersBalance.business_id == business_id).filter(CustomersBalance.asset == asset).first()
        if balance is None:
            return False
        # check that balance is still valid.
        round_value = get_round_value(asset)
        balance.last_balance = round(balance.balance, round_value)
        balance.balance = round(balance.balance - amount, round_value)
        balance.last_updated = stamp
        db.add(balance)
        db.commit()

    if role == 'owner':
        balance = db.query(MerchantBalance).filter(MerchantBalance.business_id == user_id).filter(
            MerchantBalance.asset == asset).first()
        if balance is None:
            return False
        round_value = get_round_value(asset)
        balance.last_balance = round(balance.balance, round_value)
        balance.balance = round(balance.balance - amount, round_value)
        balance.last_updated = stamp
        db.add(balance)
        db.commit()

    return True


def get_round_value(asset):
    if asset == 'btc':
        round_value = 8
    if asset == 'usdt':
        round_value = 2
    if asset != 'btc' and asset != 'usdt':
        round_value = 6

    return round_value


def get_kite_mpfee(db: db_dependency, business_id):
    fee = db.query(Business).filter(Business.id == business_id).first()
    return fee.kite_fee