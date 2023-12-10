from database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, DATETIME, Float, Boolean, Enum


class Business(Base):
    __tablename__ = 'business'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    business_name = Column(String)
    region = Column(String)
    phone_number = Column(String)
    phone_code = Column(String)
    link = Column(String)
    account_status = Column(String)
    email_auth_code = Column(String)
    sms_auth_code = Column(String)
    tmp_value = Column(String)
    auth_stamp = Column(DATETIME)
    date_created = Column(DATETIME)
    last_password_change = Column(DATETIME)


class BusinessMembers(Base):
    __tablename__ = 'business_members'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer, ForeignKey("business.id"))
    email = Column(String)
    hashed_password = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    member_role = Column(String)
    job_title = Column(String)
    account_status = Column(String)
    auth_code = Column(String)
    auth_stamp = Column(DATETIME)
    date_created = Column(DATETIME)
    last_password_change = Column(DATETIME)


class LoginHistory(Base):
    __tablename__ = 'login_history'

    id = Column(Integer, primary_key=True, index=True)
    user = Column(Integer)
    business_id = Column(Integer, ForeignKey("business.id"))
    region = Column(String)
    device = Column(String)
    ip = Column(String)
    status = Column(String)
    date_time = Column(DATETIME)


class Wallet(Base):
    __tablename__ = 'wallets'

    id = Column(Integer, primary_key=True, index=True)
    owner = Column(Integer)
    nickname = Column(String)
    provider = Column(String)
    asset = Column(String)
    network = Column(String)
    address = Column(String)
    date_created = Column(DATETIME)
    sig = Column(String)
    flag = Column(String)

class OTCRate(Base):
    __tablename__ = 'otc_rate'

    id = Column(Integer, primary_key=True, index=True)
    owner = Column(Integer)
    wallet = Column(String)
    asset = Column(String)
    min_amount = Column(Integer)
    max_amount = Column(Integer)
    sell = Column(Integer)
    buy = Column(Integer)
    date_created = Column(DATETIME)


class OTCFEE(Base):
    __tablename__ = 'otc_fee'

    id = Column(Integer, primary_key=True, index=True)
    owner = Column(Integer)
    kite_fee = Column(Float)
    split_fee = Column(Boolean)
    charge_customer = Column(Boolean)
    charge_me = Column(Boolean)
    merchant_pay = Column(Integer)
    customer_pay = Column(Integer)
    date_created = Column(DATETIME)


class OTCORDERS(Base):
    __tablename__ = 'otc_orders'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    buyer = Column(Integer)
    seller = Column(Integer)
    trade_option = Column(String) # buy or sell
    currency = Column(String)
    asset = Column(String)
    rate = Column(Integer)
    amount = Column(Float)
    amount_usd = Column(Integer)
    amount_received_usd = Column(Integer)
    merchant_fee = Column(Integer)
    customer_fee = Column(Integer)
    wallet = Column(Integer)
    payment_details = Column(String)
    tx_hash = Column(String)
    cash_pop = Column(String)
    crypto_pop = Column(String)
    time_started = Column(DATETIME)
    time_paid = Column(DATETIME)
    time_settled = Column(DATETIME)
    time_completed = Column(DATETIME)
    time_adjusted = Column(DATETIME)
    status = Column(String) # open","waiting_1","waiting_2","waiting_3","dispute","completed



class Customers(Base):
    __tablename__ = 'customers'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    email = Column(String)
    phone_number = Column(String)
    phone_code = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    trading_name = Column(String)
    auth_code = Column(Integer)
    auth_stamp = Column(DATETIME)
    tmp_value = Column(String)
    account_status = Column(String) # active, inactive, suspended
    date_created = Column(DATETIME)





