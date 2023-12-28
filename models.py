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
    kite_fee = Column(Float)
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
    min = Column(Integer)
    max = Column(Integer)
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
    amount_received = Column(Integer)
    merchant_fee = Column(Integer)
    customer_fee = Column(Integer)
    wallet = Column(Integer)
    network = Column(String)
    address = Column(String)
    payment_details = Column(String)
    tx_hash = Column(String)
    cash_pop = Column(String)
    crypto_pop = Column(String)
    time_started = Column(DATETIME)
    time_paid = Column(DATETIME)
    time_settled = Column(DATETIME)
    time_completed = Column(DATETIME)
    time_adjusted = Column(DATETIME)
    status = Column(String) # open","waiting_1","waiting_2","waiting_3","dispute","completed, cancelled



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


class CustomersBalance(Base):
    __tablename__ = 'customers_balance'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    customer_id = Column(Integer)
    asset = Column(String)
    balance = Column(Float)
    last_balance = Column(Float)
    last_updated = Column(DATETIME)
    date_created = Column(DATETIME)


class MerchantBalance(Base):
    __tablename__ = 'merchant_balance'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    asset = Column(String)
    balance = Column(Float)
    last_balance = Column(Float)
    last_updated = Column(DATETIME)
    date_created = Column(DATETIME)


class Adverts(Base):
    __tablename__ = 'adverts'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    inputter = Column(Integer)
    asset = Column(String)
    trade_option = Column(String)
    rate = Column(Integer)
    min = Column(Integer)
    max = Column(Integer)
    created_by = Column(String)
    payment_method = Column(String)
    payment_details = Column(String)
    payment_window = Column(Integer)
    date_created = Column(DATETIME)


class CustomerActivity(Base):
    __tablename__ = 'customer_activity'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    customer_id = Column(Integer)
    asset = Column(String)
    activity_type = Column(String)
    amount = Column(Float)
    rate_usd = Column(Integer)
    address = Column(String)
    network = Column(String)
    memo = Column(String)
    fee = Column(Float)
    status = Column(String)
    confirmations = Column(Integer)
    tx_hash = Column(String)
    date_created = Column(DATETIME)
    conf_notify = Column(Boolean)
    sent_notify = Column(Boolean)
    sig = Column(String)
    flag = Column(Boolean)


class MerchantActivity(Base):
    __tablename__ = 'merchant_activity'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    asset = Column(String)
    activity_type = Column(String)
    amount = Column(Float)
    rate_usd = Column(Integer)
    address = Column(String)
    network = Column(String)
    memo = Column(String)
    fee = Column(Float)
    status = Column(String)
    confirmations = Column(Integer)
    tx_hash = Column(String)
    date_created = Column(DATETIME)
    conf_notify = Column(Boolean)
    sent_notify = Column(Boolean)
    sig = Column(String)
    flag = Column(Boolean)


class MPFees(Base):
    __tablename__ = 'mp_fees'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    fee = Column(Float)
    maker = Column(Integer)
    taker = Column(Integer)
    min = Column(Integer)
    max = Column(Integer)
    date_created = Column(DATETIME)

class MarketPlaceOrders(Base):
    __tablename__ = 'mp_orders'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    buyer = Column(Integer)
    seller = Column(Integer)
    created_by = Column(String)
    engaged_by = Column(String)
    trade_option = Column(String)
    currency = Column(String)
    asset = Column(String)
    rate = Column(Integer)
    amount = Column(Float)
    amount_usd = Column(Integer)
    taker_fee = Column(Float)
    maker_fee = Column(Float)
    payment_method = Column(String)
    payment_details = Column(String)
    cash_pop = Column(String)
    time_started = Column(DATETIME)
    time_settled = Column(DATETIME)
    time_completed = Column(DATETIME)
    status = Column(String)
    sig = Column(String)
    flag = Column(String)


class PaymentDetails(Base):
    __tablename__ = 'payment_details'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    inputter = Column(Integer)
    role = Column(String)
    payment_method = Column(String)
    payment_details = Column(String)
    date_created = Column(DATETIME)
    sig = Column(String)
    flag = Column(Boolean)


class Earnings(Base):
    __tablename__ = 'earnings'

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer)
    asset = Column(String)
    amount = Column(Float)
    narration = Column(String)
    date_created = Column(DATETIME)
    sig = Column(String)
    flag = Column(Boolean)