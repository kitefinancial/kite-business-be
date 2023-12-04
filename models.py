from database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, DATETIME


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