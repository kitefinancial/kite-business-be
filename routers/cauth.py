from datetime import timedelta, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status

from database import SessionLocal
from models import Business, BusinessMembers, LoginHistory, Customers
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
import sys
sys.path.append("..")
from random import randint
from utils import auth
from .auth import get_current_user
from utils.auth import password_check, email_check, get_auth_code, send2fa
from .auth import create_access_token
from datetime import datetime

router = APIRouter(
    prefix='/c-auth',
    tags=['customer']
)

SECRET_KEY = '40de7e2a4658627eba27255bbe67152e3eca39bf4bc3f7279c643ce63401b7b8'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')
app_token = '357b5b619bd20d1b379a1bc5db54506b5e93cf45cb4c45af17eba6273bf6c1a1'


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


def authenticate_customer(stage: str, email: str, business_id: int, password: str, ip, device, region, db):
    if business_id is None:
        return False
    user = db.query(BusinessMembers).filter(BusinessMembers.email == email).filter(BusinessMembers.business_id == business_id).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        log = LoginHistory(
            user=user.id,
            ip=ip,
            device=device,
            region=region,
            date_time=datetime.today().strftime('%Y-%m-%d %H-%M-%S'),
            business_id=business_id,
            status='failed'
        )
        db.add(log)
        db.commit()
        return False
    if user.account_status == 'inactive':
        # Todo: Resend confirmation email
        return {'status': 'failed', 'message': 'Please activate your account, an email has been sent to your email'}
    if user.account_status == 'suspended':
        return {'status': 'failed', 'message': 'Account currently suspended, please reach out to support'}
    if stage == 'one':
        code = get_auth_code()
        code_plain = code['code_plain']
        code_hashed = code['code_hashed']
        user.auth_code = code_hashed
        user.auth_stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
        db.add(user)
        db.commit()
        send2fa(code_plain, email, 'owner', 'login')
        return {'status': 'success', 'message': '2fa'}
    # reset auth code
    user.auth_code=''
    db.add(user)
    db.commit()
    return user


def create_access_token(email: str, user_id: int, business_id: int, role: str, expires_delta: timedelta):
    encode = {'em': email, 'id': user_id, 'bid': business_id, 'role': role}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


class LoginRequest(BaseModel):
    email: str
    business_id: int = Path(gt=0)
    app_token: str


class VerifyRequest(BaseModel):
    email: str
    business_id: int = Path(gt=0)
    code: str
    app_token: str


class UpdateProfile(BaseModel):
    first_name: str
    last_name: str
    trading_name: str
    phone_code: str
    phone_number: str


class VerifyUpdate(BaseModel):
    code: str


@router.post("/", status_code=status.HTTP_200_OK)
async def login(db: db_dependency, login_request: LoginRequest):
    if login_request.app_token != app_token:
        raise HTTPException(status_code=403, detail="Permission denied")
    business = db.query(Business).filter(Business.id == login_request.business_id).first()
    if business is None:
        raise HTTPException(status_code=404, detail="Business not found")
    customer = db.query(Customers).filter(Customers.email == login_request.email).\
        filter(Customers.business_id == login_request.business_id).first()
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')

    if customer is None:
        # User is first time user of this business.
        code = get_auth_code()
        code_plain = code['code_plain']
        code_hashed = code['code_hashed']
        register = Customers(
            email=login_request.email,
            business_id=login_request.business_id,
            date_created=stamp,
            auth_code=code_hashed,
            auth_stamp=stamp,
            account_status='active'
        )

        # Todo: send 2fa code to email

        db.add(register)
        db.commit()

        return {'status': 'new', 'message': 'code sent to your email'}

    code = get_auth_code()
    code_plain = code['code_plain']
    code_hashed = code['code_hashed']

    customer.auth_code = code_hashed
    customer.auth_stamp = stamp

    db.add(customer)
    db.commit()

    return {'status': 'success', 'message': 'code sent to your email'}


@router.post("/verify", status_code=status.HTTP_200_OK)
async def verify(db: db_dependency, verify_request: VerifyRequest):
    if verify_request.app_token != app_token:
        raise HTTPException(status_code=403, detail="Permission denied")

    user = db.query(Customers).filter(Customers.email == verify_request.email).first()
    if user is None:
        return {'status': 'fail', 'message': 'User not found'}
    if not bcrypt_context.verify(verify_request.code, user.auth_code):
        return {'status': 'fail', 'message': 'Invalid code entered'}
    # authenticate user.
    role = 'customer'
    token = create_access_token(user.email, user.id, verify_request.business_id, role, timedelta(minutes=30))
    user.auth_code=''
    db.add(user)
    db.commit()

    return {'status': 'success', 'access_token': token, 'token_type': 'bearer'}


@router.put("/", status_code=status.HTTP_200_OK)
async def update_profile(user: user_dependency, db: db_dependency, update_req: UpdateProfile):
    if user.get('user_role') != 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    user_model = db.query(Customers).filter(Customers.id == user.get('id')).first()
    if user_model is None:
        raise HTTPException(status_code=401, detail="Could not verify user")

    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    code = get_auth_code()
    code_plain = code['code_plain']
    code_hashed = code['code_hashed']
    user_model.first_name = update_req.first_name
    user_model.last_name = update_req.last_name
    user_model.trading_name = update_req.trading_name
    user_model.phone_code = update_req.phone_code
    user_model.tmp_value = update_req.phone_number
    user_model.auth_code = code_hashed
    user_model.auth_stamp = stamp

    db.add(user_model)
    db.commit()

    # Todo: Send sms code to provided number
    return {'status': 'success', 'message': 'Verify your phone number'}


@router.post("/verify-update", status_code=status.HTTP_200_OK)
async def verify_update(user: user_dependency, db: db_dependency, verify_update: VerifyUpdate):
    if user.get('user_role') != 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    user_model = db.query(Customers).filter(Customers.id == user.get('id')).first()
    if user_model is None:
        return {'status': 'fail', 'message': 'User not found'}
    if not bcrypt_context.verify(verify_update.code, user_model.auth_code):
        return {'status': 'fail', 'message': 'Invalid code entered'}
    # authenticate user.

    user_model.phone_number = user_model.tmp_value
    user_model.tmp_value = ''
    user_model.auth_code = ''
    db.add(user_model)
    db.commit()

    return {'status': 'success', 'message': 'Profile updated'}
