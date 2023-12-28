from datetime import timedelta, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status

from database import SessionLocal
from models import Business, BusinessMembers, LoginHistory
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from random import randint
from utils import auth
from utils.auth import password_check, email_check, get_auth_code, send2fa
from datetime import datetime

router = APIRouter(
    prefix='/auth',
    tags=['auth']
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


def get_business_id(db:db_dependency, business_link: str):
    business = db.query(Business).filter(Business.link == business_link).first()
    if not business:
        return False
    return business.id


def authenticate_user(stage: str, email: str, password: str, ip, device, region, db):
    user = db.query(Business).filter(Business.email == email).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        log = LoginHistory(
            user=user.id,
            ip=ip,
            device=device,
            region=region,
            date_time=datetime.today().strftime('%Y-%m-%d %H-%M-%S'),
            business_id=user.id,
            status='failed'
        )
        db.add(log)
        db.commit()
        return False
    if user.account_status == 'inactive':
        # Todo: Resend confirmation email
        return {'status': 'failed', 'message': 'Please activate your account, an email has been sent to you'}
    if user.account_status == 'suspended':
        return {'status': 'failed', 'message': 'Account currently suspended, please reach out to support'}
    if stage == 'one':
        code = get_auth_code()
        code_plain = code['code_plain']
        code_hashed = code['code_hashed']
        user.email_auth_code = code_hashed
        user.auth_stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
        db.add(user)
        db.commit()
        send2fa(code_plain, email, 'owner', 'login')
        return {'status': 'success', 'message': '2fa'}

    # reset auth codes
    user.email_auth_code = ''
    db.add(user)
    db.commit()
    return user


def authenticate_member(stage: str, email: str, business_link: str, password: str, ip, device, region, db):
    business_id = get_business_id(db, business_link)
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


def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get('em')
        user_id: int = payload.get('id')
        business_id: int = payload.get('bid')
        user_role: str = payload.get('role')
        if email is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not verify user')
        return {'email': email, 'id': user_id, 'bid': business_id, 'user_role': user_role}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not verify user')


class CreateUserRequest(BaseModel):
    email: str
    password: str
    app_token: str


class VerifyAccountRequest(BaseModel):
    email: str
    code: str
    app_token: str


class LoginRequest(BaseModel):
    email: str
    password: str
    type: str
    business_link: str # required for member login only, null for owner login
    region: str
    device: str
    ip: str
    app_token: str


class LoginRequestTwo(BaseModel):
    email: str
    password: str
    type: str
    business_link: str # required for member login only, null for owner login
    code: str
    region: str
    device: str
    ip: str
    app_token: str


class ForgotPasswordRequest(BaseModel):
    email: str
    app_token: str
    #business_link: str required for members reset to identify the business acount they are resetting, null for business owners


class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str
    confirm_password: str
    app_token: str


class ResetPasswordRequestMember(BaseModel):
    business_id: int
    email: str
    code: str
    new_password: str
    confirm_password: str
    app_token: str


class Token(BaseModel):
    status: str
    access_token: str
    token_type: str


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    # Validate app
    if create_user_request.app_token != app_token:
        raise HTTPException(status_code=403, detail='Access denied')
    # Run validations
    check_password = password_check(create_user_request.password)
    if not check_password['valid']:
        return {"status": 'failed', 'message': check_password['message']}
    check_email = email_check(db, create_user_request.email)
    if not check_email['valid']:
        if check_email['message'] == 'User already exists' and check_email['account_status'] == 'inactive':
            # Revalidate user and send verification code, update current password with this password
            code = get_auth_code()
            code_plain = code['code_plain']
            code_hashed = code['code_hashed']
            time_stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
            user = db.query(Business).filter(Business.email == create_user_request.email).first()
            user.hashed_password = bcrypt_context.hash(create_user_request.password)
            user.email_auth_code = code_hashed
            user.auth_stamp = time_stamp
            user.date_created = time_stamp

            db.add(user)
            db.commit()

            # Todo: Send verification code to email
            return {"status": "success", "message": "registration complete"}

        return {"status": 'failed', 'message': check_email['message']}

    # Validation successful start signup

    code = get_auth_code()
    code_plain = code['code_plain']
    code_hashed = code['code_hashed']
    time_stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    create_user_model = Business(
        email=create_user_request.email,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        account_status='inactive',
        email_auth_code=code_hashed,
        kite_fee=0.2, # 20% MP fee
        date_created=time_stamp

    )

    db.add(create_user_model)
    db.commit()

    # Todo: Send verification code to email
    return {"status": "success", "message": "registration complete"}


@router.post("/verify-account")
async def verify_account(db: db_dependency, verify_account_request: VerifyAccountRequest):
    user = db.query(Business).filter(Business.email == verify_account_request.email).first()
    if not user:
        return {'status': 'failed', 'message': 'User not found'}
    if not bcrypt_context.verify(verify_account_request.code, user.email_auth_code):
        return {'status': 'failed', 'message': 'Invalid code provided'}
    user.email_auth_code=''
    user.account_status='active'

    db.add(user)
    db.commit()

    return {'status': 'success', 'message': 'Account successfully verified, you may now login'}

@router.post("/token-one")
async def login_access_one(login_request: LoginRequest,
                             db: db_dependency):
    # Validate app
    if login_request.app_token != app_token:
        raise HTTPException(status_code=403, detail='Access denied')
    if login_request.type == 'owner':
        user = authenticate_user('one', login_request.email, login_request.password, login_request.ip, login_request.device, login_request.region, db)
    if login_request.type == 'member':
        user = authenticate_member('one', login_request.email, login_request.business_link, login_request.password, login_request.ip, login_request.device, login_request.region, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not verify user')
    if user['status'] == 'failed':
        return {'status': 'failed', 'message': user['message']}
    # token = create_access_token(user.email, user.id, business_id, role, timedelta(minutes=20))

    return {'status': 'success', 'message': 'Email verification'}


@router.post("/token-two", status_code=status.HTTP_200_OK)
async def login_access_two(login_request: LoginRequestTwo,
                             db: db_dependency):
    # Validate app
    if login_request.app_token != app_token:
        raise HTTPException(status_code=403, detail='Access denied')
    if login_request.type == 'owner':
        two_fa = db.query(Business).filter(Business.email == login_request.email).first()
        if two_fa is None:
            return {'status': 'failed', 'message': 'Could not verify user'}
        if not bcrypt_context.verify(login_request.code, two_fa.email_auth_code):
            return {'status': 'failed', 'message': 'Invalid Code'}
        user = authenticate_user('two', login_request.email, login_request.password, login_request.ip, login_request.device, login_request.region, db)
        # check if account not verified or account suspended
        try:
            if user.id:
                role = 'owner'
                business_id = user.id
        except AttributeError:
            # user is either not verified or suspended
            if user['status']:
                return {'status': 'failed', 'message': user['message']}

    if login_request.type == 'member':
        two_fa = db.query(BusinessMembers).filter(BusinessMembers.email == login_request.email).first()
        if not bcrypt_context.verify(login_request.code, two_fa.auth_code):
            return {'status': 'failed', 'message': 'Invalid Code'}
        user = authenticate_member('two', login_request.email, login_request.business_link, login_request.password, login_request.ip, login_request.device, login_request.region, db)
        # check if account not verified or account suspended
        try:
            if user.id:
                role = user.member_role
                business_id = user.business_id
        except AttributeError:
            # user is either not verified or suspended
            if user['status']:
                return {'status': 'failed', 'message': user['message']}
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not verify user')
    token = create_access_token(user.email, user.id, business_id, role, timedelta(minutes=30))
    login_history = LoginHistory(
        user=user.id,
        business_id=business_id,
        region=login_request.region,
        device=login_request.device,
        ip=login_request.ip,
        date_time=datetime.today().strftime('%Y-%m-%d %H-%M-%S'),
        status='success'
    )

    db.add(login_history)
    db.commit()

    return {'status': 'success', 'access_token': token, 'token_type': 'bearer'}



@router.post("/forgot", status_code=status.HTTP_200_OK)
async def forgot_password(db: db_dependency, forgot_password_request: ForgotPasswordRequest):
        # Validate app
        if forgot_password_request.app_token != app_token:
            raise HTTPException(status_code=403, detail='Access denied')

        user = db.query(Business).filter(Business.email == forgot_password_request.email).first()
        if not user:
            return {'status': 'failed', 'message': 'Account not found'}
        else:
            code = get_auth_code()
            code_plain = code['code_plain']
            code_hashed = code['code_hashed']
            user.email_auth_code=code_hashed
            db.add(user)
            db.commit()
            # Todo: Send code to reset account

            return {'status': 'success', 'message': 'Check your email for reset instructions'}


@router.post("/reset", status_code=status.HTTP_200_OK)
async def reset_account(db:db_dependency, reset_password_request: ResetPasswordRequest):
    # Validate app
    if reset_password_request.app_token != app_token:
        raise HTTPException(status_code=403, detail='Access denied')

    code = str(reset_password_request.code)
    email = reset_password_request.email
    check_password = password_check(reset_password_request.new_password)
    if not check_password['valid']:
        return {'status': 'failed', 'message': check_password['message']}
    if reset_password_request.new_password != reset_password_request.confirm_password:
        return {'status': 'failed', 'message': 'Password do not match'}
    user = db.query(Business).filter(Business.email == email).first()
    if not bcrypt_context.verify(code,user.email_auth_code):
        return {'status': 'failed', 'message': 'Invalid or broken reset link'}
    user.hashed_password = bcrypt_context.hash(reset_password_request.new_password)
    user.last_password_change = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    user.email_auth_code=''
    user.sms_auth_code=''

    db.add(user)
    db.commit()
    # Todo: send email of password change
    return {'status': 'success', 'message': 'Password reset successful'}


@router.post("/reset-member", status_code=status.HTTP_200_OK)
async def reset_account(db:db_dependency, reset_password_request: ResetPasswordRequestMember):
    # Validate app
    if reset_password_request.app_token != app_token:
        raise HTTPException(status_code=403, detail='Access denied')

    code = str(reset_password_request.code)
    email = reset_password_request.email
    check_password = password_check(reset_password_request.new_password)
    if not check_password['valid']:
        return {'status': 'failed', 'message': check_password['message']}
    if reset_password_request.new_password != reset_password_request.confirm_password:
        return {'status': 'failed', 'message': 'Password do not match'}
    user = db.query(BusinessMembers).filter(BusinessMembers.email == email)\
        .filter(BusinessMembers.business_id == reset_password_request.business_id).first()
    if not bcrypt_context.verify(code,user.auth_code):
        return {'status': 'failed', 'message': 'Invalid or broken reset link'}
    user.hashed_password = bcrypt_context.hash(reset_password_request.new_password)
    user.last_password_change = datetime.today().strftime('%Y-%m-%d %H-%M-%S')
    user.auth_code=''

    db.add(user)
    db.commit()
    # Todo: send email of password change
    return {'status': 'success', 'message': 'Password reset successful'}


