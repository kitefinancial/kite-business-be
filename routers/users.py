from typing import Annotated

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette import status
from models import Business, BusinessMembers, Wallet
from database import SessionLocal
from .auth import get_current_user
from utils.auth import get_auth_code, get_random_str, verify_sig, get_address
from datetime import datetime


router = APIRouter(
    prefix='/user',
    tags=['users']
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


class UserVerification(BaseModel):
    password: str
    new_password: str = Field(min_length=6)


class OtpRequest(BaseModel):
    code_1: str # email
    code_2: str # sms, optional only for actions that requires email and sms verification
    action: str
    reason: str


class GetOtpRequest(BaseModel):
    action: str
    reason: str


class AddMemberRequest(BaseModel):
    email: str
    first_name: str
    last_name: str
    job_title: str
    role: str

class GetAddress(BaseModel):
    asset: str
    network: str


@router.get("/", status_code=status.HTTP_200_OK)
async def get_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status=402, detail='Not Authenticated')
    if user.get('user_role') != 'owner':
        raise HTTPException(status_code=401, detail='Only Business owners')
    user_model = db.query(Business).filter(Business.id == user.get('id')).first()
    if user_model is None:
        raise HTTPException(status=402, detail='Not Authenticated')
    return {'email': user_model.email, 'phone_number': user_model.phone_number}


@router.put("/", status_code=status.HTTP_200_OK)
async def change_password(user: user_dependency, db: db_dependency, password_details: UserVerification):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")
    if user is None:
        raise HTTPException(status_code=401, detail='Not authenticated')
    user_model = db.query(Business).filter(Business.id == user.get('id')).first()
    if user_model is None:
        raise HTTPException(status_code=401, detail='User not found')
    if not bcrypt_context.verify(password_details.password, user_model.hashed_password):
        raise HTTPException(status_code=403, detail='Invalid password')
    new_password=bcrypt_context.hash(password_details.new_password)
    user_model.hashed_password = new_password

    db.add(user_model)
    db.commit()


@router.post("/add-member", status_code=status.HTTP_200_OK)
async def add_member(user:user_dependency, db: db_dependency, add_member_request: AddMemberRequest):
    if user.get('user_role') != 'owner':
        raise HTTPException(status_code=403, detail="Permission denied.")
    if user.get('em') == add_member_request.email:
        return {'status': 'failed', 'message': 'You cannot add yourself as a member'}
    code = get_auth_code()
    code_plain = code['code_plain']
    code_hashed = code['code_hashed']
    add_member = BusinessMembers(
        business_id=user.get('id'),
        email=add_member_request.email,
        first_name=add_member_request.first_name,
        last_name=add_member_request.last_name,
        member_role=add_member_request.role,
        job_title=add_member_request.job_title,
        auth_code=code_hashed,
        date_created=datetime.today().strftime('%Y-%m-%d %H-%M-%S'),
        hashed_password=bcrypt_context.hash(get_random_str(10)),
        account_status='active'
    )

    db.add(add_member)
    db.commit()

    # Todo: Send email to member for password setting using same reset-member endpoint
    return {'status': 'success', 'message': 'Team member successfully added'}


@router.post("/get-otp", status_code=status.HTTP_200_OK)
async def get_otp(db: db_dependency, user: user_dependency, otp_request: GetOtpRequest):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    user_model = db.query(Business).filter(Business.id == user.get('id')).first()
    stamp = datetime.today().strftime('%Y-%m-%d %H-%M-%S')

    if otp_request.action == 'mail':
        code_1 = get_auth_code()
        code_1_plain = code_1['code_plain']
        code_1_hashed = code_1['code_hashed']
        user_model.email_auth_code=code_1_hashed
        user_model.auth_stamp=stamp

        db.add(user_model)
        db.commit()
        # phone number is on tmp_value phone code on phone_code. after verification number moves from tmp_value
        # to phone_number
        # Todo: send code to email

    if otp_request.action == 'sms':
        code_1 = get_auth_code()
        code_1_plain = code_1['code_plain']
        code_1_hashed = code_1['code_hashed']
        user_model.sms_auth_code=code_1_hashed
        user_model.auth_stamp=stamp

        db.add(user_model)
        db.commit()
        # phone number is on tmp_value phone code on phone_code. after verification number moves from tmp_value
        # to phone_number
        # Todo: send sms to phone number

    if otp_request.action == 'phone_verification':
        code_1 = get_auth_code()
        code_1_plain = code_1['code_plain']
        code_1_hashed = code_1['code_hashed']
        user_model.sms_auth_code=code_1_hashed
        user_model.auth_stamp=stamp

        db.add(user_model)
        db.commit()
        # phone number is on tmp_value phone code on phone_code. after verification number moves from tmp_value
        # to phone_number
        # Todo: send sms to phone number

    user_model = db.query(BusinessMembers).filter(BusinessMembers.id == user.get('id')).first()

    if otp_request.action == 'regular' and user.get('user_role') == 'owner':
        code_1 = get_auth_code()
        code_1_plain = code_1['code_plain']
        code_1_hashed = code_1['code_hashed']
        user_model.email_auth_code=code_1_hashed
        user_model.auth_stamp=stamp

        db.add(user_model)
        db.commit()

        # Todo: send code to email

    if otp_request.action == 'regular' and user.get('user_role') != 'owner':
        code_1 = get_auth_code()
        code_1_plain = code_1['code_plain']
        code_1_hashed = code_1['code_hashed']
        user_model.auth_code=code_1_hashed
        user_model.auth_stamp=stamp

        db.add(user_model)
        db.commit()

        # Todo: send code to email

    if otp_request.action == 'email':
        code_1 = get_auth_code()
        code_1_plain = code_1['code_plain']
        code_1_hashed = code_1['code_hashed']
        user_model.email_auth_code=code_1_hashed
        user_model.auth_stamp=stamp

        db.add(user_model)
        db.commit()
        # phone number is on tmp_value phone code on phone_code. after verification number moves from tmp_value
        # to phone_number
        # Todo: send code to email

    return {'status': 'success', 'message': 'OTP sent'}


@router.post("/verify-otp", status_code=status.HTTP_200_OK)
async def otp_auth(db: db_dependency, user: user_dependency, otp_request: OtpRequest):
    if user.get('user_role') == 'customer':
        raise HTTPException(status_code=403, detail="Permission denied.")

    if user.get('user_role') == 'owner':
        user_model = db.query(Business).filter(Business.id == user.get('id')).first()
        if otp_request.action == 'connect_wallet' or otp_request.action == 'withdraw':
            # sms  and email required
            if not bcrypt_context.verify(otp_request.code_1, user_model.email_auth_code):
                return {'status': 'failed', 'message': 'Invalid email code'}
            if not bcrypt_context.verify(otp_request.code_2, user_model.sms_auth_code):
                return {'status': 'failed', 'message': 'Invalid SMS code'}
        if otp_request.action == 'regular':
            if not bcrypt_context.verify(otp_request.code_1, user_model.email_auth_code):
                return {'status': 'failed', 'message': 'Invalid code'}
        if otp_request.action == 'phone_verification':
            if bcrypt_context.verify(otp_request.code_1, user_model.sms_auth_code):
                user_model.phone_number = user_model.tmp_value
                user_model.tmp_value = ''
                user_model.sms_auth_code=''
                db.add(user_model)
                db.commit()

                return {'status': 'success', 'message': 'phone number verified'}

            return {'status': 'failed', 'message': 'Invalid code'}

        return {'status': 'success', 'message': 'OTP verified'}
    else:
        user_model = db.query(BusinessMembers).filter(BusinessMembers.id == user.get('id')).first()
        if otp_request.action == 'regular':
            if not bcrypt_context.verify(otp_request.code_1, user_model.auth_code):
                return {'status': 'failed', 'message': 'Invalid code'}
            return {'status': 'success', 'message': 'OTP verified'}


@router.post("/get-address", status_code=status.HTTP_200_OK)
async def get_deposit_address(user: user_dependency, db: db_dependency, address_req: GetAddress):
    role = user.get('user_role')
    if role != 'customer':
        role = 'owner'

    address = get_address(db, address_req.asset, user.get('bid'), user.get('id'), user.get('user_role'))

    return {'status': 'success', 'address': address, 'network': address_req.network}
