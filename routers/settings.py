from typing import Annotated

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from passlib.context import CryptContext

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette import status
from models import Business, BusinessMembers
from database import SessionLocal
from .auth import get_current_user
from .users import get_otp
from utils.auth import get_auth_code, get_random_str
from datetime import datetime


router = APIRouter(
    prefix='/settings',
    tags=['settings']
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


class BasicInfoRequest(BaseModel):
    business_name: str
    region: str
    link: str
    phone_number: str
    phone_code: str


@router.put("/basic-info", status_code=status.HTTP_200_OK)
async def update_info(db: db_dependency, user: user_dependency, info_request: BasicInfoRequest):
    if user.get('user_role') != 'owner':
        raise HTTPException(status_code=403, detail="Permission denied, only business owner can edit.")
    user_model = db.query(Business).filter(Business.id == user.get('id')).first()
    user_model.business_name = info_request.business_name
    user_model.region = info_request.region
    user_model.link = info_request.link
    otp = False
    if user_model.phone_number != info_request.phone_number:
        user_model.tmp_value = info_request.phone_number
        otp = True

    db.add(user_model)
    db.commit()
    if otp:
        code_1 = get_auth_code()
        code_1_plain = code_1['code_plain']
        code_1_hashed = code_1['code_hashed']
        user_model.sms_auth_code = code_1_hashed
        user_model.auth_stamp = datetime.today().strftime('%Y-%m-%-d %H-%M-%S')
        db.add(user_model)
        db.commit()

        # Todo: send sms to phone number

    return {'status': 'success', 'message': 'update was successful'}

