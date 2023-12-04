from typing import Annotated
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, Path
from database import SessionLocal
import re
from models import Business, BusinessMembers
from random import randint
from passlib.context import CryptContext
import random
import string

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

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