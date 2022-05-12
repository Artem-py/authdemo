import base64
import hmac
import hashlib
import json

from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = '665f07b68bbd4d6f0ffd4caba771df7a7b351b7304f3904ec67799e6fa4bfeb9'
PASSWORD_SALT = 'f149523b3e70518889d1dd22ce07e9896d2e400cd86254dec01f032a5ce023a0'

def sign_data(data: str) -> str:
        return hmac.new(
            SECRET_KEY.encode(),
            msg=data.encode(),
            digestmod=hashlib.sha256
        ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash


users ={
    "alexey@user.com": {
        "name": "Алексей",
        "password": "f8158fb1322e1b4d42d15ecf572d068608afa2e2f2d8237a7d9747def562a19d",
        "balance": 100_000
    },
    "petr@user.com": {
        "name": "Петр",
        "password": "aab86ca7b16225256502369e04db739d956dcebab4b7370b3092be724ad09f69",
        "balance": 555_555
    }
}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс: {users[valid_username]['balance']}",
         media_type="text/html")
    


@app.post("/login")
def process_login_page(username:str = Form(...), password:str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю!"
            }),
            media_type="application/json")
    
    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
        }),
        media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode() +\
                   "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
