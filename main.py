from fastapi import FastAPI
from routers import users, settings, otc, cauth, auth, marketplace, callback

app = FastAPI()

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(settings.router)
app.include_router(otc.router)
app.include_router(cauth.router)
app.include_router(marketplace.router)
app.include_router(callback.router)