from fastapi import FastAPI
from routers import auth, users, settings
from database import engine

app = FastAPI()

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(settings.router)
