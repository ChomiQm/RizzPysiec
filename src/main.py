from fastapi import FastAPI

from src.auth.router import auth_router
from src.database import connect_to_mongo, close_mongo_connection
from dotenv import load_dotenv
load_dotenv()
app = FastAPI()
app.include_router(auth_router)

@app.on_event("startup")
async def startup():
    await connect_to_mongo()


@app.on_event("shutdown")
async def shutdown():
    await close_mongo_connection()
