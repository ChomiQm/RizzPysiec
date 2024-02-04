from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient
from src.config import settings

client: Optional[AsyncIOMotorClient] = None


async def connect_to_mongo():
    global client
    client = AsyncIOMotorClient(settings.MONGODB_URI)


async def close_mongo_connection():
    if client:
        await client.close()


def get_database():
    if client:
        return client.get_database(settings.MONGO_DB)
    raise RuntimeError("Database connection is not established.")
