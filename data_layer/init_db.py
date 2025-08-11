from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy import MetaData
from typing import AsyncGenerator
import os
from dotenv import load_dotenv


# Import the existing Base from gateway_model to avoid duplication
from data_layer.gateway_model import Base, SecureUser, UserFlag

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in .env file")

# SQLAlchemy setup
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False)

# Create all tables
async def init_models():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables initialized")

# Dependency for FastAPI routes
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Provide database session for dependency injection"""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

# Legacy function name for compatibility
get_session = get_db