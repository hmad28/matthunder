"""
Startup and shutdown events
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.database import init_db, close_db
from app.core.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    setup_logging()
    await init_db()
    yield
    # Shutdown
    await close_db()
