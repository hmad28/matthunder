"""
matthunder backend - FastAPI application
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.config import settings
from app.core.events import lifespan
from app.api import router as api_router
from app.core.logging import setup_logging


# Setup logging
setup_logging()


# Rate limiter
limiter = Limiter(key_func=get_remote_address)


# Create FastAPI app
app = FastAPI(
    title="matthunder API",
    description="AI-Powered Bug Hunting & Penetration Testing Automation Platform",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)


# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)


# Include API routes
app.include_router(api_router)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "matthunder API",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}
