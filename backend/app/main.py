from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.core.database import engine, Base
from app.core.redis import redis_client
from app.api import auth_router, biometric_router, dashboard_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting application...")
    
    # Connect to Redis
    await redis_client.connect()
    logger.info("Redis connected")
    
    # Create tables if not exist (for development)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")
    await redis_client.disconnect()
    await engine.dispose()


app = FastAPI(
    title="Passive Biometric Authentication System",
    description="""
    A web application implementing passive biometric authentication
    using behavioral analysis (keystroke dynamics, mouse movements,
    touch patterns, and sensor data) for continuous user verification.
    """,
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Include routers
app.include_router(auth_router, prefix="/api")
app.include_router(biometric_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")


# Health check
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "trust_score_threshold": settings.trust_score_threshold
    }


# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Passive Biometric Authentication System",
        "docs": "/docs",
        "health": "/health"
    }
