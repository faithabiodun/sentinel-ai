"""FastAPI application entry point.

Run from the sentinel/ root:
    uvicorn backend.app.main:app --reload --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .db import close_pool, configured, open_pool
from .api.auth import router as auth_router
from .api.incidents import router as incidents_router
from .api.entities import router as entities_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await open_pool()
    yield
    await close_pool()


app = FastAPI(
    title="Sentinel AI",
    description="Agentic security incident investigator with persistent memory.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    # Comma-separated so a deployment can allow both the Railway domain and
    # localhost without a rebuild.
    allow_origins=[o.strip() for o in settings.cors_origin.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(incidents_router)
app.include_router(entities_router)


@app.get("/healthz")
async def health() -> dict:
    """Liveness plus a readable account of what is and isn't configured.

    Reports degraded rather than failing, so the container stays up and an
    operator can see which secret is missing instead of reading a crash loop.
    """
    database = configured()
    # Credentials are what the agent actually needs. S3 is not wired to
    # anything yet, so it must not count towards Bedrock being usable.
    bedrock = bool(settings.aws_access_key_id and settings.aws_secret_access_key)
    return {
        "status": "ok" if database else "degraded",
        "database": "connected" if database else "not configured",
        "bedrock": "configured" if bedrock else "not configured",
        "agent_available": database and bedrock,
    }
