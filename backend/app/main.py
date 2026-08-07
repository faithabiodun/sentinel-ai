"""FastAPI application entry point.

Run from the sentinel/ root:
    uvicorn backend.app.main:app --reload --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .db import close_pool, open_pool
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
    allow_origins=[settings.cors_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(incidents_router)
app.include_router(entities_router)


@app.get("/healthz")
async def health() -> dict:
    return {"status": "ok"}
