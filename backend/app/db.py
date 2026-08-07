"""CockroachDB connection pool via psycopg3.

The pool is opened once at application startup and closed on shutdown.
Helpers fetch_one/fetch_all/execute open a connection from the pool,
run the query, and return the connection immediately — no long-held
connections, no leaks.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import psycopg
import psycopg.rows
from fastapi import HTTPException
from psycopg_pool import AsyncConnectionPool

from .config import settings

log = logging.getLogger(__name__)

_pool: AsyncConnectionPool | None = None


def configured() -> bool:
    """True when a DATABASE_URL was supplied."""
    return bool(settings.database_url)


async def open_pool() -> None:
    """Open the pool, tolerating a missing DATABASE_URL.

    A deployed API with no database should report that clearly on /healthz
    rather than crash-looping the container, which tells an operator nothing
    and makes the logs harder to read than the actual problem.
    """
    global _pool
    if not configured():
        log.warning("DATABASE_URL is not set — database routes will return 503.")
        return

    pool = AsyncConnectionPool(
        settings.database_url,
        min_size=2,
        max_size=10,
        open=False,
    )
    try:
        await pool.open(wait=True, timeout=10)
    except Exception:
        log.exception("Could not reach the database — routes will return 503.")
        return
    _pool = pool


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def get_conn() -> AsyncIterator[psycopg.AsyncConnection]:
    if _pool is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Database not connected. Set DATABASE_URL to a CockroachDB "
                "connection string and restart the API."
            ),
        )
    async with _pool.connection() as conn:
        yield conn


async def fetch_one(sql: str, params: Any = None) -> dict | None:
    async with get_conn() as conn:
        async with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            await cur.execute(sql, params)
            return await cur.fetchone()


async def fetch_all(sql: str, params: Any = None) -> list[dict]:
    async with get_conn() as conn:
        async with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            await cur.execute(sql, params)
            return await cur.fetchall()


async def execute(sql: str, params: Any = None) -> None:
    async with get_conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
