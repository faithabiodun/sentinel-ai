"""CockroachDB connection pool via psycopg3.

The pool is opened once at application startup and closed on shutdown.
Helpers fetch_one/fetch_all/execute open a connection from the pool,
run the query, and return the connection immediately — no long-held
connections, no leaks.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import psycopg
import psycopg.rows
from psycopg_pool import AsyncConnectionPool

from .config import settings

_pool: AsyncConnectionPool | None = None


async def open_pool() -> None:
    global _pool
    _pool = AsyncConnectionPool(
        settings.database_url,
        min_size=2,
        max_size=10,
        open=False,
    )
    await _pool.open()


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def get_conn() -> AsyncIterator[psycopg.AsyncConnection]:
    if _pool is None:
        raise RuntimeError("DB pool not open — lifespan not registered?")
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
