"""Async SQLite database manager using aiosqlite."""

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
import aiosqlite

from app.config import settings

DATABASE_PATH = Path(settings.db_path)


def get_schema_sql() -> str:
    """Read the schema.sql file."""
    schema_path = Path(__file__).parent / "schema.sql"
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found at {schema_path}")
    return schema_path.read_text(encoding="utf-8")


async def init_db() -> None:
    """Initialize the SQLite database with the schema."""
    # Ensure parent dir exists
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("PRAGMA journal_mode=DELETE;")
        await db.execute("PRAGMA foreign_keys=ON;")
        schema = get_schema_sql()
        await db.executescript(schema)
        await db.commit()


@asynccontextmanager
async def get_db_connection() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Context manager for obtaining an aiosqlite database connection."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA foreign_keys=ON;")
        yield db


async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Dependency provider for FastAPI route endpoints."""
    async with get_db_connection() as db:
        yield db
