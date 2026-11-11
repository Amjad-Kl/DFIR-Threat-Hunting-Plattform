"""Pytest configuration and fixtures."""

import pytest
import pytest_asyncio
from app.database import init_db


@pytest_asyncio.fixture(autouse=True, scope="function")
async def setup_test_db():
    """Ensure database schema and directories are initialized before each test."""
    await init_db()
