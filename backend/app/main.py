"""Threat Hunting Workbench - FastAPI Main Entrypoint."""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.analysis import router as analysis_router
from app.api.artifacts import router as artifacts_router
from app.api.cases import router as cases_router
from app.api.events import router as events_router
from app.api.iocs import router as iocs_router
from app.api.reports import router as reports_router
from app.api.tags import router as tags_router
from app.api.yara_api import router as yara_router
from app.config import settings
from app.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for database initialization and directory readiness."""
    await init_db()
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    settings.yara_rules_dir.mkdir(parents=True, exist_ok=True)
    settings.ioc_lists_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Local, offline-first DFIR and Threat Hunting Workbench",
    lifespan=lifespan,
)

# CORS configuration for local React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes with /api/v1 prefix
API_PREFIX = "/api/v1"
app.include_router(cases_router, prefix=API_PREFIX)
app.include_router(artifacts_router, prefix=API_PREFIX)
app.include_router(events_router, prefix=API_PREFIX)
app.include_router(iocs_router, prefix=API_PREFIX)
app.include_router(tags_router, prefix=API_PREFIX)
app.include_router(analysis_router, prefix=API_PREFIX)
app.include_router(reports_router, prefix=API_PREFIX)
app.include_router(yara_router, prefix=API_PREFIX)


# Static files directory for local Web GUI
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def root():
    """Serve the local Threat Hunting Workbench Web GUI."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "status": "online",
        "app": settings.app_name,
        "version": settings.app_version,
        "mode": "local_offline",
        "docs_url": "/docs",
    }


@app.get("/api/v1/health")
async def health():
    """Health check and platform status."""
    return {
        "status": "online",
        "app": settings.app_name,
        "version": settings.app_version,
        "mode": "local_offline",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=True)
