"""
Argus — Network Asset Discovery & Inventory Platform
FastAPI application entry point.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select

from app.api.routes import assets, auth, scans, system, topology, websocket
from app.bootstrap import ensure_admin_user, ensure_system_defaults
from app.core.config import settings
from app.db.models import Asset, ScanJob
from app.db.session import AsyncSessionLocal


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    await ensure_admin_user()
    await ensure_system_defaults()
    yield


app = FastAPI(
    title="Argus",
    description="Network asset discovery, inventory, and topology mapping for home labs.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(topology.router, prefix="/api/v1/topology", tags=["topology"])
app.include_router(system.router, prefix="/api/v1/system", tags=["system"])
app.include_router(websocket.router, prefix="/ws", tags=["websocket"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "argus-backend"}


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> str:
    async with AsyncSessionLocal() as db:
        total_assets = await db.scalar(select(func.count()).select_from(Asset)) or 0
        online_assets = await db.scalar(select(func.count()).select_from(Asset).where(Asset.status == "online")) or 0
        offline_assets = await db.scalar(select(func.count()).select_from(Asset).where(Asset.status == "offline")) or 0
        total_scans = await db.scalar(select(func.count()).select_from(ScanJob)) or 0

    return "\n".join(
        [
            "# HELP argus_assets_total Total assets in inventory",
            "# TYPE argus_assets_total gauge",
            f"argus_assets_total {total_assets}",
            "# HELP argus_assets_online Assets currently marked online",
            "# TYPE argus_assets_online gauge",
            f"argus_assets_online {online_assets}",
            "# HELP argus_assets_offline Assets currently marked offline",
            "# TYPE argus_assets_offline gauge",
            f"argus_assets_offline {offline_assets}",
            "# HELP argus_scan_jobs_total Total scan jobs recorded",
            "# TYPE argus_scan_jobs_total counter",
            f"argus_scan_jobs_total {total_scans}",
        ]
    ) + "\n"
