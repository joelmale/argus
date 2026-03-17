"""
Argus — Network Asset Discovery & Inventory Platform
FastAPI application entry point.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import assets, auth, scans, topology, websocket
from app.bootstrap import ensure_admin_user
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    await ensure_admin_user()
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
app.include_router(websocket.router, prefix="/ws", tags=["websocket"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "argus-backend"}
