from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from api.routers_dashboard import dashboard_dir, router as dashboard_router
from api.routers_incidents import router as incidents_router
from api.routers_ingest import router as ingest_router
from api.routers_public import router as public_router
from api.routers_reports import router as reports_router
from api.routers_swarm import router as swarm_router
from api.services import startup, shutdown
from config import config

logging.basicConfig(
    level=config.log_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: start queue + decay on boot, drain on shutdown."""
    await startup()
    yield
    await shutdown()


app = FastAPI(
    title="SwarmSentinel - Honeypot + Swarm Intelligence",
    lifespan=lifespan,
)


def _sanitize_for_json(value):
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): _sanitize_for_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_json(item) for item in value]
    return value

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.api.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Request validation failed.",
            "errors": _sanitize_for_json(exc.errors()),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    payload = {"detail": exc.detail}
    if not isinstance(exc.detail, str):
        payload = {
            "detail": "Request failed.",
            "errors": exc.detail,
        }
    return JSONResponse(status_code=exc.status_code, content=payload)


if os.path.isdir(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="dashboard_static")

app.include_router(public_router)
app.include_router(ingest_router)
app.include_router(swarm_router)
app.include_router(incidents_router)
app.include_router(reports_router)
app.include_router(dashboard_router)
