"""Nexus Read API — FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRouter

from read_api.routers import inventory

app = FastAPI(
    title="Nexus Read API",
    version="0.1.0",
    description="Read-layer API for the Nexus Cyber OS product frontend.",
)

v1 = APIRouter(prefix="/v1")
v1.include_router(inventory.router)

app.include_router(v1)
