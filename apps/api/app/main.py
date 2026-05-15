from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apps.api.app.routers import intelligence


def create_app() -> FastAPI:
    app = FastAPI(
        title="PHI Guard Intelligence API",
        description="HIPAA-oriented healthcare data risk intelligence API using synthetic demo data.",
        version="0.1.0",
    )
    origins = [
        origin.strip()
        for origin in os.getenv("API_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
        if origin.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(intelligence.router, prefix="/api", tags=["intelligence"])

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "mode": os.getenv("PHI_GUARD_MODE", "demo")}

    return app


app = create_app()
