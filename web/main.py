#!/usr/bin/env python3
"""
web/main.py — matthunder Web Interface

A FastAPI application that exposes all matthunder features through a
single-page web UI with real-time scan log streaming via WebSocket.

Usage:
    cd C:\\Projects\\Tools-Automation-main
    python -m uvicorn web.main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys
from pathlib import Path

# Ensure the project root is on sys.path so we can import matthunder modules
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .api import scans as scans_api
from .api import targets as targets_api
from .api import results as results_api
from .api import config as config_api

DESCRIPTION = """
# matthunder Web Interface

Full-featured bug bounty recon & vulnerability scanning toolkit.
Supports deep scans, inline scanners, pipeline, targets, and reports.

## Features
- 🔍 **Deep Scan** — Full subfinder → httpx → katana → nuclei → takeover chain
- 🎯 **Inline Scanners** — BLH, TPA, Cred, SSTI, CORS, XSS, SQLi, LFI, CRLF, etc.
- 🧬 **Pipeline** — 6-phase automated recon-to-report orchestration
- 📊 **Live Logs** — WebSocket streaming of scan output
- 📁 **Target Management** — Add/remove targets
- 📈 **Results** — View findings from SQLite, nuclei files, and reports
"""

app = FastAPI(
    title="matthunder Web",
    description=DESCRIPTION,
    version="1.4",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow the dev frontend (and production single-page app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API routers ─────────────────────────────────────────────────

app.include_router(scans_api.router)
app.include_router(targets_api.router)
app.include_router(results_api.router)
app.include_router(config_api.router)

# ── Static files (single-page frontend) ─────────────────────────

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(exist_ok=True)

# Mount static assets (CSS, JS, images)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the SPA frontend."""
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return HTMLResponse("<h1>matthunder Web</h1><p>Frontend not built. Run <code>python web/build.py</code></p>")
    return FileResponse(str(index_path))


@app.get("/api")
async def api_root():
    """API info."""
    return {
        "name": "matthunder Web API",
        "version": "1.4",
        "endpoints": {
            "GET  /api/scans/status": "Current scan status",
            "POST /api/scans/start": "Start a deep scan",
            "POST /api/scans/stop": "Stop the current scan",
            "WS   /api/scans/ws/log": "WebSocket live log stream",
            "WS   /api/scans/ws/scanner": "WebSocket inline scanner runner",
            "GET  /api/targets/": "List targets",
            "POST /api/targets/": "Add a target",
            "GET  /api/results/scans": "Scan history",
            "GET  /api/results/findings": "Inline scanner findings",
            "GET  /api/results/nuclei": "Nuclei results",
            "GET  /api/results/reports": "Generated report files",
            "GET  /api/config/": "Current configuration",
        },
    }
