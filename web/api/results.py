"""
web/api/results.py — Results, reports, and scan history endpoints.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, Response

ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = ROOT / "reports"
NUCLEI_DIR = ROOT / "nuclei"
TAKEOVER_DIR = ROOT / "take_over"
SENSITIVE_DIR = ROOT / "sensitive_data"

router = APIRouter(prefix="/api/results", tags=["results"])


def _db() -> sqlite3.Connection:
    db_path = str(ROOT / "matthunder_scans.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@router.get("/scans")
async def scan_history(limit: int = 20):
    """Return recent scans from the SQLite database."""
    try:
        conn = _db()
        rows = conn.execute(
            "SELECT id, scanner, domain, status, created_at, finished_at, "
            "total_sources, total_links FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return {"scans": [dict(r) for r in rows]}
    except Exception as e:
        return {"error": str(e), "scans": []}


@router.get("/findings")
async def findings(scan_id: str = None, limit: int = 100):
    """Return findings, optionally filtered by scan_id."""
    try:
        conn = _db()
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM results WHERE scan_id=? ORDER BY extracted_at DESC LIMIT ?",
                (scan_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM results ORDER BY extracted_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        conn.close()
        return {"findings": [dict(r) for r in rows]}
    except Exception as e:
        return {"error": str(e), "findings": []}


@router.get("/nuclei")
async def nuclei_results(target: str = None):
    """Return nuclei findings from the output files."""
    if not NUCLEI_DIR.exists():
        return {"findings": []}
    files = sorted(NUCLEI_DIR.glob(f"*{target}*.txt")) if target else sorted(NUCLEI_DIR.glob("*.txt"))
    results = []
    for f in files:
        findings = []
        try:
            text = f.read_text("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("[INF]"):
                    findings.append(line)
        except Exception:
            pass
        results.append({
            "file": f.name,
            "findings_count": len(findings),
            "findings": findings[:50],  # limit for UI
        })
    return {"files": results}


@router.get("/reports")
async def list_reports():
    """List generated HTML/TXT reports."""
    if not REPORTS_DIR.exists():
        return {"reports": []}
    files = sorted(REPORTS_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    reports = []
    for f in files[:30]:
        reports.append({
            "name": f.name,
            "path": f.name,
            "size": f.stat().st_size,
            "type": f.suffix,
        })
    return {"reports": reports}


@router.get("/reports/{name}")
async def get_report(name: str):
    """Return a report file."""
    report_path = REPORTS_DIR / name
    if not report_path.exists() or not report_path.is_file():
        return {"error": "Report not found"}
    content_type = "text/html" if name.endswith(".html") else "text/plain"
    return Response(
        content=report_path.read_bytes(),
        media_type=content_type,
        headers={"Content-Disposition": f'inline; filename="{name}"'},
    )
