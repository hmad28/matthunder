"""
web/api/results.py — Results, findings, reports endpoints.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, Response, Query

ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = ROOT / "reports"
NUCLEI_DIR = ROOT / "nuclei"

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
async def findings(
    scan_id: str = None,
    severity: str = None,
    category: str = None,
    search: str = "",
    limit: int = 200,
    offset: int = 0
):
    """Return findings with optional filters.

    Supports filtering by scan_id, severity (nuclei), category, and text search.
    Returns paginated results with total count.
    """
    try:
        conn = _db()
        where = []
        params = []

        if scan_id:
            where.append("r.scan_id=?")
            params.append(scan_id)
        if category:
            where.append("r.category=?")
            params.append(category)
        if search:
            where.append("(r.target_url LIKE ? OR r.detail LIKE ? OR r.category LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s, s])

        # Convert severity to category filter for inline findings
        if severity and severity.lower() in ("critical", "high", "medium", "low", "info"):
            # Inline findings use status field for severity-like filtering
            if severity.lower() == "critical":
                where.append("r.http_code>=500")
            elif severity.lower() == "high":
                where.append("r.http_code>=400 AND r.http_code<500")
            elif severity.lower() == "medium":
                where.append("r.http_code>=300 AND r.http_code<400")
            elif severity.lower() == "low":
                where.append("r.http_code<300")

        where_clause = (" WHERE " + " AND ".join(where)) if where else ""

        # Count
        count_row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM results r{where_clause}", params
        ).fetchone()
        total = count_row["cnt"] if count_row else 0

        # Data
        rows = conn.execute(
            f"SELECT r.*, s.scanner as scan_scanner, s.domain as scan_domain "
            f"FROM results r LEFT JOIN scans s ON r.scan_id=s.id{where_clause} "
            f"ORDER BY r.extracted_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        conn.close()

        findings_list = []
        for r in rows:
            d = dict(r)
            d["severity"] = _infer_severity(d)
            findings_list.append(d)

        return {"findings": findings_list, "total": total, "offset": offset, "limit": limit}
    except Exception as e:
        return {"error": str(e), "findings": [], "total": 0}


@router.get("/findings/{scan_id}")
async def findings_detail(scan_id: str, limit: int = 200):
    """Get all findings for a specific scan, with summary stats."""
    try:
        conn = _db()
        rows = conn.execute(
            "SELECT r.*, s.scanner as scan_scanner, s.domain as scan_domain "
            "FROM results r LEFT JOIN scans s ON r.scan_id=s.id "
            "WHERE r.scan_id=? ORDER BY r.extracted_at DESC LIMIT ?",
            (scan_id, limit)
        ).fetchall()

        # Get scan info
        scan = conn.execute(
            "SELECT * FROM scans WHERE id=? LIMIT 1", (scan_id,)
        ).fetchone()

        conn.close()

        findings_list = []
        severity_counts = {}
        for r in rows:
            d = dict(r)
            sev = _infer_severity(d)
            d["severity"] = sev
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            findings_list.append(d)

        return {
            "findings": findings_list,
            "total": len(findings_list),
            "severity_counts": severity_counts,
            "scan": dict(scan) if scan else None,
        }
    except Exception as e:
        return {"error": str(e), "findings": [], "total": 0, "severity_counts": {}}


def _infer_severity(row: dict) -> str:
    """Infer severity from finding data."""
    status = (row.get("status") or "").lower()
    detail = (row.get("detail") or "").lower()
    code = row.get("http_code") or 0

    if any(k in detail for k in ("critical", "sql", "sqli", "rce", "command", "xss")):
        return "critical"
    if any(k in detail for k in ("high", "lfi", "ssrf", "ssti", "auth", "bypass")):
        return "high"
    if any(k in detail for k in ("medium", "cors", "xss reflected", "open redirect", "csrf")):
        return "medium"
    if code >= 500:
        return "critical"
    if code >= 400:
        return "high" if code == 403 or code == 401 else "medium"
    return "info"


@router.get("/nuclei")
async def nuclei_results(target: str = None):
    """Return nuclei findings from output files with severity parsing."""
    if not NUCLEI_DIR.exists():
        return {"files": []}
    files = sorted(NUCLEI_DIR.glob(f"*{target}*.txt")) if target else sorted(NUCLEI_DIR.glob("*.txt"))
    results = []
    for f in files:
        findings = []
        try:
            text = f.read_text("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("[INF]") and not line.startswith("[WRN]"):
                    sev = "info"
                    if "[critical]" in line.lower():
                        sev = "critical"
                    elif "[high]" in line.lower():
                        sev = "high"
                    elif "[medium]" in line.lower():
                        sev = "medium"
                    elif "[low]" in line.lower():
                        sev = "low"
                    findings.append({"line": line, "severity": sev})
        except Exception:
            pass
        results.append({
            "file": f.name,
            "findings_count": len(findings),
            "findings": findings[:100],
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
