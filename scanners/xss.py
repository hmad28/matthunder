"""
xss - Reflected XSS scanner (dalfox wrapper).

Wraps dalfox (Go-based XSS scanner) for reflected/dom XSS detection.
Falls back gracefully if dalfox binary is missing.

Usage:
  python matthunder_cli.py xss example.com
"""

import json
import os
import shutil
import subprocess
from typing import Optional

import httpx

from . import SCANNER_REGISTRY
from .common import (
    resolve_tool,
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    extract_anchors, finish_scan, host_in_scope, log, normalize_domain,
    open_db, utc_now_iso, merge_crawled_and_fallback, FALLBACK_PARAMS,
)


def _resolve(name: str) -> Optional[str]:
    return resolve_tool(name)


def _load_pipeline_urls() -> list[str]:
    """Load pre-discovered URLs from pipeline Phase 3."""
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


def run(domain: str, max_pages: int = 50) -> dict:
    domain = normalize_domain(domain)
    dalfox = _resolve("dalfox")
    if not dalfox:
        return {"scanner": "xss", "ok": False, "error": "dalfox not installed. Run setup.sh / setup.bat."}

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'xss', ?, ?, 'running', ?)",
        (domain, "dalfox", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"XSS scan started - domain: {domain}")

    # Load pipeline URLs if available
    pipeline_urls = _load_pipeline_urls()
    all_urls = set()

    if pipeline_urls:
        log(con, scan_id, f"Using {len(pipeline_urls)} pre-discovered URLs from pipeline")
        all_urls.update(pipeline_urls)

    # Also crawl for more URLs
    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} additional pages")
    for page_url, html in pages:
        for a in extract_anchors(html, page_url):
            if a["canonical"] and host_in_scope(_url_host(a["canonical"]), domain):
                all_urls.add(a["canonical"])
        if "?" in page_url:
            all_urls.add(page_url)

    # Add fallback endpoints with common XSS params
    base_urls = [f"https://{domain}", f"http://{domain}"]
    for base in base_urls:
        for endpoint in ["/search", "/api/search", "/q", "/find", "/error",
                         "/page", "/redirect", "/api/v1/search"]:
            for param in FALLBACK_PARAMS["xss"][:6]:
                all_urls.add(f"{base}{endpoint}?{param}=test")

    url_file = f"_matthunder_xss_{scan_id}.txt"
    with open(url_file, "w", encoding="utf-8") as f:
        for u in all_urls:
            f.write(u + "\n")

    url_count = len(all_urls)
    log(con, scan_id, f"Total URLs for dalfox: {url_count}")

    cmd = [dalfox, "file", url_file, "--silence", "--no-color", "--no-spinner",
           "--format", "json", "-o", f"_matthunder_xss_{scan_id}_out.json"]
    log(con, scan_id, f"Running dalfox...")
    try:
        proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=900)
    except subprocess.TimeoutExpired:
        proc = None
        log(con, scan_id, "dalfox timed out")
    except FileNotFoundError:
        proc = None
        log(con, scan_id, "dalfox binary not found at runtime")
    out_path = f"_matthunder_xss_{scan_id}_out.json"
    findings: list[dict] = []
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                findings.append({
                    "url": j.get("url") or j.get("data", ""),
                    "param": j.get("param", ""),
                    "payload": j.get("payload", ""),
                    "type": j.get("type", "reflected"),
                })
    log(con, scan_id, f"Found {len(findings)} XSS findings")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"xss_{f['type']}", f["url"], "vulnerable",
             f"param={f['param']} payload={f['payload'][:200]}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=url_count, total_links=len(findings))
    for p in (url_file, out_path):
        try:
            os.remove(p)
        except OSError:
            pass
    con.close()
    return {"scan_id": scan_id, "scanner": "xss", "domain": domain, "pages": url_count, "findings": len(findings)}


def _url_host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return ""


SCANNER_REGISTRY["xss"] = run
