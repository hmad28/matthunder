"""
Cred scanner — Credential / Config URL finder.

Discovers in-scope URLs that look like exposed config files, source-control
paths, database dumps, archives, logs, API docs, or similar sensitive paths.
Ported from BLH-Hunter lazy_dorking.cred.scanner (streamlined).
"""

from typing import Optional
from urllib.parse import urlparse
import re

from . import SCANNER_REGISTRY
from .common import (
    canonical_url, crawl_domain, extract_anchors, finish_scan, host_in_scope,
    log, normalize_domain, open_db, utc_now_iso,
)


CRED_CATEGORIES = {
    "config": {
        "patterns": [
            r"\.env(\.|$)", r"config\.json$", r"settings\.json$", r"application\.properties$",
            r"web\.config$", r"appsettings\.json$", r"\.envrc$", r"\.ini$", r"\.conf$",
            r"\.cfg$", r"\.toml$", r"\.yaml$", r"\.yml$",
        ]
    },
    "docker": {
        "patterns": [
            r"^/?Dockerfile$", r"docker-compose\.ya?ml$", r"\.dockerignore$",
            r"docker-compose\.override\.ya?ml$",
        ]
    },
    "database_dumps": {
        "patterns": [
            r"\.sql$", r"\.dump$", r"\.bak$", r"\.db$", r"\.sqlite$", r"\.sqlite3$",
            r"\.mdb$", r"\.accdb$",
        ]
    },
    "archives": {
        "patterns": [
            r"\.zip$", r"\.tar$", r"\.tar\.gz$", r"\.tgz$", r"\.rar$", r"\.7z$",
            r"\.sql\.gz$", r"\.bak\.gz$", r"\.gz$", r"\.bz2$", r"\.xz$",
        ]
    },
    "logs": {
        "patterns": [
            r"\.log$", r"(^|/)access[-_]?log", r"(^|/)error[-_]?log", r"(^|/)debug[-_]?log",
            r"(^|/)app[-_]?log", r"(^|/)server[-_]?log",
        ]
    },
    "source_control": {
        "patterns": [
            r"\.git/config$", r"\.git/HEAD$", r"\.git/index$",
            r"\.svn/entries$", r"\.svn/wc\.db$",
            r"\.hg/store/", r"\.bzr/branch-format$",
        ]
    },
    "api_docs": {
        "patterns": [
            r"swagger\.json$", r"swagger\.yaml$", r"openapi\.json$", r"openapi\.yaml$",
            r"api-docs", r"/v1/swagger", r"/v2/api-docs", r"/v3/api-docs",
            r"swagger\.ui\.html?$", r"redoc\.html?$",
        ]
    },
    "php_info": {
        "patterns": [
            r"phpinfo\.php$", r"info\.php$", r"test\.php$", r"\.php$",
        ]
    },
    "ide_meta": {
        "patterns": [
            r"\.idea/", r"\.vscode/", r"\.project$", r"\.classpath$",
            r"\.DS_Store$", r"Thumbs\.db$",
        ]
    },
    "ci_cd": {
        "patterns": [
            r"\.github/workflows/", r"\.gitlab-ci\.yml$", r"\.circleci/config\.yml$",
            r"\.travis\.yml$", r"azure-pipelines\.yml$", r"Jenkinsfile$",
        ]
    },
}


def match_sensitive_url(url: str, categories: list[str]) -> Optional[tuple[str, str]]:
    cu = canonical_url(url)
    if not cu:
        return None
    p = urlparse(cu)
    path = (p.path or "").lower()
    full = cu.lower()
    for cat in categories:
        info = CRED_CATEGORIES.get(cat)
        if not info:
            continue
        for pat in info["patterns"]:
            try:
                if re.search(pat, path) or re.search(pat, full):
                    return cat, pat
            except re.error:
                if pat.lower() in path or pat.lower() in full:
                    return cat, pat
    return None


def run(domain: str, categories: list[str], max_pages: int = 30) -> dict:
    domain = normalize_domain(domain)
    categories = [c for c in (categories or list(CRED_CATEGORIES.keys())) if c in CRED_CATEGORIES]
    if not categories:
        categories = list(CRED_CATEGORIES.keys())

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'cred', ?, ?, 'running', ?)",
        (domain, str(categories), utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Cred scan started - domain: {domain} | categories: {', '.join(categories)}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    found: list[dict] = []
    for page_url, html in pages:
        for a in extract_anchors(html, page_url):
            cu = a["canonical"]
            if not cu:
                continue
            cu_host = urlparse(cu).netloc
            if not host_in_scope(cu_host, domain):
                continue
            matched = match_sensitive_url(cu, categories)
            if not matched:
                continue
            cat, pat = matched
            found.append({
                "category": cat,
                "pattern_matched": pat,
                "target_url": cu,
                "source_url": page_url,
                "anchor": a["anchor"],
            })

    seen = set()
    unique = []
    for f in found:
        if f["target_url"] in seen:
            continue
        seen.add(f["target_url"])
        unique.append(f)
    log(con, scan_id, f"Discovered {len(unique)} sensitive URL matches")

    for f in unique:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, source_url, anchor, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, 'match', ?, ?)",
            (scan_id, f["category"], f["target_url"], f["source_url"], f["anchor"], f["pattern_matched"], utc_now_iso()),
        )

    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(unique))
    log(con, scan_id, f"Cred scan completed - {len(unique)} sensitive URLs found")
    con.close()
    return {"scan_id": scan_id, "scanner": "cred", "domain": domain, "pages": len(pages), "links_found": len(unique)}


SCANNER_REGISTRY["cred"] = run
