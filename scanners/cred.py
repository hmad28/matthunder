"""
Cred scanner — Credential / Config URL finder.

Discovers in-scope URLs that look like exposed config files, source-control
paths, database dumps, archives, logs, API docs, or similar sensitive paths.
Combines passive anchor scanning with active path probing.
"""

from typing import Optional
from urllib.parse import urlparse
import re

import httpx

from . import SCANNER_REGISTRY
from .common import (
    canonical_url, crawl_domain, extract_anchors, finish_scan, host_in_scope,
    log, normalize_domain, open_db, utc_now_iso, USER_AGENT, DEFAULT_TIMEOUT,
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
            r"phpinfo\.php$", r"info\.php$", r"test\.php$", r"php_status\.php$",
            r"server-status\.php$", r"server-info\.php$",
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

# Active probing paths — well-known sensitive endpoints to check directly
SENSITIVE_PATHS = [
    ("/.env", "config"),
    ("/.env.bak", "config"),
    ("/.env.local", "config"),
    ("/.env.production", "config"),
    ("/.git/config", "source_control"),
    ("/.git/HEAD", "source_control"),
    ("/.git/index", "source_control"),
    ("/.svn/entries", "source_control"),
    ("/config.json", "config"),
    ("/config.yml", "config"),
    ("/config.yaml", "config"),
    ("/settings.json", "config"),
    ("/application.properties", "config"),
    ("/web.config", "config"),
    ("/appsettings.json", "config"),
    ("/wp-config.php.bak", "config"),
    ("/wp-config.php.old", "config"),
    ("/phpinfo.php", "php_info"),
    ("/server-status", "php_info"),
    ("/server-info", "php_info"),
    ("/swagger.json", "api_docs"),
    ("/swagger.yaml", "api_docs"),
    ("/openapi.json", "api_docs"),
    ("/api-docs", "api_docs"),
    ("/v1/swagger.json", "api_docs"),
    ("/v2/api-docs", "api_docs"),
    ("/v3/api-docs", "api_docs"),
    ("/graphql", "api_docs"),
    ("/.DS_Store", "ide_meta"),
    ("/debug/vars", "config"),
    ("/debug/pprof/", "config"),
    ("/actuator", "config"),
    ("/actuator/env", "config"),
    ("/actuator/health", "config"),
    ("/elmah.axd", "logs"),
    ("/trace.axd", "logs"),
    ("/.aws/credentials", "config"),
    ("/.ssh/authorized_keys", "config"),
    ("/dump.sql", "database_dumps"),
    ("/database.sql", "database_dumps"),
    ("/backup.sql", "database_dumps"),
    ("/db.sql", "database_dumps"),
]

# Content verification markers — these strings should NOT appear in a valid error page
SENSITIVE_CONTENT_MARKERS = {
    "config": ["APP_KEY=", "DB_PASSWORD=", "AWS_SECRET", "API_KEY=", "SECRET_KEY="],
    "source_control": ["[core]", "repositoryformatversion", "[remote", "[branch"],
    "database_dumps": ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "mysqldump"],
    "php_info": ["phpinfo()", "PHP Version", "php.ini"],
    "api_docs": ["swagger", "openapi", "paths"],
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
    seen = set()

    # Phase 1: Passive — scan anchor tags from crawled pages
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
            if cu in seen:
                continue
            seen.add(cu)
            found.append({
                "category": cat,
                "pattern_matched": pat,
                "target_url": cu,
                "source_url": page_url,
                "anchor": a["anchor"],
                "verified": False,
            })

    log(con, scan_id, f"Passive: {len(found)} sensitive URLs from anchors")

    # Phase 2: Active — probe well-known sensitive paths directly
    active_found = 0
    base_urls = [f"https://{domain}", f"http://{domain}"]
    probe_paths = [(p, cat) for p, cat in SENSITIVE_PATHS if cat in categories]

    try:
        with httpx.Client(
            headers={"User-Agent": USER_AGENT},
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
        ) as client:
            for path, cat in probe_paths:
                for base in base_urls:
                    probe_url = base + path
                    try:
                        r = client.get(probe_url)
                        if r.status_code in (404, 403, 410, 502, 503):
                            continue
                        if r.status_code >= 500:
                            continue
                        # 200/301/302 with actual content = finding
                        body = r.text[:50000]
                        # Verify it's not a generic error page
                        verified = False
                        markers = SENSITIVE_CONTENT_MARKERS.get(cat, [])
                        for marker in markers:
                            if marker.lower() in body.lower():
                                verified = True
                                break
                        # If no markers defined or no marker matched, still flag if status is 200
                        if not markers:
                            verified = r.status_code == 200

                        cu = canonical_url(probe_url)
                        if cu in seen:
                            continue
                        seen.add(cu)
                        found.append({
                            "category": cat,
                            "pattern_matched": f"active_probe:{path}",
                            "target_url": cu,
                            "source_url": "active_probe",
                            "anchor": "",
                            "verified": verified,
                        })
                        active_found += 1
                        break  # Don't test both http/https if http works
                    except Exception:
                        continue
    except Exception as e:
        log(con, scan_id, f"Active probe error: {e}")

    log(con, scan_id, f"Active: {active_found} sensitive paths found via probing")

    # Store all findings
    for f in found:
        status = "verified" if f.get("verified") else "match"
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, source_url, anchor, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, f["category"], f["target_url"], f["source_url"], f["anchor"], status, f["pattern_matched"], utc_now_iso()),
        )

    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(found))
    log(con, scan_id, f"Cred scan completed - {len(found)} sensitive URLs found ({active_found} active, {len(found)-active_found} passive)")
    con.close()
    return {"scan_id": scan_id, "scanner": "cred", "domain": domain, "pages": len(pages), "links_found": len(found)}


SCANNER_REGISTRY["cred"] = run
