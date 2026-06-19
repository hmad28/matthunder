"""
jsanalysis - JavaScript analysis scanner.

Extracts endpoints, secrets, API keys, and sensitive paths from JS files.
Uses multiple techniques: regex patterns, link extraction, entropy analysis.

Usage:
  python matthunder_cli.py jsanalysis example.com
"""

import base64
import math
import re
from urllib.parse import urljoin, urlparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    extract_anchors, finish_scan, host_in_scope, log, normalize_domain,
    open_db, utc_now_iso,
)


# Secret patterns (high-confidence regex)
SECRET_PATTERNS = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("gitlab_token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]+")),
    ("slack_webhook", re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("stripe_key", re.compile(r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}")),
    ("google_api", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("firebase", re.compile(r"(?i)firebase[^\s]*['\"]?\s*[=:]\s*['\"]?([a-z0-9\-]{20,})")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("basic_auth", re.compile(r"(?i)basic\s+[A-Za-z0-9+/]+=*")),
    ("private_key", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})")),
    ("generic_secret", re.compile(r"(?i)(client[_-]?secret|app[_-]?secret|secret[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})")),
    ("password", re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{6,})")),
]

# Known placeholder/template values — ignore these
PLACEHOLDER_VALUES = {
    "replace_me", "replaceme", "your_api_key", "your-api-key", "your_token",
    "example", "example_key", "test", "test_key", "changeme", "change_me",
    "todo", "fixme", "xxx", "null", "undefined", "none", "empty",
    "insert_key_here", "your_secret_here", "your_password_here",
    "password_placeholder", "secret_placeholder", "api_key_placeholder",
}

# Max file size to analyze (2MB) — skip huge bundles
MAX_JS_SIZE = 2 * 1024 * 1024

# Endpoint patterns
ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/api/[^"\']+)["\']'),
    re.compile(r'["\'](/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+(?:\?[^"\']*)?)["\']'),
    re.compile(r'["\']https?://[^"\']*(/api/[^"\']+)["\']'),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'\.get\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'\.post\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'\.put\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'\.delete\s*\(\s*["\']([^"\']+)["\']'),
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _extract_js_files(html: str, base_url: str) -> list[str]:
    """Extract JS file URLs from HTML, including sourcemap references."""
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1)
        absolute = urljoin(base_url, src)
        if absolute.endswith(".js") or "javascript" in absolute.lower():
            js_urls.add(absolute)
    # Also check for sourcemap references inside script tags
    for m in re.finditer(r'//#\s*sourceMappingURL=(.+)', html):
        map_url = m.group(1).strip()
        absolute = urljoin(base_url, map_url)
        js_urls.add(absolute)
    return list(js_urls)


def _extract_inline_scripts(html: str, base_url: str) -> list[str]:
    """Extract inline script blocks from HTML for analysis."""
    scripts = []
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL):
        content = m.group(1).strip()
        if content and len(content) > 50:  # Skip tiny inline scripts
            scripts.append(content)
    return scripts


def _analyze_js(js_url: str, client: httpx.Client, domain: str) -> dict:
    """Analyze a single JS file for secrets and endpoints."""
    result = {"url": js_url, "secrets": [], "endpoints": [], "high_entropy_strings": []}

    try:
        r = client.get(js_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        if r.status_code != 200:
            return result
        # Skip huge files
        if len(r.content) > MAX_JS_SIZE:
            return result
        content = r.text
    except Exception:
        return result

    return _analyze_content(content, js_url, domain, result)


def _analyze_inline(script_content: str, source_url: str, domain: str) -> dict:
    """Analyze inline script content for secrets and endpoints."""
    result = {"url": source_url, "secrets": [], "endpoints": [], "high_entropy_strings": []}
    return _analyze_content(script_content, source_url, domain, result)


def _analyze_content(content: str, source_url: str, domain: str, result: dict) -> dict:
    """Analyze text content for secrets and endpoints."""
    # Find secrets — filter placeholders and duplicates
    seen_secrets = set()
    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            match = m.group(0)
            if len(match) > 8:
                # Skip known placeholders
                match_lower = match.lower().strip()
                if any(p in match_lower for p in PLACEHOLDER_VALUES):
                    continue
                # Dedup
                secret_key = (name, match[:60])
                if secret_key in seen_secrets:
                    continue
                seen_secrets.add(secret_key)
                result["secrets"].append({"type": name, "value": match[:80]})

    # Find endpoints
    for pattern in ENDPOINT_PATTERNS:
        for m in pattern.finditer(content):
            endpoint = m.group(1) if m.lastindex else m.group(0)
            if endpoint.startswith("/") or domain in endpoint:
                if endpoint not in result["endpoints"]:
                    result["endpoints"].append(endpoint)

    # Find high-entropy strings — raise threshold to 5.0 to reduce FP
    for m in re.finditer(r'["\']([A-Za-z0-9+/=_-]{32,})["\']', content):
        s = m.group(1)
        if _shannon_entropy(s) > 5.0:
            if s not in result["high_entropy_strings"]:
                result["high_entropy_strings"].append(s[:60])

    return result


def run(domain: str, max_pages: int = 30) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'jsanalysis', ?, ?, 'running', ?)",
        (domain, "regex+entropy", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"JS analysis started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    # Collect all JS file URLs
    js_urls = set()
    for page_url, html in pages:
        for js_url in _extract_js_files(html, page_url):
            if host_in_scope(urlparse(js_url).netloc, domain):
                js_urls.add(js_url)

    log(con, scan_id, f"Found {len(js_urls)} JS files to analyze")

    all_secrets = []
    all_endpoints = []
    all_entropy = []
    seen_secrets = set()

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        # Analyze external JS files
        for js_url in js_urls:
            result = _analyze_js(js_url, client, domain)
            for s in result["secrets"]:
                s["js_url"] = js_url
                key = (s["type"], s["value"][:40])
                if key not in seen_secrets:
                    seen_secrets.add(key)
                    all_secrets.append(s)
            for e in result["endpoints"]:
                all_endpoints.append({"endpoint": e, "js_url": js_url})
            for h in result["high_entropy_strings"]:
                all_entropy.append({"value": h, "js_url": js_url})

        # Analyze inline scripts from crawled pages
        for page_url, html in pages:
            for script_content in _extract_inline_scripts(html, page_url):
                result = _analyze_inline(script_content, page_url, domain)
                for s in result["secrets"]:
                    s["js_url"] = page_url
                    key = (s["type"], s["value"][:40])
                    if key not in seen_secrets:
                        seen_secrets.add(key)
                        all_secrets.append(s)
                for e in result["endpoints"]:
                    all_endpoints.append({"endpoint": e, "js_url": page_url})
                for h in result["high_entropy_strings"]:
                    all_entropy.append({"value": h, "js_url": page_url})

    total_findings = len(all_secrets) + len(all_endpoints) + len(all_entropy)
    log(con, scan_id, f"Found {len(all_secrets)} secrets, {len(all_endpoints)} endpoints, {len(all_entropy)} high-entropy strings")

    # Store results
    for s in all_secrets:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"js_secret_{s['type']}", s["js_url"], "found",
             f"value={s['value']}", utc_now_iso()),
        )
    for e in all_endpoints:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "js_endpoint", e["js_url"], "found",
             f"endpoint={e['endpoint']}", utc_now_iso()),
        )
    for h in all_entropy:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "js_high_entropy", h["js_url"], "found",
             f"value={h['value']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(js_urls), total_links=total_findings)
    con.close()
    return {
        "scan_id": scan_id, "scanner": "jsanalysis", "domain": domain,
        "js_files": len(js_urls), "secrets": len(all_secrets),
        "endpoints": len(all_endpoints), "high_entropy": len(all_entropy),
        "findings": total_findings,
    }


SCANNER_REGISTRY["jsanalysis"] = run
SCANNER_REGISTRY["js"] = run
