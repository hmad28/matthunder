"""
Common helpers for scanners package.
"""

import json
import os
import re
import shutil
import sqlite3
import time
import uuid
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

import httpx

from . import DB_PATH


SCHEMES_ALLOWED = ("http", "https")
DEFAULT_TIMEOUT = 10.0
USER_AGENT = "matthunder/1.4 (+https://github.com/hmad28/matthunder)"
MAX_PAGES_PER_SCAN = 50
MAX_LINKS_PER_PAGE = 200


class RateLimiter:
    """Per-host rate limiter with exponential backoff."""
    def __init__(self, base_delay: float = 0.5, max_delay: float = 30.0, max_retries: int = 3):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self._host_last_hit: dict[str, float] = {}
        self._host_failures: dict[str, int] = {}

    def wait(self, host: str) -> None:
        import time
        now = time.time()
        last = self._host_last_hit.get(host, 0)
        failures = self._host_failures.get(host, 0)
        delay = min(self.base_delay * (2 ** failures), self.max_delay)
        elapsed = now - last
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._host_last_hit[host] = time.time()

    def record_failure(self, host: str) -> None:
        self._host_failures[host] = self._host_failures.get(host, 0) + 1

    def record_success(self, host: str) -> None:
        self._host_failures[host] = 0


# Global rate limiter instance
rate_limiter = RateLimiter()


def resolve_tool(name):
    """Find a tool binary — prioritize Go bin over Python pip scripts.

    Go tools (subfinder, httpx, nuclei, etc) live in ~/go/bin/.
    Python pip packages with same names (httpx) live in Python/Scripts/.
    Always prefer the Go version.
    """
    import shutil
    ext = ".exe" if os.name == "nt" else ""
    # 1. Go bin first
    go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", name + ext)
    if os.path.exists(go_bin):
        return go_bin
    # 2. PATH, but skip Python Scripts (pip httpx != Go httpx)
    found = shutil.which(name)
    if found:
        if "Python" in found and "Scripts" in found:
            return None
        return found
    return None


def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    for p in ("https://", "http://"):
        if d.startswith(p):
            d = d[len(p):]
    d = d.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    if not d or "." not in d:
        raise ValueError(f"invalid domain: {domain!r}")
    return d


def host_in_scope(host: str, root_domain: str) -> bool:
    h = (host or "").lower()
    rd = root_domain.lower()
    return h == rd or h.endswith("." + rd)


def canonical_url(url: str, include_query: bool = True) -> str:
    try:
        p = urlparse(url)
        if p.scheme not in SCHEMES_ALLOWED or not p.netloc:
            return ""
        scheme = p.scheme.lower()
        host = p.netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        path = p.path or "/"
        if include_query and p.query:
            return f"{scheme}://{host}{path}?{p.query}"
        return f"{scheme}://{host}{path}"
    except Exception:
        return ""


def get_root_urls(domain: str) -> list[str]:
    return [f"https://{domain}", f"http://{domain}"]


ANCHOR_RE = re.compile(
    r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
TAG_STRIP_RE = re.compile(r"<[^>]+>")
HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


def extract_anchors(html: str, base_url: str) -> list[dict]:
    out = []
    for m in ANCHOR_RE.finditer(html or ""):
        href_raw, inner = m.group(1), m.group(2)
        anchor = TAG_STRIP_RE.sub(" ", inner)
        anchor = re.sub(r"\s+", " ", anchor).strip()
        absolute = urljoin(base_url, href_raw)
        canonical = canonical_url(absolute)
        if not canonical:
            continue
        out.append({"href": href_raw, "absolute": absolute, "canonical": canonical, "anchor": anchor[:200]})
    return out


def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        scanner TEXT NOT NULL,
        domain TEXT NOT NULL,
        params TEXT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        finished_at TEXT,
        total_sources INTEGER DEFAULT 0,
        total_links INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        category TEXT,
        target_url TEXT NOT NULL,
        source_url TEXT,
        anchor TEXT,
        status TEXT,
        http_code INTEGER,
        detail TEXT,
        extracted_at TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    );
    CREATE TABLE IF NOT EXISTS scan_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        message TEXT,
        logged_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
    CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_url);
    CREATE INDEX IF NOT EXISTS idx_results_source ON results(source_url);
    CREATE INDEX IF NOT EXISTS idx_scans_scanner_domain ON scans(scanner, domain);
    """)


def open_db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    ensure_schema(con)
    return con


def create_scan(con: sqlite3.Connection, scanner: str, domain: str, params: dict) -> str:
    scan_id = str(uuid.uuid4())
    con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (?, ?, ?, ?, 'running', ?)",
        (scan_id, scanner, domain, json.dumps(params or {}), utc_now_iso()),
    )
    con.commit()
    return scan_id


def finish_scan(con: sqlite3.Connection, scan_id: str, status: str = "completed",
                total_sources: int = 0, total_links: int = 0) -> None:
    con.execute(
        "UPDATE scans SET status=?, finished_at=?, total_sources=?, total_links=? WHERE id=?",
        (status, utc_now_iso(), total_sources, total_links, scan_id),
    )
    con.commit()


def log(con: sqlite3.Connection, scan_id: str, message: str) -> None:
    con.execute(
        "INSERT INTO scan_log (scan_id, message, logged_at) VALUES (?, ?, ?)",
        (scan_id, message, utc_now_iso()),
    )
    con.commit()


def fetch(url: str, client: httpx.Client, retries: int = 2) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Return (final_url, status_code, error). Uses rate limiter with retry."""
    host = urlparse(url).netloc
    last_err = None
    for attempt in range(retries + 1):
        rate_limiter.wait(host)
        try:
            r = client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            rate_limiter.record_success(host)
            return (str(r.url), r.status_code, None)
        except httpx.TimeoutException:
            rate_limiter.record_failure(host)
            last_err = "timeout"
        except Exception as e:
            rate_limiter.record_failure(host)
            last_err = type(e).__name__
    return (None, None, last_err)


def crawl_domain(domain: str, max_pages: int = MAX_PAGES_PER_SCAN) -> list[tuple[str, str]]:
    """Return list of (canonical_url, html) for in-scope pages.

    Uses robots.txt / sitemap seeds when available, then BFS from root.
    """
    pages: list[tuple[str, str]] = []
    seen: set[str] = set()
    queue: list[str] = list(get_root_urls(domain))
    start_time = time.time()
    max_crawl_time = 30  # Max 30 seconds for crawling
    try:
        with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
            while queue and len(pages) < max_pages:
                if time.time() - start_time > max_crawl_time:
                    break
                url = queue.pop(0)
                cu = canonical_url(url)
                if not cu or cu in seen:
                    continue
                if not host_in_scope(urlparse(cu).netloc, domain):
                    continue
                seen.add(cu)
                host = urlparse(cu).netloc
                rate_limiter.wait(host)
                try:
                    r = client.get(cu, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
                    rate_limiter.record_success(host)
                    if r.status_code >= 400:
                        continue
                    final_url = str(r.url)
                    if not host_in_scope(urlparse(final_url).netloc, domain):
                        continue
                    ct = r.headers.get("content-type", "")
                    if "html" not in ct.lower():
                        continue
                    html = r.text[:200000]
                except Exception:
                    rate_limiter.record_failure(host)
                    continue
                pages.append((final_url, html))
                anchors = extract_anchors(html, final_url)
                for a in anchors:
                    if host_in_scope(urlparse(a["canonical"]).netloc, domain) and a["canonical"] not in seen:
                        queue.append(a["canonical"])
    except Exception:
        pass
    return pages


def dedupe_preserve_order(items: Iterable) -> list:
    seen = set()
    out = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return out


# ─── Dynamic parameter pre-check ─────────────────────────────────────────────

def is_dynamic_param(url: str, param: str, client: httpx.Client) -> bool:
    """Check if a parameter actually influences the response.

    Sends two different values and compares responses.
    If responses are identical, the parameter is static (not injectable).
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return False

    val1 = "mtcheck1"
    val2 = "mtcheck2"

    qs1 = dict(qs)
    qs1[param] = [val1]
    url1 = urlunparse(parsed._replace(query=urlencode(qs1, doseq=True)))

    qs2 = dict(qs)
    qs2[param] = [val2]
    url2 = urlunparse(parsed._replace(query=urlencode(qs2, doseq=True)))

    try:
        r1 = client.get(url1, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        r2 = client.get(url2, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        if r1.status_code != r2.status_code:
            return True
        if abs(len(r1.text) - len(r2.text)) > 20:
            return True
        if r1.text[:500] != r2.text[:500]:
            return True
    except Exception:
        pass
    return False


def is_spa_catchall(domain: str, client: httpx.Client) -> bool:
    """Detect if a domain is a SPA that returns 200 for every path.

    Tests with random/nonexistent paths and compares response bodies.
    If all responses are identical (same size, same content), it's a SPA catch-all.
    """
    import hashlib
    test_paths = [
        "/nonexistent_test_path_xyz123",
        "/asdfghjkl_random_456",
        "/totally_fake_page_789",
        "/.well-known/fake_probe",
    ]
    bodies = []
    for path in test_paths:
        url = f"https://{domain}{path}"
        try:
            r = client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            if r.status_code == 200:
                bodies.append(r.text[:2000])
        except Exception:
            continue

    if len(bodies) < 3:
        return False

    # Hash each body and compare
    hashes = [hashlib.md5(b.encode("utf-8", errors="ignore")).hexdigest() for b in bodies]
    # If 3+ out of 4 have same hash, it's a catch-all
    from collections import Counter
    counts = Counter(hashes)
    most_common_count = counts.most_common(1)[0][1]
    return most_common_count >= 3


# ─── Fallback endpoint discovery ─────────────────────────────────────────────

FALLBACK_ENDPOINTS = [
    "/search", "/api/search", "/api/v1/search", "/api/query",
    "/login", "/api/login", "/admin", "/api/users", "/api/items",
    "/api/products", "/profile", "/user", "/page", "/redirect",
    "/api/v1/users", "/api/v1/items", "/q", "/find", "/error",
    "/contact", "/feedback", "/api/comments", "/api/reviews",
]

FALLBACK_PARAMS = {
    "sqli": ["id", "user", "username", "search", "q", "query", "filter",
             "sort", "order", "page", "category", "item", "product",
             "email", "name", "ref", "article", "post", "comment"],
    "xss": ["q", "search", "query", "s", "keyword", "name", "input",
            "text", "msg", "error", "redirect", "url", "page",
            "callback", "id", "user", "term", "data"],
    "lfi": ["file", "path", "page", "doc", "template", "include", "url",
            "load", "read", "download", "content", "view", "open",
            "dir", "folder", "document", "img", "image"],
    "openredirect": ["url", "redirect", "redirect_url", "redirect_uri",
                     "return", "return_url", "next", "go", "goto",
                     "target", "dest", "destination", "redir",
                     "continue", "returnPath", "to", "out", "ref"],
}


def discover_targets(domain: str, max_pages: int = 50) -> list[tuple[str, str]]:
    """Crawl domain and return list of (url, param) targets for injection testing.

    Combines crawled URLs with fallback endpoint testing.
    """
    pages = crawl_domain(domain, max_pages=max_pages)
    targets: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # From crawled pages
    for page_url, html in pages:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(page_url)
        params = list(parse_qs(parsed.query).keys())
        for param in params:
            key = (page_url.split("?")[0], param)
            if key not in seen:
                seen.add(key)
                targets.append((page_url, param))

    # Fallback: test common endpoints with common params
    base_urls = [f"https://{domain}", f"http://{domain}"]
    for base in base_urls:
        for endpoint in FALLBACK_ENDPOINTS:
            full = f"{base}{endpoint}"
            for param in FALLBACK_PARAMS.get("sqli", [])[:6]:
                key = (full, param)
                if key not in seen:
                    seen.add(key)
                    targets.append((full, param))

    return targets


def merge_crawled_and_fallback(crawled_urls: list[str], domain: str,
                               scanner_type: str = "sqli",
                               max_pages: int = 50) -> list[tuple[str, str]]:
    """Merge pre-discovered URLs (from pipeline) with fallback endpoint testing.

    Returns list of (url, param) targets.
    """
    from urllib.parse import urlparse, parse_qs

    targets: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # From pre-discovered URLs
    for url in crawled_urls:
        if "?" not in url:
            continue
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        for param in params:
            base = url.split("?")[0]
            key = (base, param)
            if key not in seen:
                seen.add(key)
                targets.append((url, param))

    # Fallback endpoints
    base_urls = [f"https://{domain}", f"http://{domain}"]
    params_list = FALLBACK_PARAMS.get(scanner_type, FALLBACK_PARAMS["sqli"])
    for base in base_urls:
        for endpoint in FALLBACK_ENDPOINTS:
            full = f"{base}{endpoint}"
            for param in params_list[:6]:
                key = (full, param)
                if key not in seen:
                    seen.add(key)
                    targets.append((full, param))

    return targets
