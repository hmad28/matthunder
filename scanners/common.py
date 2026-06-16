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


def canonical_url(url: str) -> str:
    try:
        p = urlparse(url)
        if p.scheme not in SCHEMES_ALLOWED or not p.netloc:
            return ""
        scheme = p.scheme.lower()
        host = p.netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        path = p.path or "/"
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


def fetch(url: str, client: httpx.Client) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Return (final_url, status_code, error)."""
    try:
        r = client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        return (str(r.url), r.status_code, None)
    except httpx.TimeoutException:
        return (None, None, "timeout")
    except Exception as e:
        return (None, None, type(e).__name__)


def crawl_domain(domain: str, max_pages: int = MAX_PAGES_PER_SCAN) -> list[tuple[str, str]]:
    """Return list of (canonical_url, html) for in-scope pages.

    Uses robots.txt / sitemap seeds when available, then BFS from root.
    """
    pages: list[tuple[str, str]] = []
    seen: set[str] = set()
    queue: list[str] = list(get_root_urls(domain))
    try:
        with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
            while queue and len(pages) < max_pages:
                url = queue.pop(0)
                cu = canonical_url(url)
                if not cu or cu in seen:
                    continue
                if not host_in_scope(urlparse(cu).netloc, domain):
                    continue
                seen.add(cu)
                final, code, err = fetch(cu, client)
                if err or code is None or code >= 400:
                    continue
                if not final or not host_in_scope(urlparse(final).netloc, domain):
                    continue
                try:
                    r = client.get(final, timeout=DEFAULT_TIMEOUT)
                    if r.status_code >= 400:
                        continue
                    ct = r.headers.get("content-type", "")
                    if "html" not in ct.lower():
                        continue
                    html = r.text[:200000]
                except Exception:
                    continue
                pages.append((final, html))
                anchors = extract_anchors(html, final)
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
