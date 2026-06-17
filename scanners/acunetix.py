"""
Acunetix scanner — pull scans/vulnerabilities from Acunetix API.

Sub-commands (CLI):
  python matthunder_cli.py acunetix list              # list all scans
  python matthunder_cli.py acunetix targets           # list all targets
  python matthunder_cli.py acunetix summary           # dashboard: scans + vuln counts by severity
  python matthunder_cli.py acunetix vulns <scan_id>   # vuln list for a scan
  python matthunder_cli.py acunetix detail <vuln_id>  # full vuln detail

Auth: X-Auth header (API key from Acunetix UI > Profile > API Key).
Config keys (config.py or env):
  ACUNETIX_URL        e.g. https://acunetix.local:3443
  ACUNETIX_API_KEY    long API key string
  ACUNETIX_VERIFY_SSL False to skip TLS verify (self-signed)
"""

import os
import sys
import time
from typing import Optional
from urllib.parse import urljoin

import httpx

from . import SCANNER_REGISTRY
from .common import (
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


API_BASE = "/api/v1/"
DEFAULT_TIMEOUT = 30.0

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_COLOR = {
    "Critical": "\033[91m", "High": "\033[93m", "Medium": "\033[93m",
    "Low": "\033[94m", "Informational": "\033[90m",
}
RST = "\033[0m"


# ─── Config loader ───────────────────────────────────────────────────────────

def _load_config() -> dict:
    """Read Acunetix config from env or config.py."""
    url = os.getenv("ACUNETIX_URL")
    key = os.getenv("ACUNETIX_API_KEY")
    verify = os.getenv("ACUNETIX_VERIFY_SSL", "true").lower() not in ("0", "false", "no")
    try:
        import config as lazy
        url = url or getattr(lazy, "ACUNETIX_URL", None)
        key = key or getattr(lazy, "ACUNETIX_API_KEY", None)
        if hasattr(lazy, "ACUNETIX_VERIFY_SSL"):
            verify = bool(getattr(lazy, "ACUNETIX_VERIFY_SSL"))
    except Exception:
        pass
    return {"url": (url or "").rstrip("/"), "key": (key or "").strip(), "verify": verify}


def _err(msg: str, **extra) -> dict:
    out = {"ok": False, "error": msg, "scanner": "acunetix"}
    out.update(extra)
    return out


# ─── HTTP client ─────────────────────────────────────────────────────────────

def _client(cfg: dict) -> httpx.Client:
    if not cfg["url"] or not cfg["key"]:
        raise RuntimeError("ACUNETIX_URL / ACUNETIX_API_KEY not configured")
    return httpx.Client(
        base_url=cfg["url"] + API_BASE,
        headers={"X-Auth": cfg["key"], "Accept": "application/json"},
        verify=cfg["verify"],
        timeout=DEFAULT_TIMEOUT,
    )


def _get(client: httpx.Client, path: str, params: Optional[dict] = None) -> dict:
    r = client.get(path, params=params or {})
    if r.status_code == 401:
        raise RuntimeError("Acunetix auth failed (401). Check ACUNETIX_API_KEY.")
    if r.status_code == 404:
        raise RuntimeError(f"Acunetix endpoint not found: {path}")
    r.raise_for_status()
    return r.json()


def _paginate(client: httpx.Client, path: str, key: str = None) -> list[dict]:
    """Yield all items across pagination (Acunetix uses ?limit=N&cursor=...)."""
    out: list[dict] = []
    cursor = 0
    while True:
        params = {"l": 100, "c": cursor}
        data = _get(client, path, params=params)
        items = data.get(key or path) or data.get("results") or []
        if isinstance(items, dict):
            items = list(items.values())
        out.extend(items)
        if len(items) < 100:
            break
        cursor += 100
    return out


# ─── Fetchers ────────────────────────────────────────────────────────────────

def fetch_scans(client: httpx.Client) -> list[dict]:
    return _paginate(client, "scans")


def fetch_targets(client: httpx.Client) -> list[dict]:
    return _paginate(client, "targets")


def fetch_vulnerabilities(client: httpx.Client, scan_id: str) -> list[dict]:
    return _paginate(client, f"scans/{scan_id}/results")


def fetch_vuln_detail(client: httpx.Client, vuln_id: str) -> dict:
    return _get(client, f"vulnerabilities/{vuln_id}")


def fetch_profiles(client: httpx.Client) -> list[dict]:
    """List available scan profiles (used to start a scan)."""
    try:
        data = _get(client, "scanning_profiles")
    except Exception:
        # Older Acunetix API path
        try:
            data = _get(client, "profiles")
        except Exception:
            return []
    profiles = data.get("scanning_profiles") or data.get("profiles") or []
    if isinstance(profiles, dict):
        profiles = list(profiles.values())
    return profiles


def start_scan(client: httpx.Client, target_id: str, profile_id: str = None) -> dict:
    """Start a new scan on a target. Returns the API response.

    If profile_id is None, picks the first available profile.
    """
    if not profile_id:
        profiles = fetch_profiles(client)
        if not profiles:
            return {"ok": False, "error": "no scan profiles available"}
        profile_id = profiles[0].get("profile_id") or profiles[0].get("id")
    payload = {"target_id": target_id, "profile_id": profile_id}
    try:
        r = client.post("scans", json=payload)
    except Exception as e:
        return {"ok": False, "error": f"POST failed: {e}"}
    if r.status_code in (401, 403):
        return {"ok": False, "error": f"auth failed: HTTP {r.status_code}"}
    if r.status_code == 404:
        return {"ok": False, "error": "scans endpoint not found (Acunetix version mismatch?)"}
    if r.status_code == 409:
        return {"ok": False, "error": "scan already running for this target"}
    if r.status_code >= 400:
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    try:
        data = r.json()
    except Exception:
        return {"ok": False, "error": f"non-JSON response: {r.text[:200]}"}
    scan_id = data.get("scan_id") or data.get("id")
    return {"ok": True, "scan_id": scan_id, "target_id": target_id, "profile_id": profile_id, "raw": data}


def fetch_scan_status(client: httpx.Client, scan_id: str) -> str:
    """Return scan status string (queued, running, completed, failed, aborted, …)."""
    try:
        s = _get(client, f"scans/{scan_id}")
    except Exception:
        return "unknown"
    sess = s.get("current_session") or {}
    return sess.get("status") or s.get("status") or "unknown"


def add_target(client: httpx.Client, address: str, description: str = "") -> dict:
    """Create a new target in Acunetix.

    Acunetix API: POST /api/v1/targets with body {"address": "...", "description": "..."}
    Returns the created target object containing target_id.
    """
    payload = {"address": address, "description": description or ""}
    try:
        r = client.post("targets", json=payload)
    except Exception as e:
        return {"ok": False, "error": f"POST failed: {e}"}
    if r.status_code in (401, 403):
        return {"ok": False, "error": f"auth failed: HTTP {r.status_code}"}
    if r.status_code == 404:
        return {"ok": False, "error": "targets endpoint not found (Acunetix version mismatch?)"}
    if r.status_code >= 400:
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    try:
        data = r.json()
    except Exception:
        return {"ok": False, "error": f"non-JSON response: {r.text[:200]}"}
    target_id = data.get("target_id") or data.get("id")
    return {"ok": True, "target_id": target_id, "address": data.get("address", address), "raw": data}


def delete_target(client: httpx.Client, target_id: str) -> dict:
    """Delete a target from Acunetix.

    Acunetix API: DELETE /api/v1/targets/{target_id}
    Returns {"ok": True} on 204, else error.
    """
    try:
        r = client.delete(f"targets/{target_id}")
    except Exception as e:
        return {"ok": False, "error": f"DELETE failed: {e}"}
    if r.status_code in (401, 403):
        return {"ok": False, "error": f"auth failed: HTTP {r.status_code}"}
    if r.status_code == 404:
        return {"ok": False, "error": "target not found"}
    if r.status_code >= 400:
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    return {"ok": True, "target_id": target_id}


def update_vuln_status(client: httpx.Client, vuln_id: str, status: str) -> dict:
    """Update vulnerability status (open / fixed / false_positive / ignored / urgent).

    Acunetix API: PATCH /api/v1/vulnerabilities/{vuln_id}
    Body: {"status": "..."}  (in newer versions)
    Older versions: PATCH /vulnerabilities/{id}/status with same body.
    """
    payload = {"status": status}
    last_err = None
    for path in (f"vulnerabilities/{vuln_id}", f"vulnerabilities/{vuln_id}/status"):
        try:
            r = client.patch(path, json=payload)
        except Exception as e:
            last_err = f"PATCH failed: {e}"
            continue
        if r.status_code in (200, 204):
            return {"ok": True, "vuln_id": vuln_id, "status": status}
        if r.status_code in (401, 403):
            return {"ok": False, "error": f"auth failed: HTTP {r.status_code}"}
        if r.status_code == 404:
            last_err = f"404 on {path}"
            continue
        last_err = f"HTTP {r.status_code} on {path}: {r.text[:200]}"
    return {"ok": False, "error": last_err or "unknown error"}


# ─── Formatters ──────────────────────────────────────────────────────────────

def _fmt_severity(sev: str) -> str:
    sev = sev or "Informational"
    color = SEVERITY_COLOR.get(sev, "")
    return f"{color}{sev:<14}{RST}" if color else f"{sev:<14}"


def _trunc(s: str, n: int) -> str:
    s = (s or "").replace("\n", " ").replace("\r", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _scan_summary(scan: dict) -> dict:
    """Extract relevant fields from a scan record."""
    profile_name = ""
    profile = scan.get("profile") or {}
    if isinstance(profile, dict):
        profile_name = profile.get("name", "")
    target = scan.get("target") or {}
    address = target.get("address") if isinstance(target, dict) else ""
    return {
        "scan_id": scan.get("scan_id") or scan.get("id"),
        "target": address or "",
        "profile": profile_name,
        "status": scan.get("status", ""),
        "start_date": scan.get("start_date", ""),
        "end_date": scan.get("end_date", ""),
        "criticality": scan.get("criticality", 0),
    }


def print_scan_list(scans: list[dict]) -> None:
    if not scans:
        print("  (no scans found)")
        return
    print(f"  {'SCAN ID':<20} {'TARGET':<35} {'STATUS':<12} {'STARTED':<20} {'PROFILE'}")
    print(f"  {'─' * 20} {'─' * 35} {'─' * 12} {'─' * 20} {'─' * 30}")
    for s in scans[:100]:
        info = _scan_summary(s)
        sid = _trunc(str(info["scan_id"] or "?"), 18)
        tgt = _trunc(info["target"], 33)
        st = _trunc(info["status"], 10)
        stt = _trunc(info["start_date"].replace("T", " ").rstrip("Z")[:19], 19)
        prof = _trunc(info["profile"], 28)
        print(f"  {sid:<20} {tgt:<35} {st:<12} {stt:<20} {prof}")
    if len(scans) > 100:
        print(f"  … {len(scans) - 100} more (use API for full list)")


def print_target_list(targets: list[dict]) -> None:
    if not targets:
        print("  (no targets found)")
        return
    print(f"  {'TARGET ID':<24} {'ADDRESS':<40} {'DESCRIPTION'}")
    print(f"  {'─' * 24} {'─' * 40} {'─' * 30}")
    for t in targets[:100]:
        tid = _trunc(str(t.get("target_id") or "?"), 22)
        addr = _trunc(t.get("address", ""), 38)
        desc = _trunc(t.get("description", ""), 40)
        print(f"  {tid:<24} {addr:<40} {desc}")
    if len(targets) > 100:
        print(f"  … {len(targets) - 100} more")


def print_dashboard(scans: list[dict], targets: list[dict]) -> dict:
    """Build dashboard: counts by severity across all scans (fetches vuln lists)."""
    cfg = _load_config()
    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    per_scan: list[dict] = []
    print(f"  Fetching vulnerability counts across {len(scans)} scan(s)…")
    with _client(cfg) as c:
        for s in scans:
            sid = s.get("scan_id") or s.get("id")
            try:
                vulns = fetch_vulnerabilities(c, sid)
            except Exception as e:
                print(f"    [skip] {sid}: {e}")
                continue
            counts = {sev: 0 for sev in SEVERITY_ORDER}
            for v in vulns:
                sev = v.get("severity") or "Informational"
                if sev not in counts:
                    sev = "Informational"
                counts[sev] += 1
                severity_counts[sev] += 1
            per_scan.append({"scan": _scan_summary(s), "counts": counts, "total": len(vulns)})
    return {"per_scan": per_scan, "totals": severity_counts, "scans_total": len(scans)}


def render_dashboard(data: dict) -> None:
    totals = data["totals"]
    grand = sum(totals.values())
    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║              ACUNETIX VULNERABILITY DASHBOARD            ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print()
    print(f"  Scans:        {data['scans_total']}")
    print(f"  Total vulns:  {grand}")
    print()
    print("  Severity breakdown:")
    for sev in SEVERITY_ORDER:
        c = totals[sev]
        bar = "█" * min(c, 50)
        pct = (c / grand * 100) if grand else 0
        print(f"    {_fmt_severity(sev)} {c:>5}  ({pct:5.1f}%)  {bar}")
    print()
    print("  Per-scan breakdown:")
    print(f"  {'SCAN ID':<18} {'TARGET':<30} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'INFO':>5} {'TOTAL':>7}")
    print(f"  {'─' * 18} {'─' * 30} {'─' * 5} {'─' * 5} {'─' * 5} {'─' * 5} {'─' * 5} {'─' * 7}")
    for entry in data["per_scan"][:30]:
        s = entry["scan"]
        c = entry["counts"]
        sid = _trunc(str(s["scan_id"] or "?"), 16)
        tgt = _trunc(s["target"], 28)
        print(
            f"  {sid:<18} {tgt:<30} "
            f"{c['Critical']:>5} {c['High']:>5} {c['Medium']:>5} {c['Low']:>5} {c['Informational']:>5} "
            f"{entry['total']:>7}"
        )
    if len(data["per_scan"]) > 30:
        print(f"  … {len(data['per_scan']) - 30} more scans")
    print()


def print_vuln_list(vulns: list[dict]) -> None:
    if not vulns:
        print("  (no vulnerabilities for this scan)")
        return
    print(f"  {'VULN ID':<20} {'SEVERITY':<14} {'NAME':<45} {'URL'}")
    print(f"  {'─' * 20} {'─' * 14} {'─' * 45} {'─' * 50}")
    for v in vulns[:200]:
        vid = _trunc(str(v.get("vuln_id") or "?"), 18)
        sev = v.get("severity") or "Informational"
        name = _trunc(v.get("vuln_name") or v.get("name") or "?", 43)
        url = _trunc(
            (v.get("affects_url") or v.get("affects") or "").split("?")[0],
            48,
        )
        print(f"  {vid:<20} {_fmt_severity(sev)} {name:<45} {url}")
    if len(vulns) > 200:
        print(f"  … {len(vulns) - 200} more")


def print_vuln_detail(v: dict) -> None:
    print()
    print(f"  Vuln ID:      {v.get('vuln_id') or v.get('id')}")
    print(f"  Name:         {v.get('vuln_name') or v.get('name')}")
    print(f"  Severity:     {_fmt_severity(v.get('severity') or 'Informational')}")
    print(f"  CVSS:         v2={v.get('cvss_score')}  v3={v.get('cvss3_score')}")
    print(f"  Status:       {v.get('status', '?')}")
    print(f"  URL:          {v.get('affects_url') or v.get('affects')}")
    details = v.get("details") or v.get("description") or ""
    if details:
        print()
        print("  Details:")
        for line in details.splitlines()[:30]:
            print(f"    {line}")
    rec = v.get("recommendation") or v.get("remediation") or ""
    if rec:
        print()
        print("  Recommendation:")
        for line in rec.splitlines()[:20]:
            print(f"    {line}")


# ─── Sub-command dispatch (CLI uses this) ────────────────────────────────────

def run_subcommand(action: str, *args) -> dict:
    """Top-level entry used by matthunder_cli.py.

    action: 'list' | 'targets' | 'summary' | 'vulns' | 'detail'
    args:   action-specific (e.g. scan_id or vuln_id)
    """
    cfg = _load_config()
    if not cfg["url"] or not cfg["key"]:
        return _err(
            "ACUNETIX_URL / ACUNETIX_API_KEY not set. "
            "Add to config.py or env vars."
        )

    try:
        with _client(cfg) as c:
            if action == "list":
                scans = fetch_scans(c)
                print()
                print(f"  ╔══════════════════════════════════════════════════════════╗")
                print(f"  ║  ACUNETIX — {cfg['url']:<46}║")
                print(f"  ╚══════════════════════════════════════════════════════════╝")
                print(f"  Total scans: {len(scans)}")
                print()
                print_scan_list(scans)
                return {"ok": True, "count": len(scans), "scans": [_scan_summary(s) for s in scans]}

            elif action == "targets":
                targets = fetch_targets(c)
                print()
                print(f"  ACUNETIX TARGETS — {cfg['url']}")
                print(f"  Total targets: {len(targets)}")
                print()
                print_target_list(targets)
                return {"ok": True, "count": len(targets), "targets": targets}

            elif action == "summary":
                scans = fetch_scans(c)
                targets = fetch_targets(c)
                data = print_dashboard(scans, targets)
                data["targets"] = len(targets)
                render_dashboard(data)
                _persist_summary(data)
                return {"ok": True, "findings": sum(data["totals"].values())}

            elif action == "vulns":
                if not args:
                    return _err("vulns action needs a scan_id")
                scan_id = args[0]
                vulns = fetch_vulnerabilities(c, scan_id)
                print()
                print(f"  ACUNETIX VULNERABILITIES — scan {scan_id}")
                print(f"  Total: {len(vulns)}")
                print()
                print_vuln_list(vulns)
                _persist_vulns(scan_id, vulns)
                return {"ok": True, "scan_id": scan_id, "count": len(vulns), "vulns": vulns}

            elif action == "detail":
                if not args:
                    return _err("detail action needs a vuln_id")
                vuln_id = args[0]
                v = fetch_vuln_detail(c, vuln_id)
                print_vuln_detail(v)
                return {"ok": True, "vuln_id": vuln_id}

            else:
                return _err(f"unknown action: {action}")
    except RuntimeError as e:
        return _err(str(e))
    except httpx.HTTPError as e:
        return _err(f"HTTP error: {e}")
    except Exception as e:
        return _err(f"unexpected: {e}")


# ─── DB persistence ──────────────────────────────────────────────────────────

def _persist_summary(data: dict) -> None:
    """Save a 'acunetix_summary' record (one row per scan) into results table."""
    try:
        con = open_db()
        scan_id = con.execute(
            "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
            "VALUES (lower(hex(randomblob(16))), 'acunetix_summary', 'acunetix', ?, 'completed', ?)",
            (str(data["totals"]), utc_now_iso()),
        ).lastrowid
        con.commit()
        scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
        for entry in data["per_scan"]:
            s = entry["scan"]
            con.execute(
                "INSERT INTO results (scan_id, category, target_url, source_url, anchor, status, detail, extracted_at) "
                "VALUES (?, ?, ?, ?, ?, 'info', ?, ?)",
                (
                    scan_id, s["scan_id"] or "?", s["target"] or "?",
                    f"profile={s['profile']}", s["status"],
                    str(entry["counts"]), utc_now_iso(),
                ),
            )
        con.commit()
        finish_scan(con, scan_id, status="completed", total_sources=len(data["per_scan"]), total_links=sum(data["totals"].values()))
        con.close()
    except Exception:
        pass


def _persist_vulns(scan_id: str, vulns: list[dict]) -> None:
    try:
        con = open_db()
        row_id = con.execute(
            "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
            "VALUES (lower(hex(randomblob(16))), 'acunetix_vulns', ?, ?, 'completed', ?)",
            (scan_id, str(len(vulns)), utc_now_iso()),
        ).lastrowid
        con.commit()
        db_scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (row_id,)).fetchone()["id"]
        for v in vulns:
            sev = v.get("severity") or "Informational"
            url = v.get("affects_url") or v.get("affects") or ""
            name = v.get("vuln_name") or v.get("name") or "?"
            con.execute(
                "INSERT INTO results (scan_id, category, target_url, source_url, anchor, status, detail, extracted_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    db_scan_id, sev, url, scan_id, name,
                    v.get("status") or "open", v.get("vuln_id") or "?", utc_now_iso(),
                ),
            )
        con.commit()
        finish_scan(con, db_scan_id, status="completed", total_sources=len(vulns), total_links=len(vulns))
        con.close()
    except Exception:
        pass


# ─── Default run() — dashboard view (registered as SCANNER_REGISTRY['acunetix']) ─

def run(domain: str = "") -> dict:
    """Default entry: show dashboard."""
    return run_subcommand("summary")


SCANNER_REGISTRY["acunetix"] = run
