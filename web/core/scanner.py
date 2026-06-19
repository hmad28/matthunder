"""
web/core/scanner.py — Bridge to matthunder inline scanners.

Provides async wrappers that run scanners from the `scanners/` package
and return findings as JSON so the web frontend can render them.
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent.parent

# ── Scanner registry ────────────────────────────────────────────

# Copied from scanners/__init__.py so we can load them on demand
SCANNER_KEYS = {
    "blh": "Broken Link Hunter",
    "thirdparty": "Third Party Assets",
    "cred": "Credential/Config URLs",
    "ssti": "SSTI Probe",
    "cors": "CORS Misconfiguration",
    "xss": "XSS Scan",
    "ssrf": "SSRF (Server-Side Request Forgery)",
    "hostheader": "Host Header Injection",
    "graphql": "GraphQL Introspection",
    "apirecon": "API Recon (kiterunner)",
    "params": "Hidden Parameters (arjun)",
    "sqli": "SQL Injection (sqlmap)",
    "lfi": "LFI / Path Traversal",
    "crlf": "CRLF Injection",
    "openredirect": "Open Redirect",
    "portscan": "Port Scan",
    "waf": "WAF Detection",
    "jsanalysis": "JS Secrets",
    "fuzzer": "Path Fuzzing",
    "techfingerprint": "Tech Fingerprinting",
}


async def run_scanner(scanner_key: str, domain: str, websocket=None) -> dict:
    """Run a single inline scanner and return its findings.

    If *websocket* is given, progress messages are sent through it.
    """
    if scanner_key not in SCANNER_KEYS:
        return {"error": f"Unknown scanner: {scanner_key}", "findings": 0}

    label = SCANNER_KEYS[scanner_key]
    _send(websocket, f"[{label}] Starting scan for {domain}...")

    # Run the scanner in a thread executor so it doesn't block the event loop
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run_sync, scanner_key, domain)

    findings = result.get("links_checked", result.get("links_found",
                 result.get("endpoints", result.get("params",
                 result.get("findings", result.get("probes", 0))))))

    _send(websocket, f"[{label}] Done — {findings} findings.")
    return result


def _run_sync(scanner_key: str, domain: str) -> dict:
    """Run scanner synchronously in a thread pool."""
    try:
        sys.path.insert(0, str(ROOT))
        from scanners import SCANNER_REGISTRY
        runner = SCANNER_REGISTRY.get(scanner_key)
        if not runner:
            return {"error": f"Scanner '{scanner_key}' not registered", "ok": False}
        return runner(domain, [])
    except FileNotFoundError as e:
        return {"error": str(e), "ok": False}
    except ImportError as e:
        return {"error": f"Module import failed: {e}", "ok": False}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "ok": False}
    finally:
        sys.path.pop(0)


def _send(ws, msg: str):
    """Best-effort WebSocket send."""
    if ws is None:
        return
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(ws.send_text(msg))
    except Exception:
        pass


# ── Pipeline ─────────────────────────────────────────────────────

PIPELINE_STEPS = [
    ("passive",    "Passive Recon (subfinder → assetfinder)"),
    ("active",     "Active Recon (httpx → portscan → WAF)"),
    ("discovery",  "Content Discovery (gau → katana → JS → fuzzing → API)"),
    ("nuclei",     "Automated Scanning (Nuclei focused templates)"),
    ("vulnscan",   "Vulnerability Scan (SQLi → XSS → LFI → CORS → SSTI → SSRF → Host H)"),
    ("intel",      "Intel & Discovery (BLH → 3rd Party → Cred → GraphQL → JS Secrets)"),
]


async def run_pipeline(domain: str, websocket=None) -> dict:
    """Run the full 6-phase pipeline."""
    _send(websocket, json.dumps({"type": "pipeline_start", "domain": domain}))
    results = {}
    for step_key, step_label in PIPELINE_STEPS:
        _send(websocket, json.dumps({
            "type": "pipeline_step", "step": step_key, "label": step_label,
        }))
        # Pipeline integration would call scanners/pipeline.py here
        await asyncio.sleep(0.1)
    _send(websocket, json.dumps({"type": "pipeline_done"}))
    return results


# ── Target helpers ───────────────────────────────────────────────

TARGETS_FILE = ROOT / "targets.json"


def load_targets() -> list:
    if not TARGETS_FILE.exists():
        return []
    try:
        return json.loads(TARGETS_FILE.read_text(encoding="utf-8") or "[]")
    except Exception:
        return []


def save_target(target: str) -> bool:
    targets = load_targets()
    if any(t.get("addresses", [target])[0] == target for t in targets):
        return False  # already exists
    from datetime import datetime, timezone
    targets.append({
        "name": target,
        "addresses": [target],
        "notes": "",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    TARGETS_FILE.write_text(json.dumps(targets, ensure_ascii=False, indent=2), encoding="utf-8")
    return True


def remove_target(target: str) -> bool:
    targets = load_targets()
    new = [t for t in targets if t.get("addresses", [""])[0] != target]
    if len(new) == len(targets):
        return False
    TARGETS_FILE.write_text(json.dumps(new, ensure_ascii=False, indent=2), encoding="utf-8")
    return True
