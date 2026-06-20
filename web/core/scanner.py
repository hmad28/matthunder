"""Web bridge to the shared matthunder core scanner service."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from matthunder_core import ProgressEvent, ScanRequest, list_scanners
from matthunder_core import run_scan as core_run_scan


SCANNER_KEYS = {
    item.key: item.label
    for item in list_scanners()
    if item.kind in {"inline", "go"}
}

ROOT = Path(__file__).resolve().parent.parent.parent
TARGETS_FILE = ROOT / "targets.json"


async def run_scanner(scanner_key: str, domain: str, websocket=None) -> dict:
    """Run a scanner through the shared service layer."""
    if scanner_key not in SCANNER_KEYS:
        return {"error": f"Unknown scanner: {scanner_key}", "findings": 0}

    def progress(event: ProgressEvent) -> None:
        _send(websocket, json.dumps({
            "type": "progress",
            "scan_id": event.scan_id,
            "mode": event.mode,
            "target": event.target,
            "stage": event.stage,
            "progress_pct": event.progress_pct,
            "status": event.status,
            "message": event.message,
        }))

    result = await asyncio.to_thread(
        core_run_scan,
        ScanRequest(mode=scanner_key, target=domain),
        progress,
    )
    if not result.ok:
        return {"ok": False, "error": result.error, "scan_id": result.scan_id}
    payload = result.raw or {}
    payload.update({"ok": True, "scan_id": result.scan_id, "mode": result.mode})
    return payload


PIPELINE_STEPS = [
    ("passive", "Passive Recon"),
    ("active", "Active Recon"),
    ("discovery", "Content Discovery"),
    ("nuclei", "Automated Scanning"),
    ("vulnscan", "Vulnerability Scan"),
    ("intel", "Intel & Discovery"),
]


async def run_pipeline(domain: str, websocket=None) -> dict:
    """Run the canonical pipeline scanner."""
    return await run_scanner("pipeline", domain, websocket)


def _send(ws, msg: str):
    if ws is None:
        return
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(ws.send_text(msg))
    except Exception:
        pass


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
        return False
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
