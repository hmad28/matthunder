"""
web/api/scans.py — Scan management endpoints + WebSocket log streaming.
"""

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..core.runner import get_runner
from ..core.scanner import run_scanner, run_pipeline, SCANNER_KEYS

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("/status")
async def scan_status():
    """Return current scan status."""
    r = get_runner()
    return r.status()


@router.post("/start")
async def scan_start(body: dict):
    """Start a deep scan.

    Body: {"target": "example.com", "speed": "standard"}
    """
    target = (body.get("target") or "").strip().lower()
    speed = (body.get("speed") or "standard").strip().lower()
    if not target:
        return {"error": "Target is required"}
    if speed not in ("low", "standard", "fast"):
        speed = "standard"

    r = get_runner()
    if r.running:
        return {"error": "A scan is already running", **r.status()}

    return await r.start(target, speed)


@router.post("/stop")
async def scan_stop():
    """Stop the currently running scan."""
    r = get_runner()
    return await r.stop()


@router.get("/scanner-list")
async def scanner_list():
    """List all available inline scanners."""
    items = [{"key": k, "label": v} for k, v in SCANNER_KEYS.items()]
    return {"scanners": items}


@router.post("/scanner-run")
async def scanner_run(body: dict):
    """Run a single inline scanner.

    Body: {"scanner": "blh", "domain": "example.com"}
    """
    scanner = body.get("scanner", "")
    domain = body.get("domain", "").strip().lower()
    if not scanner or not domain:
        return {"error": "scanner and domain are required"}
    result = await run_scanner(scanner, domain)
    return result


@router.post("/pipeline-run")
async def pipeline_run(body: dict):
    """Run the full pipeline.

    Body: {"domain": "example.com"}
    """
    domain = body.get("domain", "").strip().lower()
    if not domain:
        return {"error": "domain is required"}
    result = await run_pipeline(domain)
    return result


# ── WebSocket: live log streaming ───────────────────────────────


@router.websocket("/ws/log")
async def websocket_log(websocket: WebSocket):
    """Stream scan log lines to the client in real time.

    Each message is a single log line (minus ANSI codes). The client
    should reconnect after disconnect — the server will replay the
    last N lines from the ring buffer.
    """
    await websocket.accept()
    r = get_runner()

    try:
        async for line in r.stream_log():
            try:
                await websocket.send_text(line)
            except WebSocketDisconnect:
                return
            except Exception:
                return
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@router.websocket("/ws/scanner")
async def websocket_scanner(websocket: WebSocket):
    """Run an inline scanner or pipeline via WebSocket.

    Client sends JSON::
        {"action": "scan", "scanner": "blh", "domain": "example.com"}
        {"action": "pipeline", "domain": "example.com"}
    """
    await websocket.accept()
    try:
        msg = await websocket.receive_text()
        data = json.loads(msg)
        action = data.get("action", "")
        domain = data.get("domain", "").strip().lower()

        if action == "scan":
            scanner = data.get("scanner", "")
            await run_scanner(scanner, domain, websocket)
        elif action == "pipeline":
            await run_pipeline(domain, websocket)
        else:
            await websocket.send_text(json.dumps({"error": f"Unknown action: {action}"}))
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"error": str(e)}))
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
