"""Shared scan service called by CLI, Web, and Telegram surfaces."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from .registry import SCAN_DEFINITIONS, canonical_key
from .scope import ScopeError, validate_target


ProgressCallback = Callable[["ProgressEvent"], None]


@dataclass(frozen=True)
class ScanRequest:
    mode: str
    target: str | None = None
    speed: str = "standard"
    list_path: str | None = None
    auto_continue: bool = False
    auto_restart: bool = False
    full: bool = False
    scope_rules: list[str] | None = None
    scope_file: str | None = None


@dataclass(frozen=True)
class ProgressEvent:
    scan_id: str | None
    mode: str
    target: str | None
    stage: str
    progress_pct: int
    message: str
    status: str = "running"


@dataclass(frozen=True)
class ScanResult:
    ok: bool
    mode: str
    target: str | None
    scan_id: str | None = None
    message: str = ""
    raw: dict | None = None
    error: str | None = None


def run_scan(request: ScanRequest, callback: ProgressCallback | None = None) -> ScanResult:
    mode = canonical_key(request.mode)
    definition = SCAN_DEFINITIONS[mode]
    speed = _normalize_speed(request.speed)
    target = None
    if request.target:
        target = validate_target(request.target, request.scope_rules, request.scope_file)

    if definition.kind in {"go", "inline"} and mode != "tov" and not target:
        raise ScopeError(f"{mode} requires a target")

    if definition.kind == "go":
        return _run_go_mode(mode, target, speed, request, callback)
    if definition.kind == "inline":
        return _run_inline_mode(mode, target, speed, callback)
    return _run_utility_or_integration(mode, target, speed)


def _run_go_mode(
    mode: str,
    target: str | None,
    speed: str,
    request: ScanRequest,
    callback: ProgressCallback | None,
) -> ScanResult:
    import matthunder as core
    from scanners.common import create_scan, finish_scan, log, open_db, update_scan_progress

    core.CMD_LINE_SPEED = speed
    core.SCAN_SPEED = speed

    con = open_db()
    scan_id = create_scan(con, mode, target or request.list_path or "takeover", {"speed": speed, "list": request.list_path})

    def progress(stage: str, pct: int, message: str, status: str = "running") -> None:
        update_scan_progress(con, scan_id, pct, stage, status)
        log(con, scan_id, message)
        _emit(callback, scan_id, mode, target, stage, pct, message, status)

    try:
        progress("scope-validated", 5, f"Scope accepted for {target or request.list_path}")
        if mode == "lts":
            progress("light-scan", 15, "Starting light scan")
            core.light_scan_target(target, resume=request.auto_continue)
        elif mode in {"dks", "dps"}:
            scan_mode = "dark" if mode == "dks" else "deep"
            progress(f"{scan_mode}-scan", 15, f"Starting {scan_mode} scan")
            core.dark_deep_target(scan_mode, target, resume=request.auto_continue)
        elif mode == "tov":
            progress("takeover", 15, "Starting takeover scan")
            if request.list_path:
                if not os.path.isfile(request.list_path):
                    raise FileNotFoundError(request.list_path)
                core.takeover_mass_file(request.list_path, target)
            elif target:
                core.takeover_single(target)
            else:
                raise ScopeError("takeover requires target or list_path")
        elif mode == "sens":
            progress("sensitive-data", 15, "Starting sensitive data scan")
            core.find_sensitive_data(target)
        if request.full and target:
            progress("full-chain", 80, "Running full scanner chain")
            from deep_full import run_full_chain

            run_full_chain(target, subdomain_file=os.path.join("subdomain", f"{target}.txt"))
        finish_scan(con, scan_id, "completed")
        progress("done", 100, "Scan completed", "completed")
        return ScanResult(True, mode, target, scan_id, f"{mode} completed")
    except Exception as exc:
        finish_scan(con, scan_id, "failed", error_message=str(exc))
        progress("failed", 0, str(exc), "failed")
        return ScanResult(False, mode, target, scan_id, error=str(exc))
    finally:
        con.close()


def _run_inline_mode(
    mode: str,
    target: str | None,
    speed: str,
    callback: ProgressCallback | None,
) -> ScanResult:
    from scanners import SCANNER_REGISTRY
    from scanners.common import open_db, update_scan_progress

    runner = SCANNER_REGISTRY.get(mode)
    if not runner:
        return ScanResult(False, mode, target, error=f"scanner not registered: {mode}")
    _emit(callback, None, mode, target, "starting", 5, f"Starting {mode}")
    try:
        result = _invoke_inline_runner(mode, runner, target, speed)
        scan_id = result.get("scan_id") if isinstance(result, dict) else None
        if scan_id:
            con = open_db()
            try:
                update_scan_progress(con, scan_id, 100, "done", "completed")
            finally:
                con.close()
        _emit(callback, scan_id, mode, target, "done", 100, f"{mode} completed", "completed")
        return ScanResult(True, mode, target, scan_id, f"{mode} completed", result if isinstance(result, dict) else None)
    except Exception as exc:
        _emit(callback, None, mode, target, "failed", 0, str(exc), "failed")
        return ScanResult(False, mode, target, error=str(exc))


def _invoke_inline_runner(mode: str, runner: Callable, target: str, speed: str) -> dict:
    if mode in {"blh", "tpa", "cred"}:
        return runner(target, [])
    if mode == "pipeline":
        return runner(target, speed=speed)
    return runner(target)


def _run_utility_or_integration(mode: str, target: str | None, speed: str) -> ScanResult:
    if mode == "acunetix":
        from scanners.acunetix import run_subcommand

        action = target or "summary"
        result = run_subcommand(action)
        return ScanResult(bool(not isinstance(result, dict) or result.get("ok", True)), mode, target, raw=result if isinstance(result, dict) else None)
    return ScanResult(False, mode, target, error=f"{mode} must be run interactively")


def _normalize_speed(speed: str) -> str:
    aliases = {"1": "low", "2": "standard", "3": "fast"}
    value = aliases.get((speed or "").strip().lower(), (speed or "standard").strip().lower())
    return value if value in {"low", "standard", "fast"} else "standard"


def _emit(
    callback: ProgressCallback | None,
    scan_id: str | None,
    mode: str,
    target: str | None,
    stage: str,
    progress_pct: int,
    message: str,
    status: str = "running",
) -> None:
    if callback is None:
        return
    callback(ProgressEvent(scan_id, mode, target, stage, progress_pct, message, status))
