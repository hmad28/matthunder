"""Async scan runner for the web UI backed by matthunder_core."""

from __future__ import annotations

import asyncio
import time
from typing import AsyncGenerator, Optional

from matthunder_core import ProgressEvent, ScanRequest
from matthunder_core import run_scan as core_run_scan


RING_BUF_SIZE = 200


class ScanRunner:
    """Tracks one active scan task for the Web UI."""

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._target: Optional[str] = None
        self._mode: str = "dps"
        self._started_at: Optional[float] = None
        self._ring: list[str] = []
        self._progress_pct = 0
        self._stage = "idle"
        self._status = "idle"
        self._scan_id: Optional[str] = None
        self._lock = asyncio.Lock()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def elapsed(self) -> int:
        return int(time.time() - self._started_at) if self._started_at else 0

    def status(self) -> dict:
        return {
            "running": self.running,
            "target": self._target,
            "mode": self._mode,
            "scan_id": self._scan_id,
            "elapsed": self.elapsed,
            "started_at": self._started_at,
            "progress_pct": self._progress_pct,
            "stage": self._stage,
            "status": self._status,
        }

    async def start(self, target: str, speed: str = "standard", mode: str = "dps") -> dict:
        async with self._lock:
            if self.running:
                return {"error": "A scan is already running", **self.status()}
            self._target = target
            self._mode = mode
            self._started_at = time.time()
            self._ring = []
            self._progress_pct = 0
            self._stage = "queued"
            self._status = "running"
            self._scan_id = None
            self._task = asyncio.create_task(self._run(mode, target, speed))
            return self.status()

    async def _run(self, mode: str, target: str, speed: str) -> None:
        def progress(event: ProgressEvent) -> None:
            self._scan_id = event.scan_id or self._scan_id
            self._progress_pct = event.progress_pct
            self._stage = event.stage
            self._status = event.status
            line = f"[{event.progress_pct:>3}%] {event.stage}: {event.message}"
            self._ring.append(line)
            if len(self._ring) > RING_BUF_SIZE:
                self._ring.pop(0)

        try:
            result = await asyncio.to_thread(
                core_run_scan,
                ScanRequest(mode=mode, target=target, speed=speed),
                progress,
            )
            self._scan_id = result.scan_id or self._scan_id
            self._status = "completed" if result.ok else "failed"
            self._stage = "done" if result.ok else "failed"
            self._progress_pct = 100 if result.ok else self._progress_pct
            self._ring.append(result.message if result.ok else f"failed: {result.error}")
        except Exception as exc:
            self._status = "failed"
            self._stage = "failed"
            self._ring.append(f"failed: {exc}")

    async def stop(self):
        async with self._lock:
            if not self.running:
                return {"error": "No scan running"}
            self._task.cancel()
            self._status = "cancelled"
            self._stage = "cancelled"
            self._ring.append("cancel requested; active external tools may finish their current step")
            return {"stopped": True, **self.status()}

    async def stream_log(self) -> AsyncGenerator[str, None]:
        index = 0
        while self.running or index < len(self._ring):
            while index < len(self._ring):
                yield self._ring[index]
                index += 1
            await asyncio.sleep(0.25)


_runner: Optional[ScanRunner] = None


def get_runner() -> ScanRunner:
    global _runner
    if _runner is None:
        _runner = ScanRunner()
    return _runner
