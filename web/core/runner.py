"""
web/core/runner.py — Async subprocess scan runner with WebSocket log streaming.

Manages the full lifecycle of matthunder deep/dark/light scans:

    start()       → spawn python matthunder.py -dps -t TARGET -s SPEED
    stream_log()  → async generator yielding stdout lines
    stop()        → taskkill /F /T /PID
    status()      → {running, pid, target, step, elapsed}

Design notes
────────────
* Each scan runs in a DETACHED asyncio subprocess so the web server can restart
  without killing an in-flight scan.
* Log lines are emitted as Server-Sent Events *and* buffered to a ring buffer
  so late-connected clients still see the last N lines.
* Single-scan-gated: the web UI only allows one scan at a time (same as the
  Telegram bot). This can be lifted later if needed.
"""

import asyncio
import json
import os
import subprocess
import time
from pathlib import Path
from typing import AsyncGenerator, Optional

ROOT = Path(__file__).resolve().parent.parent.parent
MATTHUNDER = ROOT / "matthunder.py"
PYTHON_BIN = os.getenv("MATTHUNDER_PYTHON", "python")

LOG_DIR = ROOT / "web" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

RING_BUF_SIZE = 200  # lines held in memory for reconnecting clients

# Regex to strip ANSI colour codes (from telegram_deep_bot.py)
ANSI_RE = __import__("re").compile(r"\x1b\[[0-9;]*m")


class ScanRunner:
    """Manages one active deep-scan subprocess."""

    def __init__(self):
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._target: Optional[str] = None
        self._started_at: Optional[float] = None
        self._log_path: Optional[Path] = None
        self._ring: list[str] = []
        self._lock = asyncio.Lock()

    # ── properties ────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @property
    def target(self) -> Optional[str]:
        return self._target

    @property
    def pid(self) -> Optional[int]:
        return self._proc.pid if self._proc else None

    @property
    def elapsed(self) -> int:
        if self._started_at:
            return int(time.time() - self._started_at)
        return 0

    def status(self) -> dict:
        return {
            "running": self.running,
            "target": self._target,
            "pid": self.pid,
            "elapsed": self.elapsed,
            "started_at": self._started_at,
            "log_path": str(self._log_path) if self._log_path else None,
        }

    # ── lifecycle ─────────────────────────────────────────────────

    async def start(self, target: str, speed: str = "standard") -> dict:
        """Launch matthunder deep scan as an async subprocess.

        The caller is responsible for checking ``running`` first.
        Returns immediately with the initial status dict.
        """
        async with self._lock:
            if self.running:
                return {"error": "A scan is already running", **self.status()}

            cmd = [PYTHON_BIN, str(MATTHUNDER), "-dps", "-t", target, "-s", speed, "-ar"]

            # Write log to a file so we can replay it for reconnecting clients
            ts = time.strftime("%Y%m%d_%H%M%S")
            log_name = f"deep_{target}_{ts}.log"
            self._log_path = LOG_DIR / log_name
            log_file = open(str(self._log_path), "w", encoding="utf-8", errors="ignore")

            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"

            try:
                self._proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=str(ROOT),
                    stdout=log_file,
                    stderr=asyncio.subprocess.STDOUT,
                    env=env,
                )
            except Exception as e:
                log_file.close()
                self._proc = None
                return {"error": str(e), **self.status()}

            self._target = target
            self._started_at = time.time()
            self._ring = []
            log_file.close()

            # Background watcher clears state on exit
            asyncio.create_task(self._watch())

            return self.status()

    async def _watch(self):
        """Wait for the process to exit, then clean up."""
        proc = self._proc
        if proc is None:
            return
        try:
            await proc.wait()
        finally:
            async with self._lock:
                self._proc = None
                self._target = None
                self._started_at = None

    async def stop(self):
        """Kill the scan process tree."""
        async with self._lock:
            if not self.running:
                return {"error": "No scan running"}
            pid = self._proc.pid
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True, timeout=10,
                )
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
            self._proc = None
            self._target = None
            self._started_at = None
            return {"stopped": True, "pid": pid}

    # ── log streaming ─────────────────────────────────────────────

    async def stream_log(self) -> AsyncGenerator[str, None]:
        """Yield log lines as they're written to the log file.

        Uses ``tail -f``-style polling so it works on any platform.
        Newlines are stripped; ANSI codes are removed.
        """
        log_path = self._log_path
        if not log_path or not log_path.exists():
            return

        # Replay the ring buffer first so the client gets recent history
        for line in self._ring:
            yield line

        # Then tail the file
        size = log_path.stat().st_size
        while self.running or size < log_path.stat().st_size:
            try:
                with open(str(log_path), "r", encoding="utf-8", errors="replace") as f:
                    f.seek(size)
                    for raw in f:
                        line = ANSI_RE.sub("", raw).rstrip()
                        if line:
                            self._ring.append(line)
                            if len(self._ring) > RING_BUF_SIZE:
                                self._ring.pop(0)
                            yield line
                    size = f.tell()
            except (OSError, IOError):
                pass
            await asyncio.sleep(0.25)

        # Drain remaining lines after process exits
        try:
            with open(str(log_path), "r", encoding="utf-8", errors="replace") as f:
                f.seek(size)
                for raw in f:
                    line = ANSI_RE.sub("", raw).rstrip()
                    if line:
                        self._ring.append(line)
                        if len(self._ring) > RING_BUF_SIZE:
                            self._ring.pop(0)
                        yield line
        except (OSError, IOError):
            pass


# ── singleton ────────────────────────────────────────────────────

_runner: Optional[ScanRunner] = None


def get_runner() -> ScanRunner:
    global _runner
    if _runner is None:
        _runner = ScanRunner()
    return _runner
