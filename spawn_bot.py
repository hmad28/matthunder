"""spawn_bot.py — fully detached launcher for the matthunder bot.

Run this once and the bot will keep running across reboots/shell exits.
Detects existing instances and refuses to start a second wrapper.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUN_BOT = ROOT / "run_bot.bat"
LOCK = Path(os.environ.get("TEMP", "/tmp")) / "matthunder_spawn.lock"


def _acquire_lock() -> bool:
    """Best-effort single-instance guard for spawner (not the bot itself)."""
    try:
        if LOCK.exists():
            old_pid = LOCK.read_text(encoding="utf-8", errors="ignore").strip()
            if old_pid.isdigit():
                rc = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {old_pid}", "/NH"],
                    capture_output=True, text=True, timeout=5,
                )
                if str(old_pid) in rc.stdout:
                    print(f"[spawn_bot] Another spawner active (PID {old_pid}). Exiting.")
                    return False
        LOCK.write_text(str(os.getpid()), encoding="utf-8")
        return True
    except Exception as e:
        print(f"[spawn_bot] lock check failed: {e}", file=sys.stderr)
        return True  # proceed anyway


def main() -> int:
    if not _acquire_lock():
        return 0
    if not RUN_BOT.exists():
        print(f"[spawn_bot] ERROR: {RUN_BOT} not found.", file=sys.stderr)
        return 1

    # Launch run_bot.bat in a fully detached process. DETACHED_PROCESS |
    # CREATE_NEW_PROCESS_GROUP detaches the child from our console and
    # prevents it from being killed when we exit.
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP

    try:
        # Don't redirect stdout/stderr — the child batch file manages its own
        # log files via >>. Redirecting here would mean our parent file handle
        # is the one appended to, and closing it (on our exit) breaks the
        # child's writes with "process cannot access the file".
        subprocess.Popen(
            ["cmd.exe", "/c", str(RUN_BOT)],
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
            close_fds=True,
        )
    except Exception as e:
        print(f"[spawn_bot] failed to launch run_bot.bat: {e}", file=sys.stderr)
        return 1

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[spawn_bot] {ts} launched run_bot.bat (detached).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
