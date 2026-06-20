"""
web/api/config.py — Configuration management endpoints.
"""

import json
from pathlib import Path

from fastapi import APIRouter

ROOT = Path(__file__).resolve().parent.parent.parent

router = APIRouter(prefix="/api/config", tags=["config"])

# Keys that are safe to display (mask secrets)
MASKED_KEYS = {"BOT_TOKEN", "ACUNETIX_API_KEY", "OPENAI_API_KEY",
               "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY"}


def _read_config() -> dict:
    cfg = {}
    cfg_path = ROOT / "config.py"
    if cfg_path.exists():
        try:
            text = cfg_path.read_text("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    cfg[k] = v
        except Exception:
            pass
    return cfg


@router.get("/")
async def get_config():
    """Return the current config (values masked for secrets)."""
    cfg = _read_config()
    safe = {}
    for k, v in cfg.items():
        if k in MASKED_KEYS and v:
            v = v[:8] + "****" if len(v) > 12 else "****"
        safe[k] = v
    return {"config": safe}


@router.get("/output-dirs")
async def output_dirs():
    """Return scan output directory listings."""
    import os
    dirs_info = {}
    for name in ("subdomain", "active", "crawled", "nuclei",
                  "take_over", "sensitive_data", "reports", "results"):
        p = ROOT / name
        if p.exists():
            files = [f.name for f in sorted(p.iterdir()) if f.is_file()][:50]
            dirs_info[name] = {"count": len(files), "files": files}
        else:
            dirs_info[name] = {"count": 0, "files": []}
    return {"dirs": dirs_info}
