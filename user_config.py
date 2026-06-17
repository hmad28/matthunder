"""
user_config.py — runtime user configuration store.

Persists per-user secrets (Acunetix URL/key, AI provider/key/model) to a JSON
file outside of config.py so the tool stays portable. At bot startup the values
are exported as env vars so existing loaders (scanners.acunetix._load_config,
ai_parser.detect_provider) pick them up automatically.

File location: <project>/user_config.json
"""

import json
import os
from pathlib import Path
from typing import Optional


CONFIG_PATH = Path(__file__).resolve().parent / "user_config.json"

# Acunetix env mapping
ENV_ACX_URL = "ACUNETIX_URL"
ENV_ACX_KEY = "ACUNETIX_API_KEY"
ENV_ACX_VERIFY = "ACUNETIX_VERIFY_SSL"

# AI env mapping (provider -> env var name)
AI_ENV_KEY = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}
ENV_AI_PROVIDER = "MATTHUNDER_AI_PROVIDER"
ENV_AI_MODEL = "MATTHUNDER_AI_MODEL"

AI_PROVIDER_MODELS = {
    "openai": ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
    "anthropic": ["claude-3-5-haiku-latest", "claude-3-5-sonnet-latest", "claude-3-opus-latest"],
    "gemini": ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash-exp"],
    "openrouter": ["meta-llama/llama-3.1-8b-instruct", "openai/gpt-4o-mini", "anthropic/claude-3.5-sonnet"],
}


def _read() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write(data: dict) -> bool:
    """Atomic write to avoid partial files on crash."""
    try:
        tmp = CONFIG_PATH.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CONFIG_PATH)
        return True
    except Exception:
        return False


def get_acunetix() -> dict:
    """Return Acunetix config from user_config.json (empty if unset)."""
    d = _read().get("acunetix") or {}
    return {
        "url": (d.get("url") or "").rstrip("/"),
        "api_key": (d.get("api_key") or "").strip(),
        "verify_ssl": bool(d.get("verify_ssl", True)),
    }


def set_acunetix(url: str, api_key: str, verify_ssl: bool = True) -> bool:
    data = _read()
    data["acunetix"] = {
        "url": url.rstrip("/"),
        "api_key": api_key.strip(),
        "verify_ssl": bool(verify_ssl),
    }
    return _write(data)


def get_ai() -> dict:
    d = _read().get("ai") or {}
    return {
        "provider": d.get("provider") or "",
        "api_key": d.get("api_key") or "",
        "model": d.get("model") or "",
    }


def set_ai(provider: str, api_key: str, model: str = "") -> bool:
    if provider not in AI_ENV_KEY:
        return False
    data = _read()
    data["ai"] = {
        "provider": provider,
        "api_key": api_key.strip(),
        "model": (model or "").strip(),
    }
    return _write(data)


def clear_acunetix() -> bool:
    data = _read()
    data.pop("acunetix", None)
    return _write(data)


def clear_ai() -> bool:
    data = _read()
    data.pop("ai", None)
    return _write(data)


def apply_env() -> None:
    """Push stored config into os.environ so downstream loaders pick it up.

    Call once at bot startup. Idempotent.
    """
    acx = get_acunetix()
    if acx["url"]:
        os.environ[ENV_ACX_URL] = acx["url"]
    if acx["api_key"]:
        os.environ[ENV_ACX_KEY] = acx["api_key"]
    os.environ[ENV_ACX_VERIFY] = "true" if acx["verify_ssl"] else "false"

    ai = get_ai()
    if ai["provider"] and ai["provider"] in AI_ENV_KEY:
        os.environ[ENV_AI_PROVIDER] = ai["provider"]
        if ai["api_key"]:
            os.environ[AI_ENV_KEY[ai["provider"]]] = ai["api_key"]
        if ai["model"]:
            os.environ[ENV_AI_MODEL] = ai["model"]


def mask_key(key: str, head: int = 4, tail: int = 4) -> str:
    if not key:
        return "(empty)"
    if len(key) <= head + tail + 3:
        return "*" * len(key)
    return f"{key[:head]}{'*' * 6}{key[-tail:]}"


def status() -> dict:
    """Human-readable config status (for /setup display)."""
    acx = get_acunetix()
    ai = get_ai()
    return {
        "acunetix": {
            "configured": bool(acx["url"] and acx["api_key"]),
            "url": acx["url"],
            "key_masked": mask_key(acx["api_key"]),
            "verify_ssl": acx["verify_ssl"],
        },
        "ai": {
            "configured": bool(ai["provider"] and ai["api_key"]),
            "provider": ai["provider"] or "(unset)",
            "model": ai["model"] or "(default)",
            "key_masked": mask_key(ai["api_key"]),
        },
        "file": str(CONFIG_PATH),
    }
