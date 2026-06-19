"""
web/api/targets.py — Target management endpoints.
"""

import re
from urllib.parse import urlparse

from fastapi import APIRouter
from ..core.scanner import load_targets, save_target, remove_target

router = APIRouter(prefix="/api/targets", tags=["targets"])

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


def _normalize(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.split("/")[0].split("?")[0].split("#")[0].strip().lower().rstrip(".")
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


@router.get("/")
async def list_targets():
    """Return the target registry."""
    return {"targets": load_targets()}


@router.post("/")
async def add_target(body: dict):
    """Add a target domain.

    Body: {"target": "example.com"}
    """
    target = _normalize(body.get("target", ""))
    if not target:
        return {"error": "Invalid target"}
    if not DOMAIN_RE.match(target):
        return {"error": f"Invalid domain format: {target}"}

    if save_target(target):
        return {"ok": True, "target": target}
    return {"error": f"Target already exists: {target}"}


@router.delete("/{target}")
async def delete_target(target: str):
    """Remove a target from the registry."""
    target = _normalize(target)
    if remove_target(target):
        return {"ok": True, "target": target}
    return {"error": f"Target not found: {target}"}
