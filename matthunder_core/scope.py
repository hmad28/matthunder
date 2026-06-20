"""Single target/scope gatekeeper used by every matthunder interface."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from scoper import Scoper


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
BLOCKED_EXACT = {"localhost", "local", "0.0.0.0"}
BLOCKED_SUFFIXES = (".local", ".lan", ".internal", ".localhost")


class ScopeError(ValueError):
    """Raised when a target fails the shared authorization/scope gate."""


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    in_scope: bool
    reason: str = ""


def normalize_target(raw: str) -> str:
    target = (raw or "").strip().lower()
    if not target:
        raise ScopeError("target is required")
    if "://" in target:
        target = urlparse(target).netloc
    target = target.split("/")[0].split("?")[0].split("#")[0].split("@")[-1].rstrip(".")
    if ":" in target and not _is_ip_literal(target):
        target = target.split(":", 1)[0]
    if target.startswith("www."):
        target = target[4:]
    if not target:
        raise ScopeError("target is required")
    return target


def validate_target(raw: str, scope_rules: list[str] | None = None, scope_file: str | Path | None = None) -> str:
    target = normalize_target(raw)
    _reject_private_or_local(target)
    if not _is_ip_literal(target) and not DOMAIN_RE.match(target):
        raise ScopeError("target must be a valid public domain")

    rules = list(scope_rules or [])
    if scope_file:
        rules.extend(_read_scope_file(scope_file))
    if rules:
        scoper = Scoper(rules)
        if not scoper.in_scope(target):
            raise ScopeError(f"target out of configured scope: {target}")
    return target


def _read_scope_file(path: str | Path) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"scope file not found: {p}")
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()]


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def _reject_private_or_local(target: str) -> None:
    if target in BLOCKED_EXACT or target.endswith(BLOCKED_SUFFIXES):
        raise ScopeError("local/private targets are blocked")

    try:
        ip = ipaddress.ip_address(target.strip("[]"))
        if _is_blocked_ip(ip):
            raise ScopeError("local/private targets are blocked")
        return
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            raise ScopeError("target resolves to a local/private address")


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )
