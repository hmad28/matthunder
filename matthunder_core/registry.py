"""Canonical scanner metadata registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class ScannerDefinition:
    key: str
    label: str
    kind: str
    description: str
    accepts_speed: bool = False
    accepts_list: bool = False
    estimated_seconds: int | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)


SCAN_DEFINITIONS: dict[str, ScannerDefinition] = {}


def _add(defn: ScannerDefinition) -> None:
    SCAN_DEFINITIONS[defn.key] = defn
    for alias in defn.aliases:
        SCAN_DEFINITIONS[alias] = defn


_add(ScannerDefinition("lts", "Light Scan", "go", "Subfinder, httpx, nuclei fast recon", True, aliases=("light",)))
_add(ScannerDefinition("dks", "Dark Scan", "go", "Subfinder, assetfinder, katana, nuclei", True, aliases=("dark",)))
_add(ScannerDefinition("dps", "Deep Scan", "go", "Full recon chain with takeover checks", True, aliases=("deep",)))
_add(ScannerDefinition("tov", "Subdomain Takeover", "go", "Nuclei takeover checks", False, True, aliases=("takeover",)))
_add(ScannerDefinition("sens", "Sensitive Data", "go", "Sensitive URL discovery", False, aliases=("sensitive",)))
_add(ScannerDefinition("blh", "Broken Link Hunter", "inline", "Social/profile link status checks"))
_add(ScannerDefinition("tpa", "3rd Party Assets", "inline", "Third-party resource links", aliases=("thirdparty", "bac")))
_add(ScannerDefinition("cred", "Credential URLs", "inline", "Credential/config URL finder"))
_add(ScannerDefinition("apirecon", "API Endpoint Recon", "inline", "API endpoint discovery", aliases=("params",)))
_add(ScannerDefinition("ssti", "SSTI Probe", "inline", "Server-side template injection probe"))
_add(ScannerDefinition("cors", "CORS Misconfiguration", "inline", "CORS origin reflection checks"))
_add(ScannerDefinition("xss", "XSS Scan", "inline", "Reflected/DOM XSS detection"))
_add(ScannerDefinition("sqli", "SQL Injection", "inline", "SQLi probes and sqlmap wrapper"))
_add(ScannerDefinition("lfi", "LFI / Path Traversal", "inline", "Local file inclusion checks"))
_add(ScannerDefinition("crlf", "CRLF Injection", "inline", "Header injection checks"))
_add(ScannerDefinition("openredirect", "Open Redirect", "inline", "Redirect parameter checks", aliases=("oredir",)))
_add(ScannerDefinition("ssrf", "SSRF Probe", "inline", "Bounded SSRF checks"))
_add(ScannerDefinition("hostheader", "Host Header Injection", "inline", "Host header poisoning checks", aliases=("host",)))
_add(ScannerDefinition("graphql", "GraphQL Introspection", "inline", "GraphQL security checks", aliases=("gql",)))
_add(ScannerDefinition("portscan", "Port Scan", "inline", "Open port detection", aliases=("ports",)))
_add(ScannerDefinition("waf", "WAF Detection", "inline", "WAF fingerprinting"))
_add(ScannerDefinition("jsanalysis", "JS Analysis", "inline", "JavaScript endpoint and secret discovery", aliases=("js",)))
_add(ScannerDefinition("fuzzer", "Path Fuzzer", "inline", "Directory/path fuzzing", aliases=("fuzz", "dirscan")))
_add(ScannerDefinition("pipeline", "Full Pipeline", "inline", "Six-phase scanner pipeline", True))
_add(ScannerDefinition("techfingerprint", "Tech Fingerprint", "inline", "Technology stack detection", aliases=("tech",)))
_add(ScannerDefinition("attackrank", "Attack Surface Rank", "inline", "Prioritize attack surface", aliases=("rank",)))
_add(ScannerDefinition("gfpatterns", "GF Patterns", "inline", "Pattern-based URL filtering", aliases=("gf",)))
_add(ScannerDefinition("gate", "7-Question Gate", "utility", "Finding validation helper", aliases=("validate",)))
_add(ScannerDefinition("acunetix", "Acunetix", "integration", "Acunetix API integration"))


def canonical_key(key: str) -> str:
    normalized = (key or "").strip().lower()
    definition = SCAN_DEFINITIONS.get(normalized)
    if not definition:
        raise KeyError(f"unknown scan mode: {key}")
    return definition.key


def list_scanners() -> list[ScannerDefinition]:
    seen = set()
    items = []
    for definition in SCAN_DEFINITIONS.values():
        if definition.key in seen:
            continue
        seen.add(definition.key)
        items.append(definition)
    return sorted(items, key=lambda item: (item.kind, item.key))
