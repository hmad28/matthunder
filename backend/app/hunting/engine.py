from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs, urlparse


class HuntingMode(StrEnum):
    NORMAL = "normal"
    AI = "ai"


@dataclass(frozen=True)
class ScanStep:
    name: str
    scanners: tuple[str, ...] = ()
    risk_level: str = "passive"
    description: str = ""


@dataclass(frozen=True)
class ScanPlan:
    target: str
    root_host: str
    mode: HuntingMode
    speed: str
    steps: tuple[ScanStep, ...]
    scope: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RankedAsset:
    url: str
    score: int
    reasons: tuple[str, ...]
    recommended_scanners: tuple[str, ...]


@dataclass(frozen=True)
class TargetInput:
    domain: str
    scope: dict[str, Any]

    @classmethod
    def normalize(cls, raw_target: str, scope: dict[str, Any] | None = None) -> "TargetInput":
        domain = ScopePolicy._host_from_target(raw_target)
        if not domain or "." not in domain:
            raise ValueError("target must be a public domain or URL")
        normalized_scope = cls._normalize_scope(domain, scope)
        ScopePolicy.from_target_and_scope(domain, normalized_scope).assert_allowed(domain)
        return cls(domain=domain, scope=normalized_scope)

    @staticmethod
    def _normalize_scope(domain: str, scope: dict[str, Any] | None) -> dict[str, Any]:
        scope = scope or {}
        includes = scope.get("include") or scope.get("includes") or [domain, f"*.{domain}"]
        excludes = scope.get("exclude") or scope.get("excludes") or []
        return {"include": includes, "exclude": excludes}


class ScopePolicy:
    """Authorizes targets and blocks internal network pivots by default."""

    _BLOCKED_IP_RANGES = (
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    )

    def __init__(self, includes: Iterable[str], excludes: Iterable[str] | None = None):
        self.includes = tuple(self._normalize_pattern(item) for item in includes if item)
        self.excludes = tuple(self._normalize_pattern(item) for item in (excludes or ()) if item)
        if not self.includes:
            raise ValueError("scope include list is required")

    def assert_allowed(self, target: str) -> str:
        host = self._host_from_target(target)
        if not host:
            raise ValueError("target host is required")
        if self._is_blocked_ip(host):
            raise ValueError(f"blocked internal target: {host}")
        if not self._matches_any(host, self.includes):
            raise ValueError(f"target is out of scope: {host}")
        if self._matches_any(host, self.excludes):
            raise ValueError(f"target is excluded from scope: {host}")
        return host

    @classmethod
    def from_target_and_scope(cls, target: str, scope: dict[str, Any] | None) -> "ScopePolicy":
        host = cls._host_from_target(target)
        scope = scope or {}
        includes = scope.get("include") or scope.get("includes") or [host]
        excludes = scope.get("exclude") or scope.get("excludes") or []
        return cls(includes=includes, excludes=excludes)

    @staticmethod
    def _normalize_pattern(value: str) -> str:
        value = value.strip().lower()
        if "://" in value:
            value = urlparse(value).netloc
        value = value.split("/")[0].split(":")[0].rstrip(".")
        return value[4:] if value.startswith("www.") else value

    @staticmethod
    def _host_from_target(target: str) -> str:
        raw = (target or "").strip().lower()
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").rstrip(".")
        return host[4:] if host.startswith("www.") else host

    def _matches_any(self, host: str, patterns: Iterable[str]) -> bool:
        return any(self._matches(host, pattern) for pattern in patterns)

    @staticmethod
    def _matches(host: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            root = pattern[2:]
            return host.endswith(f".{root}") and host != root
        return host == pattern

    def _is_blocked_ip(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
                ips = {item[4][0] for item in infos}
            except socket.gaierror:
                return False
            return any(self._is_blocked_ip(ip) for ip in ips)
        return any(ip in network for network in self._BLOCKED_IP_RANGES)


class ScanPlanBuilder:
    """Builds the deterministic non-AI hunting workflow."""

    def build(
        self,
        target: str,
        mode: HuntingMode | str = HuntingMode.NORMAL,
        speed: str = "standard",
        scope: dict[str, Any] | None = None,
    ) -> ScanPlan:
        mode = HuntingMode(mode)
        if mode != HuntingMode.NORMAL:
            raise ValueError("AI hunting mode is intentionally separated from normal hunting")

        policy = ScopePolicy.from_target_and_scope(target, scope)
        root_host = policy.assert_allowed(target)
        normalized_target = f"https://{root_host}"
        steps = [
            ScanStep("scope-intake", risk_level="passive", description="Normalize include/exclude scope"),
            ScanStep("asset-discovery", ("subdomain", "takeover"), "passive", "Discover subdomains and candidates"),
            ScanStep("live-host-probing", ("httpx", "waf"), "low", "Identify live HTTP services"),
            ScanStep("service-discovery", ("portscan", "tech"), "standard", "Map ports and technology stack"),
            ScanStep("deep-entry-mapping", ("crawler", "jsanalysis", "apirecon", "fuzzer"), "standard", "Collect endpoints, JS routes, forms, APIs, and params"),
            ScanStep("attack-surface-ranking", ("rank", "gf"), "passive", "Prioritize high-value entry points"),
            ScanStep("probe-selection", risk_level="passive", description="Select scanners from observed signals"),
            ScanStep("safe-validation", ("xss", "sqli", "lfi", "openredirect", "cors", "ssrf", "hostheader", "ssti", "crlf", "graphql"), "standard", "Run bounded validation probes"),
            ScanStep("dedupe-and-report", risk_level="passive", description="Normalize, deduplicate, and persist evidence"),
        ]
        return ScanPlan(
            target=normalized_target,
            root_host=root_host,
            mode=mode,
            speed=speed,
            steps=tuple(steps),
            scope=scope or {"include": [root_host], "exclude": []},
        )


class AttackSurfaceRanker:
    """Scores entry points and maps them to relevant non-AI scanners."""

    _PARAM_SCANNERS = {
        "url": ("openredirect", "ssrf"),
        "redirect": ("openredirect",),
        "redirect_url": ("openredirect",),
        "redirect_uri": ("openredirect",),
        "next": ("openredirect",),
        "return": ("openredirect",),
        "file": ("lfi",),
        "path": ("lfi",),
        "page": ("lfi", "xss"),
        "template": ("lfi", "ssti"),
        "q": ("xss", "sqli"),
        "search": ("xss", "sqli"),
        "query": ("xss", "sqli"),
        "id": ("sqli",),
    }

    def rank(self, assets: Iterable[str]) -> list[RankedAsset]:
        ranked = [self._score(url) for url in dict.fromkeys(assets) if url]
        return sorted(ranked, key=lambda item: (-item.score, item.url))

    def _score(self, url: str) -> RankedAsset:
        parsed = urlparse(url)
        path = (parsed.path or "/").lower()
        params = set(parse_qs(parsed.query, keep_blank_values=True).keys())
        score = 0
        reasons: list[str] = []
        scanners: set[str] = set()

        def add(points: int, reason: str, *scanner_names: str) -> None:
            nonlocal score
            score += points
            reasons.append(reason)
            scanners.update(scanner_names)

        if "graphql" in path or path in {"/gql", "/query", "/api/query"}:
            add(80, "graphql endpoint", "graphql")
        if any(token in path for token in ("login", "sso", "oauth", "auth")):
            add(45, "auth entry point", "cors", "hostheader")
        if any(token in path for token in ("admin", "manage", "dashboard")):
            add(40, "admin surface", "hostheader", "fuzzer")
        if any(token in path for token in ("upload", "import", "avatar")):
            add(35, "upload surface", "lfi", "xss")
        if "/api/" in path or parsed.netloc.startswith("api."):
            add(30, "api surface", "cors", "ssrf")
        if params:
            add(20 + min(len(params) * 4, 20), "parameterized endpoint", "xss", "sqli")
        for param in params:
            for scanner in self._PARAM_SCANNERS.get(param.lower(), ()):
                add(18, f"parameter:{param}", scanner)
        if re.search(r"(debug|trace|error|swagger|openapi|docs)", path):
            add(25, "diagnostic or docs surface", "cred", "cors")

        if not scanners:
            scanners.add("tech")
        return RankedAsset(
            url=url,
            score=score,
            reasons=tuple(dict.fromkeys(reasons)),
            recommended_scanners=tuple(sorted(scanners)),
        )


class FindingNormalizer:
    _SEVERITY_BY_SCANNER = {
        "sqli": "high",
        "ssrf": "high",
        "lfi": "high",
        "ssti": "high",
        "graphql": "medium",
        "xss": "medium",
        "openredirect": "medium",
        "cors": "medium",
        "hostheader": "medium",
        "crlf": "medium",
        "cred": "high",
        "takeover": "high",
    }

    def normalize(self, raw_results: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in raw_results:
            evidence = str(raw.get("evidence") or raw.get("detail") or "").strip()
            url = str(raw.get("url") or raw.get("target_url") or "").strip()
            scanner = str(raw.get("scanner") or raw.get("category") or "unknown").lower()
            if not evidence or not url:
                continue
            category = scanner.split("_", 1)[0]
            dedupe_key = self._dedupe_key(category, url, raw.get("param"), evidence)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(
                {
                    "scanner": scanner,
                    "severity": raw.get("severity") or self._SEVERITY_BY_SCANNER.get(category, "info"),
                    "category": category,
                    "title": raw.get("title") or f"{category.upper()} signal on {urlparse(url).netloc}",
                    "description": raw.get("description") or evidence,
                    "url": url,
                    "source_url": raw.get("source_url"),
                    "evidence": evidence,
                    "http_code": raw.get("http_code") or raw.get("status"),
                    "status": "new",
                    "remediation": raw.get("remediation"),
                    "metadata": {
                        "confidence": raw.get("confidence", "medium"),
                        "param": raw.get("param"),
                        "payload": raw.get("payload"),
                        "dedupe_key": dedupe_key,
                    },
                }
            )
        return findings

    @staticmethod
    def _dedupe_key(category: str, url: str, param: Any, evidence: str) -> str:
        raw = f"{category}|{url.split('#', 1)[0]}|{param or ''}|{evidence[:200]}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


class LegacyResultLoader:
    """Loads evidence rows written by legacy scanners into backend raw findings."""

    def __init__(self, db_path: str | Path = "matthunder_scans.db"):
        self.db_path = Path(db_path)

    def load(self, scan_id: str | None, scanner: str) -> list[dict[str, Any]]:
        if not scan_id or not self.db_path.exists():
            return []
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        try:
            rows = con.execute(
                "SELECT category, target_url, source_url, status, http_code, detail "
                "FROM results WHERE scan_id = ? ORDER BY rowid ASC",
                (scan_id,),
            ).fetchall()
        except sqlite3.Error:
            return []
        finally:
            con.close()

        findings: list[dict[str, Any]] = []
        for row in rows:
            evidence = str(row["detail"] or "").strip()
            url = str(row["target_url"] or "").strip()
            if not evidence or not url:
                continue
            parsed = self._parse_detail(evidence)
            findings.append(
                {
                    "scanner": scanner,
                    "category": row["category"],
                    "url": url,
                    "source_url": row["source_url"],
                    "status": row["http_code"] or row["status"],
                    "evidence": evidence,
                    "confidence": "medium",
                    **parsed,
                }
            )
        return findings

    @staticmethod
    def _parse_detail(detail: str) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for key in ("param", "payload"):
            match = re.search(rf"\b{key}=([^\s]+)", detail)
            if match:
                parsed[key] = match.group(1)
        return parsed


class ToolRunner:
    """Executes external tools without shell interpolation."""

    def run(self, args: list[str], timeout: int = 120, cwd: str | None = None) -> dict[str, Any]:
        if not args or any(not isinstance(arg, str) or not arg for arg in args):
            raise ValueError("command args must be a non-empty list of strings")
        proc = subprocess.run(
            args,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        return {
            "args": args,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }


class ScannerAdapterRegistry:
    """Loads legacy scanner functions behind a stable backend interface."""

    _MODULE_BY_SCANNER = {
        "xss": "scanners.xss",
        "sqli": "scanners.sqli",
        "lfi": "scanners.lfi",
        "openredirect": "scanners.openredirect",
        "cors": "scanners.cors",
        "ssrf": "scanners.ssrf",
        "hostheader": "scanners.hostheader",
        "ssti": "scanners.ssti",
        "crlf": "scanners.crlf",
        "graphql": "scanners.graphql",
        "waf": "scanners.waf",
        "portscan": "scanners.portscan",
        "jsanalysis": "scanners.jsanalysis",
        "fuzzer": "scanners.fuzzer",
        "tech": "scanners.techfingerprint",
        "rank": "scanners.attackrank",
        "gf": "scanners.gfpatterns",
        "cred": "scanners.cred",
        "blh": "scanners.blh",
        "tpa": "scanners.thirdparty",
    }

    def get(self, scanner_name: str) -> Callable[..., dict[str, Any]] | None:
        module_name = self._MODULE_BY_SCANNER.get(scanner_name)
        if not module_name:
            return None
        project_root = self._find_project_root()
        if project_root and str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        try:
            module = import_module(module_name)
        except Exception:
            return None
        runner = getattr(module, "run", None)
        return runner if callable(runner) else None

    def run(self, scanner_name: str, target: str, **kwargs: Any) -> dict[str, Any]:
        runner = self.get(scanner_name)
        if not runner:
            return {
                "scanner": scanner_name,
                "target": target,
                "status": "skipped",
                "evidence": f"{scanner_name} adapter is not available",
            }
        try:
            result = runner(target, **kwargs)
        except TypeError:
            result = runner(target)
        if isinstance(result, dict):
            result.setdefault("scanner", scanner_name)
            return result
        return {"scanner": scanner_name, "target": target, "status": "completed", "result": result}

    @staticmethod
    def _find_project_root() -> Path | None:
        for parent in Path(__file__).resolve().parents:
            if (parent / "scanners").is_dir():
                return parent
        return None
