from __future__ import annotations

import asyncio
import os
import tempfile
from contextlib import contextmanager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.hunting.engine import (
    AttackSurfaceRanker,
    FindingNormalizer,
    HuntingMode,
    LegacyResultLoader,
    ScanPlan,
    ScanPlanBuilder,
    ScannerAdapterRegistry,
)
from app.models import Finding, Scan, Target
from app.services.scan_service import ScanService


class NormalHuntingRunner:
    """Runs deterministic non-AI hunting through the backend scan lifecycle."""

    _SCANNERS_BY_SCAN_TYPE = {
        "light": ("waf", "tech", "jsanalysis", "cors", "graphql"),
        "dark": ("waf", "tech", "jsanalysis", "fuzzer", "xss", "openredirect", "cors", "graphql"),
        "deep": (
            "waf",
            "tech",
            "portscan",
            "jsanalysis",
            "fuzzer",
            "xss",
            "sqli",
            "lfi",
            "openredirect",
            "cors",
            "ssrf",
            "hostheader",
            "ssti",
            "crlf",
            "graphql",
        ),
        "pipeline": (
            "waf",
            "tech",
            "portscan",
            "jsanalysis",
            "fuzzer",
            "gf",
            "xss",
            "sqli",
            "lfi",
            "openredirect",
            "cors",
            "ssrf",
            "hostheader",
            "ssti",
            "crlf",
            "graphql",
            "blh",
            "tpa",
            "cred",
        ),
    }

    def __init__(
        self,
        plan_builder: ScanPlanBuilder | None = None,
        ranker: AttackSurfaceRanker | None = None,
        adapters: ScannerAdapterRegistry | None = None,
        normalizer: FindingNormalizer | None = None,
        legacy_loader: LegacyResultLoader | None = None,
    ):
        self.plan_builder = plan_builder or ScanPlanBuilder()
        self.ranker = ranker or AttackSurfaceRanker()
        self.adapters = adapters or ScannerAdapterRegistry()
        self.normalizer = normalizer or FindingNormalizer()
        self.legacy_loader = legacy_loader or LegacyResultLoader()

    async def run(self, scan: Scan, target: Target, db: AsyncSession) -> dict[str, Any]:
        scope = self._scope_for_target(target)
        plan = self.plan_builder.build(
            target=target.domain,
            mode=HuntingMode.NORMAL,
            speed=scan.speed,
            scope=scope,
        )

        scan.metadata_ = {
            **(scan.metadata_ or {}),
            "hunting_mode": HuntingMode.NORMAL.value,
            "plan": self._serialize_plan(plan),
            "current_phase": "scope-intake",
            "completed_phases": [],
        }
        await db.commit()

        await ScanService.add_log(scan.id, "info", f"Normal hunting plan created for {plan.root_host}", db)

        assets = self._seed_assets(plan)
        ranked_assets = self.ranker.rank(assets)
        selected_scanners = self._select_scanners(scan.scan_type, ranked_assets)

        await ScanService.add_log(
            scan.id,
            "info",
            f"Selected scanners: {', '.join(selected_scanners) if selected_scanners else 'none'}",
            db,
        )

        raw_results: list[dict[str, Any]] = []
        pipeline_urls = self._pipeline_urls(plan.root_host, ranked_assets)
        with self._scanner_input_env(plan.root_host, pipeline_urls):
            for scanner_name in selected_scanners:
                result = await self._run_scanner(scan, db, plan.root_host, scanner_name)
                raw_results.extend(self._extract_raw_findings(scanner_name, result))
                raw_results.extend(self.legacy_loader.load(result.get("scan_id"), scanner_name))

        findings = self.normalizer.normalize(raw_results)
        for item in findings:
            db.add(
                Finding(
                    scan_id=scan.id,
                    scanner=item["scanner"],
                    severity=item["severity"],
                    category=item["category"],
                    title=item["title"],
                    description=item["description"],
                    url=item["url"],
                    source_url=item.get("source_url"),
                    evidence=item["evidence"],
                    http_code=item.get("http_code"),
                    status=item["status"],
                    remediation=item.get("remediation"),
                    metadata_=item["metadata"],
                )
            )

        scan.metadata_ = {
            **(scan.metadata_ or {}),
            "current_phase": "dedupe-and-report",
            "completed_phases": [step.name for step in plan.steps],
            "ranked_assets": [asset.__dict__ for asset in ranked_assets[:50]],
            "selected_scanners": list(selected_scanners),
            "pipeline_urls": pipeline_urls[:100],
            "normalized_findings": len(findings),
        }
        await db.commit()
        await ScanService.add_log(scan.id, "success", f"Normalized findings saved: {len(findings)}", db)

        return {
            "target": plan.root_host,
            "selected_scanners": list(selected_scanners),
            "raw_results": len(raw_results),
            "findings": len(findings),
        }

    async def _run_scanner(self, scan: Scan, db: AsyncSession, root_host: str, scanner_name: str) -> dict[str, Any]:
        scan.metadata_ = {**(scan.metadata_ or {}), "current_phase": scanner_name}
        await db.commit()
        await ScanService.add_log(scan.id, "info", f"Running {scanner_name} on {root_host}", db)
        result = await asyncio.to_thread(self.adapters.run, scanner_name, root_host)
        status = result.get("status", "completed")
        findings_count = result.get("findings", 0)
        await ScanService.add_log(
            scan.id,
            "success" if status != "skipped" else "warn",
            f"{scanner_name} {status}; findings={findings_count}",
            db,
        )
        return result

    def _scope_for_target(self, target: Target) -> dict[str, Any]:
        scope = target.scope or {}
        includes = scope.get("include") or scope.get("includes") or [target.domain, f"*.{target.domain}"]
        excludes = scope.get("exclude") or scope.get("excludes") or []
        return {"include": includes, "exclude": excludes}

    def _seed_assets(self, plan: ScanPlan) -> list[str]:
        host = plan.root_host
        return [
            f"https://{host}/",
            f"https://{host}/login",
            f"https://{host}/admin",
            f"https://{host}/api/search?q=test",
            f"https://{host}/redirect?url=https://example.org",
            f"https://{host}/download?file=invoice.pdf",
            f"https://{host}/graphql",
        ]

    def _select_scanners(self, scan_type: str, ranked_assets: list[Any]) -> tuple[str, ...]:
        baseline = set(self._SCANNERS_BY_SCAN_TYPE.get(scan_type, (scan_type,)))
        recommended = {
            scanner
            for asset in ranked_assets[:25]
            for scanner in asset.recommended_scanners
        }
        if scan_type in self._SCANNERS_BY_SCAN_TYPE:
            return tuple(scanner for scanner in self._SCANNERS_BY_SCAN_TYPE[scan_type] if scanner in baseline | recommended)
        return tuple(baseline)

    def _pipeline_urls(self, root_host: str, ranked_assets: list[Any]) -> list[str]:
        ranked_urls = [
            asset.url
            for asset in sorted(ranked_assets, key=lambda item: (-item.score, item.url))
            if getattr(asset, "url", "").startswith("http")
        ]
        parameterized_urls = [url for url in ranked_urls if "?" in url and "=" in url]
        informational_urls = [url for url in ranked_urls if url not in parameterized_urls]
        fallbacks = [
            f"https://{root_host}/graphql",
            f"https://{root_host}/api/search?q=test",
            f"https://{root_host}/search?q=test",
            f"https://{root_host}/redirect?url=https://example.org",
            f"https://{root_host}/download?file=invoice.pdf",
            f"https://{root_host}/page?template=home",
            f"https://{root_host}/api/users?id=1",
        ]
        merged = list(dict.fromkeys(parameterized_urls + fallbacks + informational_urls))
        return merged[:2000]

    @contextmanager
    def _scanner_input_env(self, root_host: str, urls: list[str]):
        previous_urls = os.environ.get("MT_PIPELINE_URLS")
        previous_domain = os.environ.get("MT_PIPELINE_DOMAIN")
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as handle:
                temp_path = handle.name
                handle.write("\n".join(urls))
                handle.write("\n")
            os.environ["MT_PIPELINE_URLS"] = temp_path
            os.environ["MT_PIPELINE_DOMAIN"] = root_host
            yield
        finally:
            if previous_urls is None:
                os.environ.pop("MT_PIPELINE_URLS", None)
            else:
                os.environ["MT_PIPELINE_URLS"] = previous_urls
            if previous_domain is None:
                os.environ.pop("MT_PIPELINE_DOMAIN", None)
            else:
                os.environ["MT_PIPELINE_DOMAIN"] = previous_domain
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    def _extract_raw_findings(self, scanner_name: str, result: dict[str, Any]) -> list[dict[str, Any]]:
        findings = result.get("findings")
        if isinstance(findings, list):
            return [{**item, "scanner": item.get("scanner", scanner_name)} for item in findings if isinstance(item, dict)]
        if result.get("evidence") and (result.get("url") or result.get("target_url")):
            return [{**result, "scanner": scanner_name}]
        return []

    @staticmethod
    def _serialize_plan(plan: ScanPlan) -> dict[str, Any]:
        return {
            "target": plan.target,
            "root_host": plan.root_host,
            "mode": plan.mode.value,
            "speed": plan.speed,
            "scope": plan.scope,
            "steps": [
                {
                    "name": step.name,
                    "scanners": list(step.scanners),
                    "risk_level": step.risk_level,
                    "description": step.description,
                }
                for step in plan.steps
            ],
        }
