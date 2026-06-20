from app.hunting.engine import (
    AttackSurfaceRanker,
    FindingNormalizer,
    HuntingMode,
    LegacyResultLoader,
    ScopePolicy,
    ScanPlanBuilder,
    TargetInput,
)


def test_scope_policy_allows_only_authorized_public_hosts():
    policy = ScopePolicy(
        includes=["example.com", "*.example.com"],
        excludes=["admin.example.com"],
    )

    assert policy.assert_allowed("https://api.example.com/search?q=test") == "api.example.com"
    assert policy.assert_allowed("example.com") == "example.com"

    for target in [
        "https://admin.example.com",
        "https://evil.com",
        "http://127.0.0.1:8000",
        "http://169.254.169.254/latest/meta-data",
        "http://10.1.2.3",
    ]:
        try:
            policy.assert_allowed(target)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{target} should be blocked")


def test_target_input_normalizes_domain_and_builds_default_scope():
    target = TargetInput.normalize("https://WWW.Example.COM/path?q=1", scope=None)

    assert target.domain == "example.com"
    assert target.scope == {"include": ["example.com", "*.example.com"], "exclude": []}


def test_target_input_rejects_internal_or_out_of_scope_values():
    for raw in ["http://127.0.0.1:8080", "http://10.0.0.5", "localhost"]:
        try:
            TargetInput.normalize(raw, scope=None)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{raw} should be blocked")

    try:
        TargetInput.normalize("api.example.com", scope={"include": ["example.org"], "exclude": []})
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-scope target should be blocked")


def test_scan_plan_builder_creates_deterministic_hunting_flow_without_ai_steps():
    plan = ScanPlanBuilder().build(
        target="https://example.com",
        mode=HuntingMode.NORMAL,
        speed="standard",
        scope={"include": ["example.com", "*.example.com"], "exclude": []},
    )

    step_names = [step.name for step in plan.steps]

    assert plan.mode == HuntingMode.NORMAL
    assert step_names[:5] == [
        "scope-intake",
        "asset-discovery",
        "live-host-probing",
        "service-discovery",
        "deep-entry-mapping",
    ]
    assert "ai-triage" not in step_names
    assert "safe-validation" in step_names
    assert all(step.risk_level in {"passive", "low", "standard"} for step in plan.steps)


def test_attack_surface_ranker_prioritizes_entry_points_and_maps_scanners():
    assets = [
        "https://example.com/",
        "https://example.com/login",
        "https://api.example.com/graphql",
        "https://example.com/redirect?url=https://example.org",
        "https://example.com/download?file=invoice.pdf",
        "https://example.com/search?q=abc",
    ]

    ranked = AttackSurfaceRanker().rank(assets)

    assert ranked[0].url == "https://api.example.com/graphql"
    scanner_map = {item.url: item.recommended_scanners for item in ranked}
    assert "graphql" in scanner_map["https://api.example.com/graphql"]
    assert "openredirect" in scanner_map["https://example.com/redirect?url=https://example.org"]
    assert "lfi" in scanner_map["https://example.com/download?file=invoice.pdf"]
    assert {"xss", "sqli"}.issubset(set(scanner_map["https://example.com/search?q=abc"]))


def test_finding_normalizer_requires_evidence_and_deduplicates_findings():
    raw_results = [
        {
            "scanner": "xss",
            "url": "https://example.com/search?q=abc",
            "param": "q",
            "payload": "<svg onload=alert(1)>",
            "evidence": "payload reflected in HTML attribute",
            "confidence": "high",
        },
        {
            "scanner": "xss",
            "url": "https://example.com/search?q=abc",
            "param": "q",
            "payload": "<svg onload=alert(1)>",
            "evidence": "payload reflected in HTML attribute",
            "confidence": "high",
        },
        {
            "scanner": "cors",
            "url": "https://api.example.com",
            "evidence": "",
        },
    ]

    findings = FindingNormalizer().normalize(raw_results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["scanner"] == "xss"
    assert finding["severity"] == "medium"
    assert finding["category"] == "xss"
    assert finding["metadata"]["confidence"] == "high"


def test_legacy_result_loader_converts_scanner_sqlite_rows_to_raw_findings(tmp_path):
    import sqlite3

    db_path = tmp_path / "legacy.db"
    con = sqlite3.connect(db_path)
    con.execute(
        "CREATE TABLE results (scan_id TEXT, category TEXT, target_url TEXT, "
        "source_url TEXT, status TEXT, http_code INTEGER, detail TEXT)"
    )
    con.execute(
        "INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "legacy-scan-1",
            "sqli_error",
            "https://example.com/search?q=test",
            "https://example.com/search",
            "vulnerable",
            200,
            "param=q payload=single_quote evidence=SQL syntax",
        ),
    )
    con.execute(
        "INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "other-scan",
            "xss_reflected",
            "https://example.com",
            None,
            "vulnerable",
            200,
            "ignored",
        ),
    )
    con.commit()
    con.close()

    rows = LegacyResultLoader(db_path).load("legacy-scan-1", scanner="sqli")

    assert rows == [
        {
            "scanner": "sqli",
            "category": "sqli_error",
            "url": "https://example.com/search?q=test",
            "source_url": "https://example.com/search",
            "status": 200,
            "evidence": "param=q payload=single_quote evidence=SQL syntax",
            "confidence": "medium",
            "param": "q",
            "payload": "single_quote",
        }
    ]
