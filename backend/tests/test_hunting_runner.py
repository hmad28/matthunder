from app.hunting.engine import RankedAsset
from app.hunting.runner import NormalHuntingRunner


def test_runner_pipeline_urls_prioritize_parameterized_entry_points():
    ranked_assets = [
        RankedAsset(
            url="https://example.com/",
            score=0,
            reasons=(),
            recommended_scanners=("tech",),
        ),
        RankedAsset(
            url="https://example.com/search?q=test",
            score=44,
            reasons=("parameterized endpoint",),
            recommended_scanners=("xss", "sqli"),
        ),
        RankedAsset(
            url="https://example.com/redirect?url=https://example.org",
            score=62,
            reasons=("parameter:url",),
            recommended_scanners=("openredirect", "ssrf"),
        ),
    ]

    urls = NormalHuntingRunner()._pipeline_urls("example.com", ranked_assets)

    assert urls[:3] == [
        "https://example.com/redirect?url=https://example.org",
        "https://example.com/search?q=test",
        "https://example.com/graphql",
    ]
    assert "https://example.com/download?file=invoice.pdf" in urls
    assert all(url.startswith("http") for url in urls)
