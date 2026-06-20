import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def test_crawl_domain_returns_final_url_and_html(monkeypatch):
    from scanners import common

    class FakeResponse:
        status_code = 200
        headers = {"content-type": "text/html"}
        text = "<html><body>ok</body></html>"

        def __init__(self, url):
            self.url = url

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, **kwargs):
            return FakeResponse(url)

    monkeypatch.setattr(common.httpx, "Client", FakeClient)
    monkeypatch.setattr(common.rate_limiter, "wait", lambda host: None)
    monkeypatch.setattr(common.rate_limiter, "record_success", lambda host: None)
    monkeypatch.setattr(common.rate_limiter, "record_failure", lambda host: None)

    pages = common.crawl_domain("example.com", max_pages=1)

    assert pages == [("https://example.com/", "<html><body>ok</body></html>")]
