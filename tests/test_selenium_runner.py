"""Automated tests for AgentGuard's Selenium Browser Testing Module and API."""
import pytest
from app import app
from agentguard.selenium_runner import run_browser_test


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_selenium_url_validation_empty():
    result = run_browser_test("")
    assert result["status"] == "FAIL"
    assert "cannot be empty" in result["error"]
    assert any(t["id"] == "BG-004" and t["status"] == "FAIL" for t in result["tests"])


def test_selenium_url_validation_invalid_scheme():
    result = run_browser_test("ftp://example.com")
    assert result["status"] == "FAIL"
    assert "Scheme 'ftp' is not allowed" in result["error"]


def test_selenium_ssrf_blocking_metadata():
    result = run_browser_test("http://169.254.169.254/latest/meta-data")
    assert result["status"] == "FAIL"
    assert "cloud metadata" in result["error"].lower()


def test_selenium_local_sut_execution():
    """Runs real headless browser test against local SUT endpoint."""
    result = run_browser_test("http://127.0.0.1:5000/sut/health")
    assert result["status"] == "PASS"
    assert result["url"] == "http://127.0.0.1:5000/sut/health"
    assert result["duration_ms"] > 0
    test_ids = [t["id"] for t in result["tests"]]
    assert "BG-001" in test_ids  # Driver initialized
    assert "BG-002" in test_ids  # Page loaded
    assert "BG-003" in test_ids  # Title retrieved
    assert "BG-004" in test_ids  # URL validated
    assert "BG-006" in test_ids  # Cleaned up


def test_selenium_title_assertion_pass_and_fail():
    """Tests expected title assertion matching."""
    # SUT health returns JSON so title is empty string or document name
    pass_res = run_browser_test("http://127.0.0.1:5000/sut/health")
    assert pass_res["status"] == "PASS"

    # Testing non-matching expected title
    fail_res = run_browser_test("http://127.0.0.1:5000/sut/health", expected_title="Impossible Nonexistent Page Title 123456")
    assert fail_res["status"] == "FAIL"
    title_test = next(t for t in fail_res["tests"] if t["id"] == "BG-003")
    assert title_test["status"] == "FAIL"


def test_api_browser_test_missing_url(client):
    resp = client.post("/api/browser-test", json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "FAIL"
    assert "URL parameter is required" in data["error"]


def test_api_browser_test_invalid_url(client):
    resp = client.post("/api/browser-test", json={"url": "http://169.254.169.254"})
    assert resp.status_code == 422
    data = resp.get_json()
    assert data["status"] == "FAIL"
    assert "cloud metadata" in data["error"].lower()


def test_api_browser_test_success(client):
    resp = client.post("/api/browser-test", json={"url": "http://127.0.0.1:5000/sut/health"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "PASS"
    assert data["page_title"] is not None
    assert len(data["tests"]) >= 4
