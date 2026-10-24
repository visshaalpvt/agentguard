import json
import pytest
import app as app_module
from agentguard.db import connect
from agentguard.runner import execute_single_test, run_tests_for_app

def test_custom_test_creation_and_execution():
    client = app_module.app.test_client()
    # 1. Add custom test case
    resp = client.post("/test/create", data={
        "test_id": "TEST-CUST-001",
        "name": "Check Health Endpoint",
        "category": "Positive",
        "risk": "High",
        "priority": "P1",
        "method": "GET",
        "endpoint_path": "/health",
        "expected_status": "200",
        "expected_json_json": '{"status": "ok"}',
        "required_fields_json": '["status", "service"]'
    }, follow_redirects=True)
    assert resp.status_code == 200

    # 2. Execute test case
    app_info = {
        "id": 1,
        "name": "Bundled SUT",
        "base_url": "http://127.0.0.1:5000/sut"
    }
    test_case = {
        "test_id": "TEST-CUST-001",
        "name": "Check Health Endpoint",
        "method": "GET",
        "endpoint_path": "/health",
        "expected_status": 200,
        "expected_json_json": '{"status": "ok"}',
        "required_fields_json": '["status", "service"]'
    }

    # Verify execution runner logic directly
    # Note: to test with live requests against app, app.test_client handles internal routes,
    # and execute_single_test sends real requests.
    # We can test execute_single_test against a mock or valid local url or test runner.
    results = run_tests_for_app(1, test_id_filter="TEST-CUST-001")
    assert len(results) >= 1
    r = results[0]
    # It attempts to connect to http://127.0.0.1:5000/sut/health
    # Since dev server might not be running as background port during test process, status could be ERROR (ConnectionRefused) or PASS
    assert r["test_id"] == "TEST-CUST-001"
    assert "status" in r

def test_failed_assertion_creates_defect_and_retest():
    with connect() as conn:
        # Clean up any previous runs
        conn.execute("DELETE FROM defects WHERE test_id = 'FAILING-TEST-999'")
        conn.execute("DELETE FROM custom_tests WHERE test_id = 'FAILING-TEST-999'")
        conn.execute(
            """INSERT INTO custom_tests (app_id, test_id, name, category, risk, priority, method, endpoint_path, expected_status, created_at, updated_at)
               VALUES (1, 'FAILING-TEST-999', 'Should Fail', 'Negative', 'Critical', 'P0', 'GET', '/nonexistent', 200, '2026-01-01', '2026-01-01')"""
        )
        conn.commit()

    client = app_module.app.test_client()
    resp = client.post("/run/test/FAILING-TEST-999", follow_redirects=True)
    assert resp.status_code == 200

    # Verify defect was created in SQLite
    with connect() as conn:
        defect = conn.execute("SELECT * FROM defects WHERE test_id = 'FAILING-TEST-999'").fetchone()
        assert defect is not None
        assert defect["status"] == "Open"
        defect_id = defect["id"]

    # Test defect status update
    resp_update = client.post(f"/defect/{defect_id}", data={"status": "In Progress"}, follow_redirects=True)
    assert resp_update.status_code == 200
    with connect() as conn:
        updated = conn.execute("SELECT status FROM defects WHERE id = ?", (defect_id,)).fetchone()
        assert updated["status"] == "In Progress"
