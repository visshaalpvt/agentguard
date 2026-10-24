import json
import pytest
from pathlib import Path
from agentguard.reports import build_report, save_reports
from agentguard.gate import evaluate_release_gate
from agentguard.pytest_runner import validate_python_project_path, run_pytest_suite

def test_report_builder_and_export(tmp_path):
    results = [
        {"test_id": "TEST-01", "name": "Health check", "status": "PASS", "expected": "200", "actual": "200", "evidence": "OK", "category": "API", "risk": "Low"},
        {"test_id": "TEST-02", "name": "Agent route", "status": "FAIL", "expected": "tool", "actual": "none", "evidence": "Error", "category": "Agent", "risk": "High"}
    ]
    defects = [
        {"id": 1, "test_id": "TEST-02", "title": "Agent route failure", "severity": "High", "status": "Open", "evidence": "Tool not selected"}
    ]
    gate = evaluate_release_gate(results, defects, coverage_percent=85.0)
    rep = build_report(results, defects, scan={"target": "http://127.0.0.1:5000/sut", "status_code": 200, "finding_count": 1}, coverage=85.0, gate=gate)

    assert rep["summary"]["total_tests"] == 2
    assert rep["summary"]["passed"] == 1
    assert rep["summary"]["failed"] == 1
    assert rep["release_gate"]["decision"] == "NO-GO"  # Open High defect blocks release

    jp, hp = save_reports(rep, tmp_path)
    assert Path(jp).exists()
    assert Path(hp).exists()

    data = json.loads(Path(jp).read_text(encoding="utf-8"))
    assert data["summary"]["total_tests"] == 2

    html_content = Path(hp).read_text(encoding="utf-8")
    assert "AgentGuard" in html_content
    assert "TEST-01" in html_content
    assert "RELEASE GATE:" in html_content

def test_pytest_runner_path_validation():
    # Valid directory
    this_dir = str(Path(__file__).parent.parent)
    is_valid, resolved, err = validate_python_project_path(this_dir)
    assert is_valid
    assert resolved.exists()
    assert err == ""

    # Non-existent directory
    is_valid, resolved, err = validate_python_project_path("C:\\non_existent_folder_abc_123")
    assert not is_valid
    assert "does not exist" in err

    # Empty path
    is_valid, resolved, err = validate_python_project_path("")
    assert not is_valid
