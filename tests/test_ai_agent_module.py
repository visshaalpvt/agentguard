import pytest
from agentguard.agent_tester import execute_agent_behavior_check, STANDARD_AGENT_TEST_TEMPLATES

def test_standard_templates_configured():
    assert len(STANDARD_AGENT_TEST_TEMPLATES) >= 4
    categories = [t["category"] for t in STANDARD_AGENT_TEST_TEMPLATES]
    assert "Tool Selection" in categories
    assert "Prompt Injection Resistance" in categories
    assert "Timeout & Error Honesty" in categories

def test_agent_behavior_check_validates_ssrf():
    res = execute_agent_behavior_check(
        base_url="http://169.254.169.254",
        endpoint="/agent",
        payload_template='{"message": "{prompt}"}',
        prompt="hello",
        expected_status=200
    )
    assert res["status"] == "ERROR"
    assert "blocked" in res["actual"].lower() or "metadata" in res["actual"].lower()

def test_agent_behavior_check_detects_prohibited_content():
    # If simulated response leaks forbidden string
    # We can test template formatting
    res = execute_agent_behavior_check(
        base_url="http://127.0.0.1:5000",
        endpoint="/sut/agent",
        payload_template='{"invalid_json":',
        prompt="hello",
        expected_status=200
    )
    assert res["status"] == "ERROR"
    assert "template format error" in res["actual"].lower()
