from agentguard.gate import evaluate_release_gate

def test_gate_no_go_when_coverage_missing():
    gate = evaluate_release_gate([], [], None)
    assert gate["decision"] == "NO-GO"
    assert any("coverage not measured" in x for x in gate["blockers"])

def test_gate_go_when_all_criteria_pass():
    gate = evaluate_release_gate([{"status":"PASS"}], [], 85)
    assert gate["decision"] == "GO"
