from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash, session
from datetime import datetime, timezone
from pathlib import Path
import json, os, subprocess, sys

from agentguard.catalog import TEST_CASES, get_tests_for_app
from agentguard.engine import execute_functional_tests
from agentguard.sut import sut
from agentguard.db import connect, now_iso
from agentguard.scanner import scan_http_target
from agentguard.gate import evaluate_release_gate
from agentguard.reports import build_report, save_reports
from agentguard.security import validate_target_url
from agentguard.runner import run_tests_for_app, execute_single_test
from agentguard.agent_tester import execute_agent_behavior_check, STANDARD_AGENT_TEST_TEMPLATES, AI_AGENT_CATEGORIES
from agentguard.pytest_runner import run_pytest_suite
from agentguard.selenium_runner import run_browser_test

ROOT = Path(__file__).resolve().parent
app = Flask(__name__)
app.secret_key = "agentguard-local-qa-secret-key-2026"
app.config.update(DB_PATH=str(ROOT / "instance" / "agentguard.sqlite3"), INJECT_TIMEOUT_BUG=False)
app.register_blueprint(sut, url_prefix="/sut")


def rows(sql, params=()):
    with connect() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def get_active_app(app_id: int = None) -> dict:
    with connect() as c:
        if app_id:
            found = c.execute("SELECT * FROM applications WHERE id = ?", (app_id,)).fetchone()
            if found:
                return dict(found)
        # Check session
        sess_id = session.get("active_app_id")
        if sess_id:
            found = c.execute("SELECT * FROM applications WHERE id = ?", (sess_id,)).fetchone()
            if found:
                return dict(found)
        # Default to first app
        first = c.execute("SELECT * FROM applications ORDER BY id ASC LIMIT 1").fetchone()
        if first:
            return dict(first)
        return {
            "id": 1,
            "name": "AgentGuard Bundled Demo SUT",
            "description": "Deterministic local AI agent service",
            "base_url": "http://127.0.0.1:5000/sut",
            "app_type": "AI agent API",
            "auth_confirmed": 1,
            "project_path": ""
        }


def get_latest_results(app_id: int):
    found = rows("SELECT results_json FROM runs WHERE app_id = ? ORDER BY id DESC LIMIT 1", (app_id,))
    return json.loads(found[0]["results_json"]) if found else []


def get_current_scan(app_id: int):
    found = rows("SELECT findings_json FROM scans WHERE app_id = ? ORDER BY id DESC LIMIT 1", (app_id,))
    if found:
        return json.loads(found[0]["findings_json"])
    # Fallback to any scan
    found_any = rows("SELECT findings_json FROM scans ORDER BY id DESC LIMIT 1")
    return json.loads(found_any[0]["findings_json"]) if found_any else None


def get_current_coverage(app_id: int, project_path: str = ""):
    path = ROOT / "instance" / "coverage.json"
    if path.exists():
        try:
            return round(json.loads(path.read_text(encoding="utf-8")).get("totals", {}).get("percent_covered", 0), 2)
        except Exception:
            pass
    return None


def get_defects(app_id: int):
    return rows("SELECT * FROM defects WHERE app_id = ? ORDER BY id DESC", (app_id,))


# -------------------------------------------------------------
# Web UI Routes
# -------------------------------------------------------------

@app.get("/")
def dashboard():
    with connect():
        pass  # Ensures DB and default seeds are ready

    req_app_id = request.args.get("app_id", type=int)
    active_app = get_active_app(req_app_id)
    session["active_app_id"] = active_app["id"]

    all_apps = rows("SELECT * FROM applications ORDER BY id ASC")
    app_tests = get_tests_for_app(active_app["id"])
    results = get_latest_results(active_app["id"])
    app_defects = get_defects(active_app["id"])
    cov = get_current_coverage(active_app["id"], active_app.get("project_path", ""))
    scan_data = get_current_scan(active_app["id"])

    # Release gate: only require coverage if app is a Python project or coverage has been run
    require_cov = (active_app.get("app_type") == "Python project") or (cov is not None)
    gate = evaluate_release_gate(results, app_defects, cov, minimum_coverage=70, require_coverage=require_cov)
    app_runs = rows("SELECT * FROM runs WHERE app_id = ? ORDER BY id DESC LIMIT 10", (active_app["id"],))

    return render_template(
        "index.html",
        apps=all_apps,
        active_app=active_app,
        cases=app_tests,
        results=results,
        defects=app_defects,
        runs=app_runs,
        coverage=cov,
        gate=gate,
        scan=scan_data,
        bug=app.config["INJECT_TIMEOUT_BUG"],
        agent_templates=STANDARD_AGENT_TEST_TEMPLATES,
        agent_categories=AI_AGENT_CATEGORIES
    )


# --- Application Management ---

@app.post("/app/select")
def select_app():
    app_id = request.form.get("app_id", type=int)
    if app_id:
        session["active_app_id"] = app_id
        flash(f"Switched active application context.", "success")
    return redirect(url_for("dashboard", app_id=app_id))


@app.post("/app/create")
def create_app():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    base_url = request.form.get("base_url", "").strip()
    app_type = request.form.get("app_type", "REST API")
    auth_confirmed = 1 if request.form.get("auth_confirmed") else 0
    project_path = request.form.get("project_path", "").strip()

    if not name:
        flash("Application name is required.", "warning")
        return redirect(url_for("dashboard"))

    if not base_url:
        flash("Base URL is required.", "warning")
        return redirect(url_for("dashboard"))

    # Validate URL
    is_valid, err = validate_target_url(base_url, allow_localhost=True)
    if not is_valid:
        flash(f"Base URL rejected: {err}", "warning")
        return redirect(url_for("dashboard"))

    # Check external target authorization
    is_local = any(h in base_url.lower() for h in ("localhost", "127.0.0.1", "::1"))
    if not is_local and not auth_confirmed:
        flash("External targets require confirmation that you own or have explicit authorization to test the host.", "warning")
        return redirect(url_for("dashboard"))

    ts = now_iso()
    with connect() as c:
        cur = c.execute(
            """INSERT INTO applications (name, description, base_url, app_type, auth_confirmed, project_path, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, base_url, app_type, auth_confirmed, project_path, ts, ts)
        )
        new_id = cur.lastrowid

    session["active_app_id"] = new_id
    flash(f"Application '{name}' registered successfully.", "success")
    return redirect(url_for("dashboard", app_id=new_id))


@app.post("/app/edit/<int:app_id>")
def edit_app(app_id):
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    base_url = request.form.get("base_url", "").strip()
    app_type = request.form.get("app_type", "REST API")
    auth_confirmed = 1 if request.form.get("auth_confirmed") else 0
    project_path = request.form.get("project_path", "").strip()

    if not name or not base_url:
        flash("Name and Base URL are required.", "warning")
        return redirect(url_for("dashboard", app_id=app_id))

    is_valid, err = validate_target_url(base_url, allow_localhost=True)
    if not is_valid:
        flash(f"URL validation error: {err}", "warning")
        return redirect(url_for("dashboard", app_id=app_id))

    with connect() as c:
        c.execute(
            """UPDATE applications SET name = ?, description = ?, base_url = ?, app_type = ?,
               auth_confirmed = ?, project_path = ?, updated_at = ? WHERE id = ?""",
            (name, description, base_url, app_type, auth_confirmed, project_path, now_iso(), app_id)
        )
    flash(f"Application configuration updated.", "success")
    return redirect(url_for("dashboard", app_id=app_id))


@app.post("/app/delete/<int:app_id>")
def delete_app(app_id):
    if app_id == 1:
        flash("The default bundled demo SUT application cannot be deleted.", "warning")
        return redirect(url_for("dashboard"))

    with connect() as c:
        c.execute("DELETE FROM applications WHERE id = ?", (app_id,))
        c.execute("DELETE FROM custom_tests WHERE app_id = ?", (app_id,))
        c.execute("DELETE FROM runs WHERE app_id = ?", (app_id,))
        c.execute("DELETE FROM defects WHERE app_id = ?", (app_id,))
        c.execute("DELETE FROM scans WHERE app_id = ?", (app_id,))

    session["active_app_id"] = 1
    flash("Application and related test data deleted.", "success")
    return redirect(url_for("dashboard", app_id=1))


# --- Visual Test Case Builder ---

@app.post("/test/create")
def create_test():
    active_app = get_active_app()
    app_id = active_app["id"]

    test_id = request.form.get("test_id", "").strip()
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "Positive")
    risk = request.form.get("risk", "High")
    priority = request.form.get("priority", "P1")
    method = request.form.get("method", "GET").upper()
    endpoint = request.form.get("endpoint_path", "").strip()
    headers_str = request.form.get("headers_json", "{}").strip()
    body_str = request.form.get("body_json", "").strip()
    expected_status = request.form.get("expected_status", 200, type=int)
    expected_json = request.form.get("expected_json_json", "{}").strip()
    required_fields = request.form.get("required_fields_json", "[]").strip()
    max_ms = request.form.get("max_response_time_ms", type=int)
    test_type = request.form.get("test_type", "api")

    # Agent fields
    agent_prompt = request.form.get("agent_prompt", "").strip()
    agent_tool = request.form.get("agent_expected_tool", "").strip()
    agent_forbidden = request.form.get("agent_forbidden_content", "").strip()

    if not test_id or not name:
        flash("Test ID and Test Name are required.", "warning")
        return redirect(url_for("dashboard"))

    # Validate JSON inputs
    try:
        if headers_str:
            json.loads(headers_str)
    except Exception as e:
        flash(f"Malformed Headers JSON: {e}", "warning")
        return redirect(url_for("dashboard"))

    try:
        if expected_json:
            json.loads(expected_json)
    except Exception as e:
        flash(f"Malformed Expected JSON: {e}", "warning")
        return redirect(url_for("dashboard"))

    try:
        if required_fields:
            json.loads(required_fields)
    except Exception as e:
        flash(f"Malformed Required Fields JSON: {e}", "warning")
        return redirect(url_for("dashboard"))

    ts = now_iso()
    with connect() as c:
        # Check uniqueness of test_id within app
        existing = c.execute("SELECT id FROM custom_tests WHERE app_id = ? AND test_id = ?", (app_id, test_id)).fetchone()
        if existing:
            flash(f"A test with ID '{test_id}' already exists for this application. Please use a unique ID.", "warning")
            return redirect(url_for("dashboard"))

        c.execute(
            """INSERT INTO custom_tests (app_id, test_id, name, category, risk, priority, method, endpoint_path,
               headers_json, body_json, expected_status, expected_json_json, required_fields_json,
               max_response_time_ms, test_type, agent_prompt, agent_expected_tool, agent_forbidden_content, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (app_id, test_id, name, category, risk, priority, method, endpoint, headers_str, body_str,
             expected_status, expected_json, required_fields, max_ms, test_type, agent_prompt, agent_tool, agent_forbidden, ts, ts)
        )

    flash(f"Test case '{test_id} — {name}' added to test plan.", "success")
    return redirect(url_for("dashboard"))


@app.post("/test/delete/<int:test_pk>")
def delete_test(test_pk):
    with connect() as c:
        c.execute("DELETE FROM custom_tests WHERE id = ?", (test_pk,))
    flash("Test case removed from test catalogue.", "success")
    return redirect(url_for("dashboard"))


# --- Test Execution ---

@app.post("/run/tests")
def run_all_tests():
    active_app = get_active_app()
    results = run_tests_for_app(active_app["id"])
    passed = sum(r["status"] == "PASS" for r in results)
    failed = len(results) - passed
    flash(f"Test run completed: {passed} passed, {failed} failed / error.", "success" if not failed else "warning")
    return redirect(url_for("dashboard"))


@app.post("/run/test/<test_id>")
def run_single_test_route(test_id):
    active_app = get_active_app()
    results = run_tests_for_app(active_app["id"], test_id_filter=test_id)
    if results:
        r = results[0]
        status = r["status"]
        flash(f"Test {test_id} finished with status: {status}. Actual: {r['actual']}", "success" if status == "PASS" else "warning")
    else:
        flash(f"Test case {test_id} could not be executed.", "warning")
    return redirect(url_for("dashboard"))


# Existing bundled SUT test runner
@app.post("/run/functional")
def run_functional():
    active_app = get_active_app()
    results = execute_functional_tests(app.config["INJECT_TIMEOUT_BUG"])
    passed = sum(r["status"] == "PASS" for r in results)
    failed = len(results) - passed
    with connect() as c:
        c.execute("INSERT INTO runs(app_id, run_type, created_at, passed, failed, results_json) VALUES(?,?,?,?,?,?)",
                  (active_app["id"], "Functional", now_iso(), passed, failed, json.dumps(results)))
        for r in results:
            if r["status"] == "FAIL":
                existing = c.execute("SELECT id FROM defects WHERE app_id=? AND test_id=? AND status NOT IN ('Resolved','Closed') ORDER BY id DESC LIMIT 1",
                                     (active_app["id"], r["test_id"])).fetchone()
                if existing:
                    c.execute("UPDATE defects SET evidence=?, updated_at=? WHERE id=?", (r["evidence"], now_iso(), existing["id"]))
                else:
                    c.execute("INSERT INTO defects(app_id, test_id, title, severity, priority, status, evidence, created_at, updated_at) VALUES(?,?,?,?,?,'Open',?,?,?)",
                              (active_app["id"], r["test_id"], r["name"], r["severity"], "P0" if r["severity"] == "Critical" else "P1", r["evidence"], now_iso(), now_iso()))
    flash(f"Functional run complete: {passed} passed, {failed} failed.", "success" if not failed else "warning")
    return redirect(url_for("dashboard"))


@app.post("/toggle-bug")
def toggle_bug():
    app.config["INJECT_TIMEOUT_BUG"] = bool(request.form.get("enabled"))
    flash("Demo defect enabled." if app.config["INJECT_TIMEOUT_BUG"] else "Demo defect disabled.", "warning")
    return redirect(url_for("dashboard"))


@app.post("/run/api")
def run_api():
    active_app = get_active_app()
    client = app.test_client()
    results = []
    def add(tid, name, expected, actual, ok, evidence, severity):
        results.append({"test_id": tid, "name": name, "expected": expected, "actual": actual,
                        "status": "PASS" if ok else "FAIL", "evidence": evidence, "severity": severity, "priority": "P1"})
    r = client.get("/sut/health"); body = r.get_json()
    add("AG-API-001", "Health API contract", "200 JSON status=ok", f"{r.status_code} {body}",
        r.status_code == 200 and body.get("status") == "ok" and r.is_json, f"headers={dict(r.headers)}; body={body}", "High")
    r = client.post("/sut/agent", json={}); body = r.get_json()
    add("AG-API-002", "Agent API rejects empty input", "400 message_required", f"{r.status_code} {body}",
        r.status_code == 400 and body.get("error") == "message_required", f"body={body}", "High")
    r = client.get("/sut/profile/bob", headers={"X-User-ID": "alice"}); body = r.get_json()
    add("AG-API-003", "Profile API enforces ownership", "403 forbidden", f"{r.status_code} {body}",
        r.status_code == 403 and body.get("error") == "forbidden", f"body={body}", "Critical")
    passed = sum(x["status"] == "PASS" for x in results)
    failed = len(results) - passed
    with connect() as c:
        c.execute("INSERT INTO runs(app_id, run_type, created_at, passed, failed, results_json) VALUES(?,?,?,?,?,?)",
                  (active_app["id"], "API Contract Suite", now_iso(), passed, failed, json.dumps(results)))
        for r in results:
            if r["status"] == "FAIL":
                c.execute("INSERT INTO defects(app_id, test_id, title, severity, priority, status, evidence, created_at, updated_at) VALUES(?,?,?,?,'P1','Open',?,?,?)",
                          (active_app["id"], r["test_id"], r["name"], r["severity"], r["evidence"], now_iso(), now_iso()))
    flash(f"API test run complete: {passed} passed, {failed} failed.", "success" if not failed else "warning")
    return redirect(url_for("dashboard"))


# --- AI-Agent Dedicated Behavior Runner ---

@app.post("/run/agent-behavior")
def run_agent_behavior():
    active_app = get_active_app()
    endpoint = request.form.get("endpoint", "/agent").strip()
    template = request.form.get("template", '{"message": "{prompt}", "user_id": "{user_id}"}').strip()
    prompt = request.form.get("prompt", "What's the weather?").strip()
    expected_status = request.form.get("expected_status", 200, type=int)
    expected_tool = request.form.get("expected_tool", "").strip()
    forbidden_str = request.form.get("forbidden_strings", "").strip()
    forbidden_list = [s.strip() for s in forbidden_str.split(",") if s.strip()]
    check_type = request.form.get("check_type", "Deterministic")
    repeat_count = request.form.get("repeat_count", 1, type=int)

    outcome = execute_agent_behavior_check(
        base_url=active_app["base_url"],
        endpoint=endpoint,
        payload_template=template,
        prompt=prompt,
        expected_status=expected_status,
        expected_tool=expected_tool,
        forbidden_strings=forbidden_list,
        check_type=check_type,
        repeat_count=repeat_count
    )

    test_item = {
        "test_id": f"AGT-BEHAVIOR-{int(datetime.now().timestamp()) % 10000}",
        "name": f"AI-Agent Behavior: {prompt[:30]}...",
        "status": outcome["status"],
        "expected": outcome["expected"],
        "actual": outcome["actual"],
        "evidence": outcome["evidence"],
        "severity": "High",
        "priority": "P1"
    }

    with connect() as c:
        c.execute(
            "INSERT INTO runs(app_id, run_type, created_at, passed, failed, duration_ms, results_json) VALUES(?,?,?,?,?,?,?)",
            (active_app["id"], f"AI-Agent Check ({check_type})", now_iso(),
             1 if outcome["status"] == "PASS" else 0,
             0 if outcome["status"] == "PASS" else 1,
             outcome.get("elapsed_ms", 0),
             json.dumps([test_item]))
        )
        if outcome["status"] in ("FAIL", "ERROR"):
            c.execute(
                """INSERT INTO defects (app_id, test_id, title, severity, priority, status, evidence, reproduction_steps, expected, actual, created_at, updated_at)
                   VALUES (?, ?, ?, 'High', 'P1', 'Open', ?, ?, ?, ?, ?, ?)""",
                (active_app["id"], test_item["test_id"], test_item["name"], outcome["evidence"], f"Prompt: {prompt}", outcome["expected"], outcome["actual"], now_iso(), now_iso())
            )

    flash(f"AI-Agent behavior check finished: [{outcome['status']}] {outcome['actual']}", "success" if outcome["status"] == "PASS" else "warning")
    return redirect(url_for("dashboard"))


# --- Custom Python Test Suite Runner ---

@app.post("/run/pytest")
def run_custom_pytest():
    active_app = get_active_app()
    target_path = request.form.get("project_path", "").strip() or active_app.get("project_path", "").strip() or str(ROOT)

    res = run_pytest_suite(active_app["id"], target_path, run_coverage=True)
    if res.get("success"):
        cov = res.get("coverage_percent")
        cov_text = f", Coverage: {cov}%" if cov is not None else ""
        flash(f"Pytest executed on '{target_path}': {res.get('passed')} passed, {res.get('failed')} failed ({res.get('duration')}s){cov_text}", "success" if res.get("failed") == 0 else "warning")
    else:
        flash(f"Pytest execution failed: {res.get('error', 'Execution error')}", "warning")
    return redirect(url_for("dashboard"))


# --- Security Testing ---

@app.post("/scan")
def scan():
    active_app = get_active_app()
    target = request.form.get("target", "").strip() or active_app.get("base_url", "http://127.0.0.1:5000/sut/health").strip()
    auth_confirmed = bool(request.form.get("auth_confirmed")) or bool(active_app.get("auth_confirmed"))

    try:
        result = scan_http_target(target, auth_confirmed=auth_confirmed)
        with connect() as c:
            c.execute("INSERT INTO scans(app_id, target, created_at, findings_json) VALUES(?,?,?,?)",
                      (active_app["id"], target, now_iso(), json.dumps(result)))
        flash(f"Baseline security scan complete: {result['finding_count']} finding(s) detected.", "success")
    except Exception as exc:
        flash(f"Security scan not completed: {exc}", "warning")
    return redirect(url_for("dashboard"))


# --- Code Coverage ---

@app.post("/coverage")
def coverage():
    active_app = get_active_app()
    (ROOT / "instance").mkdir(exist_ok=True)
    env = os.environ.copy()
    env["COVERAGE_FILE"] = str(ROOT / "instance" / ".coverage")
    cmd = [sys.executable, "-m", "coverage", "run", "--data-file", env["COVERAGE_FILE"], "--source=agentguard", "-m", "pytest", "-q"]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=60, env=env)
    report = subprocess.run(
        [sys.executable, "-m", "coverage", "json", "--data-file", env["COVERAGE_FILE"], "-o", str(ROOT / "instance" / "coverage.json")],
        cwd=str(ROOT), capture_output=True, text=True, timeout=30, env=env
    )
    if report.returncode == 0:
        cov = get_current_coverage(active_app["id"])
        flash(f"Coverage measured from pytest execution: {cov}%. Test exit code: {proc.returncode}.", "success" if proc.returncode == 0 else "warning")
    else:
        flash("Coverage measurement failed. " + (report.stderr[-300:]), "warning")
    return redirect(url_for("dashboard"))


# --- Defect Management & Retesting ---

@app.post("/defect/<int:defect_id>")
def update_defect(defect_id):
    status = request.form.get("status", "Open")
    if status not in ("Open", "In Progress", "Resolved", "Closed"):
        status = "Open"
    with connect() as c:
        c.execute("UPDATE defects SET status = ?, updated_at = ? WHERE id = ?", (status, now_iso(), defect_id))
    flash(f"Defect #{defect_id} status updated to '{status}'.", "success")
    return redirect(url_for("dashboard"))


@app.post("/defect/<int:defect_id>/retest")
def retest_defect(defect_id):
    active_app = get_active_app()
    with connect() as c:
        row = c.execute("SELECT * FROM defects WHERE id = ?", (defect_id,)).fetchone()
        if not row:
            flash(f"Defect #{defect_id} not found.", "warning")
            return redirect(url_for("dashboard"))
        defect = dict(row)

    test_id = defect.get("test_id")
    # Retest using runner if it exists in custom_tests
    with connect() as c:
        t_row = c.execute("SELECT * FROM custom_tests WHERE app_id = ? AND test_id = ?", (active_app["id"], test_id)).fetchone()

    if t_row:
        results = run_tests_for_app(active_app["id"], test_id_filter=test_id)
        if results and results[0]["status"] == "PASS":
            with connect() as c:
                c.execute("UPDATE defects SET status = 'Resolved', updated_at = ? WHERE id = ?", (now_iso(), defect_id))
            flash(f"Retest PASSED! Defect #{defect_id} has been verified and marked 'Resolved'.", "success")
        else:
            flash(f"Retest executed: Test {test_id} still FAILING. Defect #{defect_id} remains open.", "warning")
    else:
        # If it was a functional test on App 1
        results = execute_functional_tests(app.config["INJECT_TIMEOUT_BUG"])
        target_res = next((r for r in results if r["test_id"] == test_id), None)
        if target_res and target_res["status"] == "PASS":
            with connect() as c:
                c.execute("UPDATE defects SET status = 'Resolved', updated_at = ? WHERE id = ?", (now_iso(), defect_id))
            flash(f"Retest PASSED for {test_id}! Defect #{defect_id} verified and resolved.", "success")
        else:
            flash(f"Retest executed: Test {test_id} failed. Defect #{defect_id} remains active.", "warning")

    return redirect(url_for("dashboard"))


# --- Reporting ---

@app.route("/report", methods=["GET", "POST"])
def report():
    active_app = get_active_app()
    result = get_latest_results(active_app["id"])
    ds = get_defects(active_app["id"])
    scan_data = get_current_scan(active_app["id"])
    cov = get_current_coverage(active_app["id"], active_app.get("project_path", ""))
    require_cov = (active_app.get("app_type") == "Python project") or (cov is not None)
    gate = evaluate_release_gate(result, ds, cov, require_coverage=require_cov)

    payload = build_report(result, ds, scan_data, cov, gate, app_info=active_app)
    jp, hp = save_reports(payload, ROOT / "instance" / "reports")

    fmt = request.form.get("format") or request.args.get("format", "html")
    return send_file(
        jp if fmt == "json" else hp,
        as_attachment=True,
        download_name=f"agentguard-report-{active_app['id']}.json" if fmt == "json" else f"agentguard-report-{active_app['id']}.html"
    )


# --- REST API Status ---

@app.get("/api/status")
def api_status():
    active_app = get_active_app()
    results = get_latest_results(active_app["id"])
    cov = get_current_coverage(active_app["id"])
    app_defects = get_defects(active_app["id"])
    return jsonify({
        "service": "AgentGuard",
        "active_application": active_app,
        "test_cases_count": len(get_tests_for_app(active_app["id"])),
        "latest_results": results,
        "coverage_percent": cov,
        "release_gate": evaluate_release_gate(results, app_defects, cov)
    })


@app.get("/api/apps")
def api_apps():
    return jsonify(rows("SELECT * FROM applications ORDER BY id ASC"))


# --- Selenium Browser Testing ---

@app.post("/api/browser-test")
def api_browser_test():
    """
    Executes an automated Selenium browser verification check.
    Accepts JSON: {"url": "...", "expected_title": "..."} or form data.
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict()

    target_url = (data.get("url") or "").strip()
    expected_title = (data.get("expected_title") or "").strip() or None
    raw_headless = data.get("headless")
    if raw_headless is None:
        headless = True
    elif isinstance(raw_headless, bool):
        headless = raw_headless
    else:
        headless = str(raw_headless).lower() in ("true", "1", "yes")

    if not target_url:
        return jsonify({
            "status": "FAIL",
            "url": "",
            "page_title": None,
            "final_url": None,
            "duration_ms": 0,
            "tests": [{
                "id": "BG-004",
                "name": "Target URL validation",
                "status": "FAIL",
                "detail": "Target URL cannot be empty."
            }],
            "error": "URL parameter is required."
        }), 400

    result = run_browser_test(target_url, expected_title=expected_title, headless=headless)
    status_code = 200 if result["status"] == "PASS" else 422
    return jsonify(result), status_code


if __name__ == "__main__":
    with app.app_context():
        with connect():
            pass
    app.run(host="127.0.0.1", port=5000, debug=False)
