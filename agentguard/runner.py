"""Automated HTTP test runner using Python requests with SSRF protection and assertion evaluation."""
import json
import time
import requests
from urllib.parse import urljoin
from datetime import datetime, timezone
from .security import validate_target_url, mask_sensitive_headers, mask_sensitive_in_evidence
from .db import connect

MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2MB limit
DEFAULT_TIMEOUT_SEC = 10


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_json_path_value(data, path: str):
    """Retrieves a nested value from dictionary using dot notation (e.g., 'data.user.id')."""
    if not isinstance(data, dict):
        return None
    keys = path.split(".")
    curr = data
    for k in keys:
        if isinstance(curr, dict) and k in curr:
            curr = curr[k]
        elif isinstance(curr, list):
            try:
                idx = int(k)
                curr = curr[idx]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return curr


def execute_single_test(app: dict, test: dict) -> dict:
    """
    Executes a single custom test case against the application.
    Returns result dictionary with status, evidence, expected, actual, elapsed_ms, etc.
    """
    test_id = test.get("test_id", "TEST-001")
    name = test.get("name", "Unnamed Test")
    severity = test.get("risk", "High")
    priority = test.get("priority", "P1")
    method = test.get("method", "GET").upper()
    endpoint = test.get("endpoint_path", "").strip()
    base_url = app.get("base_url", "").strip()

    # Construct full URL
    if not base_url.endswith("/"):
        base_url += "/"
    if endpoint.startswith("/"):
        endpoint = endpoint[1:]
    full_url = urljoin(base_url, endpoint)

    # SSRF & Target Validation
    # Allow localhost if target is explicitly local
    is_valid_url, error_msg = validate_target_url(full_url, allow_localhost=True)
    if not is_valid_url:
        return {
            "test_id": test_id,
            "name": name,
            "category": test.get("category", "API"),
            "risk": severity,
            "priority": priority,
            "status": "ERROR",
            "expected": f"Target reachability and HTTP {test.get('expected_status', 200)}",
            "actual": f"Blocked by Security Validator: {error_msg}",
            "evidence": f"URL={full_url}; SecurityCheck=Failed: {error_msg}",
            "elapsed_ms": 0.0,
            "url": full_url
        }

    # Parse headers
    headers = {}
    if test.get("headers_json"):
        try:
            parsed_headers = json.loads(test["headers_json"]) if isinstance(test["headers_json"], str) else test["headers_json"]
            if isinstance(parsed_headers, dict):
                headers = parsed_headers
        except Exception as e:
            return {
                "test_id": test_id,
                "name": name,
                "category": test.get("category", "API"),
                "risk": severity,
                "priority": priority,
                "status": "ERROR",
                "expected": "Valid test headers JSON",
                "actual": f"Malformed headers JSON: {e}",
                "evidence": f"Raw headers: {test.get('headers_json')}",
                "elapsed_ms": 0.0,
                "url": full_url
            }

    # Parse body
    data = None
    json_data = None
    if method in ("POST", "PUT", "PATCH", "DELETE") and test.get("body_json"):
        raw_body = test["body_json"].strip()
        if raw_body:
            try:
                json_data = json.loads(raw_body)
            except Exception:
                data = raw_body

    # Execute HTTP request
    start_time = time.perf_counter()
    response_body = None
    response_json = None
    actual_status = None
    elapsed_ms = 0.0

    try:
        req_headers = {"User-Agent": "AgentGuard-TestRunner/2.0"}
        req_headers.update(headers)

        with requests.request(
            method=method,
            url=full_url,
            headers=req_headers,
            json=json_data,
            data=data,
            timeout=DEFAULT_TIMEOUT_SEC,
            stream=True
        ) as resp:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            actual_status = resp.status_code

            # Check response size limit
            content_bytes = bytearray()
            for chunk in resp.iter_content(chunk_size=4096):
                content_bytes.extend(chunk)
                if len(content_bytes) > MAX_RESPONSE_BYTES:
                    return {
                        "test_id": test_id,
                        "name": name,
                        "category": test.get("category", "API"),
                        "risk": severity,
                        "priority": priority,
                        "status": "ERROR",
                        "expected": f"Response size under {MAX_RESPONSE_BYTES // 1024} KB",
                        "actual": f"Exceeded size limit (> {len(content_bytes)} bytes)",
                        "evidence": f"Status={actual_status}; Download aborted due to size threshold.",
                        "elapsed_ms": elapsed_ms,
                        "url": full_url
                    }

            raw_text = content_bytes.decode("utf-8", errors="replace")
            response_body = raw_text[:4000]  # Store preview
            try:
                response_json = json.loads(raw_text)
            except Exception:
                response_json = None

    except requests.exceptions.Timeout:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "test_id": test_id,
            "name": name,
            "category": test.get("category", "API"),
            "risk": severity,
            "priority": priority,
            "status": "FAIL",
            "expected": f"Response within {DEFAULT_TIMEOUT_SEC}s and HTTP {test.get('expected_status', 200)}",
            "actual": f"Request timed out after {elapsed_ms} ms",
            "evidence": f"URL={full_url}; Method={method}; Timeout={DEFAULT_TIMEOUT_SEC}s",
            "elapsed_ms": elapsed_ms,
            "url": full_url
        }
    except requests.exceptions.ConnectionError as ce:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "test_id": test_id,
            "name": name,
            "category": test.get("category", "API"),
            "risk": severity,
            "priority": priority,
            "status": "ERROR",
            "expected": f"Service active at {full_url}",
            "actual": f"Connection failed: {ce}",
            "evidence": f"ConnectionError on {full_url}",
            "elapsed_ms": elapsed_ms,
            "url": full_url
        }
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "test_id": test_id,
            "name": name,
            "category": test.get("category", "API"),
            "risk": severity,
            "priority": priority,
            "status": "ERROR",
            "expected": f"HTTP {test.get('expected_status', 200)}",
            "actual": f"Execution error: {exc}",
            "evidence": f"Exception: {type(exc).__name__}: {exc}",
            "elapsed_ms": elapsed_ms,
            "url": full_url
        }

    # Evaluate Assertions
    failures = []
    expected_parts = []
    actual_parts = []

    # 1. Status Code
    expected_status = int(test.get("expected_status", 200))
    expected_parts.append(f"HTTP {expected_status}")
    actual_parts.append(f"HTTP {actual_status}")
    if actual_status != expected_status:
        failures.append(f"Expected status {expected_status}, received {actual_status}")

    # 2. Expected JSON Fields and Values
    expected_json_str = test.get("expected_json_json", "{}")
    if expected_json_str and expected_json_str.strip():
        try:
            expected_json_map = json.loads(expected_json_str) if isinstance(expected_json_str, str) else expected_json_str
            if isinstance(expected_json_map, dict) and expected_json_map:
                expected_parts.append(f"JSON matches {json.dumps(expected_json_map)}")
                if response_json is None:
                    failures.append("Expected JSON response body, but response was non-JSON")
                    actual_parts.append("Non-JSON body")
                else:
                    for k, exp_val in expected_json_map.items():
                        actual_val = get_json_path_value(response_json, k)
                        if actual_val != exp_val:
                            failures.append(f"Field '{k}': expected {exp_val!r}, got {actual_val!r}")
                    actual_parts.append(f"JSON={json.dumps(response_json)[:100]}")
        except Exception as e:
            failures.append(f"Invalid expected JSON assertion rule: {e}")

    # 3. Required Fields Existence
    req_fields_str = test.get("required_fields_json", "[]")
    if req_fields_str and req_fields_str.strip():
        try:
            req_fields = json.loads(req_fields_str) if isinstance(req_fields_str, str) else req_fields_str
            if isinstance(req_fields, list) and req_fields:
                expected_parts.append(f"Required fields: {req_fields}")
                if response_json is None:
                    failures.append(f"Cannot verify required fields: response is not JSON")
                else:
                    missing = [f for f in req_fields if get_json_path_value(response_json, f) is None]
                    if missing:
                        failures.append(f"Missing required response fields: {missing}")
        except Exception as e:
            failures.append(f"Invalid required_fields assertion rule: {e}")

    # 4. Response Time Threshold
    max_ms = test.get("max_response_time_ms")
    if max_ms:
        try:
            max_ms_val = float(max_ms)
            expected_parts.append(f"Latency <= {max_ms_val}ms")
            actual_parts.append(f"{elapsed_ms}ms")
            if elapsed_ms > max_ms_val:
                failures.append(f"Response time {elapsed_ms}ms exceeded threshold {max_ms_val}ms")
        except ValueError:
            pass

    # 5. Agent-specific checks if test_type == 'agent'
    if test.get("test_type") == "agent":
        expected_tool = test.get("agent_expected_tool", "").strip()
        if expected_tool:
            expected_parts.append(f"Tool={expected_tool}")
            actual_tool = get_json_path_value(response_json, "tool") if response_json else None
            actual_parts.append(f"Tool={actual_tool}")
            if actual_tool != expected_tool:
                failures.append(f"Agent selected tool '{actual_tool}', expected '{expected_tool}'")

        forbidden = test.get("agent_forbidden_content", "").strip()
        if forbidden:
            expected_parts.append(f"Forbidden text absent: '{forbidden}'")
            if forbidden.lower() in (response_body or "").lower():
                failures.append(f"Response contains prohibited content/leak: '{forbidden}'")

    status = "PASS" if not failures else "FAIL"
    masked_headers = mask_sensitive_headers(headers)
    evidence_str = f"Status={actual_status}; Latency={elapsed_ms}ms; URL={full_url}; Headers={masked_headers}; Body={response_body[:250]}"
    if failures:
        evidence_str = f"Failures: {'; '.join(failures)} | " + evidence_str

    return {
        "test_id": test_id,
        "name": name,
        "category": test.get("category", "API"),
        "risk": severity,
        "priority": priority,
        "status": status,
        "expected": " & ".join(expected_parts) or f"HTTP {expected_status}",
        "actual": "; ".join(failures) if failures else (" & ".join(actual_parts) or f"HTTP {actual_status}"),
        "evidence": mask_sensitive_in_evidence(evidence_str),
        "elapsed_ms": elapsed_ms,
        "url": full_url,
        "failures": failures
    }


def run_tests_for_app(app_id: int, test_id_filter: str = None) -> list[dict]:
    """
    Executes tests for an application, records results in SQLite runs & defects tables,
    and returns list of test outcome dictionaries.
    """
    with connect() as conn:
        app_row = conn.execute("SELECT * FROM applications WHERE id = ?", (app_id,)).fetchone()
        if not app_row:
            return []
        app = dict(app_row)

        query = "SELECT * FROM custom_tests WHERE app_id = ?"
        params = [app_id]
        if test_id_filter:
            query += " AND test_id = ?"
            params.append(test_id_filter)
        query += " ORDER BY priority ASC, id ASC"

        test_rows = conn.execute(query, params).fetchall()
        tests = [dict(t) for t in test_rows]

    results = []
    total_start = time.perf_counter()

    for t in tests:
        res = execute_single_test(app, t)
        results.append(res)

    total_duration_ms = round((time.perf_counter() - total_start) * 1000, 2)
    passed = sum(r["status"] == "PASS" for r in results)
    failed = len(results) - passed

    # Record in database
    with connect() as conn:
        conn.execute(
            """INSERT INTO runs (app_id, run_type, created_at, passed, failed, duration_ms, results_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (app_id, "Automated API & Agent Suite", now_iso(), passed, failed, total_duration_ms, json.dumps(results))
        )

        # Defect tracking lifecycle
        for r in results:
            if r["status"] in ("FAIL", "ERROR"):
                existing = conn.execute(
                    "SELECT id FROM defects WHERE app_id = ? AND test_id = ? AND status NOT IN ('Resolved', 'Closed') ORDER BY id DESC LIMIT 1",
                    (app_id, r["test_id"])
                ).fetchone()

                repro = f"Target: {r.get('url', app.get('base_url'))}\nExpected: {r['expected']}\nActual: {r['actual']}"
                if existing:
                    conn.execute(
                        "UPDATE defects SET evidence = ?, actual = ?, reproduction_steps = ?, updated_at = ? WHERE id = ?",
                        (r["evidence"], r["actual"], repro, now_iso(), existing["id"])
                    )
                else:
                    conn.execute(
                        """INSERT INTO defects (app_id, test_id, title, severity, priority, status, evidence, reproduction_steps, expected, actual, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)""",
                        (app_id, r["test_id"], r["name"], r["risk"], r["priority"], r["evidence"], repro, r["expected"], r["actual"], now_iso(), now_iso())
                    )

    return results
