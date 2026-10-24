"""Controlled subprocess runner for custom local Python projects and pytest test suites."""
import os
import re
import sys
import json
import time
import subprocess
from pathlib import Path
from .db import connect, now_iso


def validate_python_project_path(project_path: str) -> tuple[bool, Path | None, str]:
    """Validates that the provided path exists, is a directory, and is safe."""
    if not project_path or not project_path.strip():
        return False, None, "Project path cannot be empty."

    p = Path(project_path.strip()).resolve()
    if not p.exists():
        return False, None, f"Directory does not exist: {p}"
    if not p.is_dir():
        return False, None, f"Specified path is not a directory: {p}"

    return True, p, ""


def run_pytest_suite(app_id: int, project_path: str, run_coverage: bool = True, timeout_sec: int = 60) -> dict:
    """
    Executes pytest in a controlled isolated subprocess for the specified directory.
    Captures test counts, pass/fail status, duration, failure traces, and measured coverage.
    """
    is_valid, resolved_path, err_msg = validate_python_project_path(project_path)
    if not is_valid:
        return {
            "success": False,
            "error": err_msg,
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "duration": 0.0,
            "coverage_percent": None,
            "failures": []
        }

    cov_file = resolved_path / ".coverage_agentguard"
    cov_json_file = resolved_path / "coverage_agentguard.json"

    env = os.environ.copy()
    env["COVERAGE_FILE"] = str(cov_file)
    env["PYTHONUNBUFFERED"] = "1"

    start_time = time.perf_counter()

    # Base pytest command
    if run_coverage:
        cmd = [
            sys.executable, "-m", "coverage", "run",
            f"--data-file={cov_file}",
            "--source=.",
            "-m", "pytest", "-v", "--tb=short"
        ]
    else:
        cmd = [sys.executable, "-m", "pytest", "-v", "--tb=short"]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(resolved_path),
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Test suite execution timed out after {timeout_sec} seconds.",
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "duration": float(timeout_sec),
            "coverage_percent": None,
            "failures": ["Execution timed out"]
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Subprocess launch failed: {exc}",
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "duration": 0.0,
            "coverage_percent": None,
            "failures": [str(exc)]
        }

    duration = round(time.perf_counter() - start_time, 2)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")

    # Parse pytest output
    passed = 0
    failed = 0
    skipped = 0
    errors = 0

    # Pattern e.g.: "10 passed, 2 failed in 1.05s"
    m_pass = re.search(r"(\d+)\s+passed", output)
    if m_pass:
        passed = int(m_pass.group(1))

    m_fail = re.search(r"(\d+)\s+failed", output)
    if m_fail:
        failed = int(m_fail.group(1))

    m_skip = re.search(r"(\d+)\s+skipped", output)
    if m_skip:
        skipped = int(m_skip.group(1))

    m_err = re.search(r"(\d+)\s+errors?", output)
    if m_err:
        errors = int(m_err.group(1))

    total = passed + failed + skipped + errors

    # Extract failure lines
    failures = []
    for line in output.splitlines():
        if line.startswith("FAILED ") or line.startswith("ERROR "):
            failures.append(line.strip())

    # Measure coverage if requested
    coverage_percent = None
    if run_coverage and cov_file.exists():
        try:
            cov_proc = subprocess.run(
                [sys.executable, "-m", "coverage", "json", f"--data-file={cov_file}", "-o", str(cov_json_file)],
                cwd=str(resolved_path),
                capture_output=True,
                text=True,
                timeout=20,
                env=env
            )
            if cov_proc.returncode == 0 and cov_json_file.exists():
                cov_data = json.loads(cov_json_file.read_text(encoding="utf-8"))
                coverage_percent = round(cov_data.get("totals", {}).get("percent_covered", 0.0), 2)
        except Exception:
            coverage_percent = None
        finally:
            # Clean temporary coverage files if desired
            try:
                if cov_file.exists():
                    cov_file.unlink()
                if cov_json_file.exists():
                    cov_json_file.unlink()
            except Exception:
                pass

    # Save to SQLite runs
    test_results_summary = [
        {
            "test_id": f"PYTEST-{idx+1:03d}",
            "name": f"Pytest Suite Execution #{idx+1}",
            "status": "FAIL" if "FAILED" in f else "ERROR",
            "expected": "All unit tests pass",
            "actual": f,
            "evidence": f"Output snippet: {f}",
            "severity": "High"
        }
        for idx, f in enumerate(failures[:10])
    ]
    if not failures and total > 0:
        test_results_summary.append({
            "test_id": "PYTEST-ALL",
            "name": f"Pytest Suite ({total} tests)",
            "status": "PASS",
            "expected": "All tests pass",
            "actual": f"{passed} passed, {skipped} skipped",
            "evidence": f"Executed {total} tests in {duration}s",
            "severity": "Low"
        })

    with connect() as conn:
        conn.execute(
            """INSERT INTO runs (app_id, run_type, created_at, passed, failed, duration_ms, results_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (app_id, "Python Pytest Suite", now_iso(), passed, failed + errors, duration * 1000, json.dumps(test_results_summary))
        )

        for f_item in test_results_summary:
            if f_item["status"] in ("FAIL", "ERROR"):
                conn.execute(
                    """INSERT INTO defects (app_id, test_id, title, severity, priority, status, evidence, reproduction_steps, expected, actual, created_at, updated_at)
                       VALUES (?, ?, ?, 'High', 'P1', 'Open', ?, ?, ?, ?, ?, ?)""",
                    (app_id, f_item["test_id"], f_item["name"], f_item["evidence"], f"Run pytest on {resolved_path}", f_item["expected"], f_item["actual"], now_iso(), now_iso())
                )

    return {
        "success": proc.returncode in (0, 1),
        "exit_code": proc.returncode,
        "total": total,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "duration": duration,
        "coverage_percent": coverage_percent,
        "failures": failures,
        "raw_output": output[-2000:]
    }
