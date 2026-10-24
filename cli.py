"""AgentGuard CLI — Run automated tests, scans, and quality gates directly from the terminal."""
import argparse
import sys
import json
from pathlib import Path

from agentguard.db import connect
from agentguard.runner import run_tests_for_app
from agentguard.agent_tester import execute_agent_behavior_check
from agentguard.scanner import scan_http_target
from agentguard.gate import evaluate_release_gate
from agentguard.reports import build_report, save_reports


def get_app(conn, app_id: int):
    row = conn.execute("SELECT * FROM applications WHERE id = ?", (app_id,)).fetchone()
    if not row:
        print(f"Error: Application with ID #{app_id} not found.")
        sys.exit(1)
    return dict(row)


def cmd_apps(args):
    """List registered applications."""
    with connect() as conn:
        rows = conn.execute("SELECT * FROM applications ORDER BY id ASC").fetchall()
        if not rows:
            print("No applications registered.")
            return

        print("\nRegistered Applications:")
        print(f"{'ID':<4} {'Type':<16} {'Name':<28} {'Base URL'}")
        print("-" * 75)
        for r in rows:
            print(f"#{r['id']:<3} {r['app_type']:<16} {r['name']:<28} {r['base_url']}")
        print()


def cmd_test(args):
    """Run tests for an application."""
    with connect() as conn:
        app = get_app(conn, args.app)

    print(f"\nRunning test suite for: #{app['id']} {app['name']} ({app['base_url']})")
    results = run_tests_for_app(args.app, test_id_filter=args.test_id)

    if not results:
        print("No test cases found for this application. Add tests via UI or test builder.")
        return

    print(f"\n{'Status':<8} {'Test ID':<14} {'Latency':<10} {'Name'}")
    print("-" * 75)
    for r in results:
        status_str = f"[{r['status']}]"
        print(f"{status_str:<8} {r['test_id']:<14} {r['elapsed_ms']}ms{'':<4} {r['name']}")
        if r['status'] != 'PASS':
            print(f"   -> Expected: {r['expected']}")
            print(f"   -> Actual:   {r['actual']}")

    passed = sum(r['status'] == 'PASS' for r in results)
    failed = len(results) - passed
    print("-" * 75)
    print(f"Summary: {passed} PASSED | {failed} FAILED / ERROR (Total: {len(results)})\n")


def cmd_agent(args):
    """Run AI-Agent behavioral check."""
    with connect() as conn:
        app = get_app(conn, args.app)

    print(f"\nExecuting AI-Agent check against {app['name']}...")
    print(f"Prompt: '{args.prompt}'")
    forbidden = [s.strip() for s in args.forbidden.split(",") if s.strip()] if args.forbidden else None

    res = execute_agent_behavior_check(
        base_url=app["base_url"],
        endpoint=args.endpoint,
        payload_template=args.template,
        prompt=args.prompt,
        expected_status=args.status,
        expected_tool=args.tool,
        forbidden_strings=forbidden,
        check_type=args.type,
        repeat_count=args.repeat
    )

    print("\nResult:")
    print(f"Status:   [{res['status']}] ({res['check_type']})")
    print(f"Latency:  {res['elapsed_ms']} ms")
    print(f"Expected: {res['expected']}")
    print(f"Actual:   {res['actual']}")
    print(f"Evidence: {res['evidence']}\n")


def cmd_scan(args):
    """Run security baseline scan."""
    print(f"\nScanning target: {args.target}")
    try:
        res = scan_http_target(args.target, auth_confirmed=args.confirm)
        print(f"Status:       HTTP {res['status_code']}")
        print(f"Latency:      {res['response_time_ms']} ms")
        print(f"Findings:     {res['finding_count']}")

        if res.get("tls_info"):
            print(f"TLS:          {res['tls_info'].get('version')} ({res['tls_info'].get('cipher')})")

        if res["findings"]:
            print("\nFindings List:")
            for idx, f in enumerate(res["findings"], 1):
                print(f"  {idx}. [{f['severity']}] {f['title']}: {f['detail']}")
        else:
            print("Zero baseline security findings.")
        print()
    except Exception as e:
        print(f"\nScan Error: {e}\n")


def cmd_gate(args):
    """Evaluate release quality gate."""
    with connect() as conn:
        app = get_app(conn, args.app)
        last_run = conn.execute("SELECT results_json FROM runs WHERE app_id = ? ORDER BY id DESC LIMIT 1", (args.app,)).fetchone()
        defects = [dict(d) for d in conn.execute("SELECT * FROM defects WHERE app_id = ?", (args.app,)).fetchall()]

    results = json.loads(last_run["results_json"]) if last_run else []

    cov = None
    cov_path = Path("instance/coverage.json")
    if cov_path.exists():
        try:
            cov = round(json.loads(cov_path.read_text(encoding="utf-8")).get("totals", {}).get("percent_covered", 0), 2)
        except Exception:
            pass

    require_cov = (app.get("app_type") == "Python project") or (cov is not None)
    gate = evaluate_release_gate(results, defects, coverage_percent=cov, minimum_coverage=args.min_cov, require_coverage=require_cov)

    print(f"\nRelease Gate Evaluation for: #{app['id']} {app['name']}")
    print("=" * 60)
    print(f"DECISION: {gate['decision']}")
    print(f"Pass Rate:                 {gate['metrics']['pass_rate_percent']}%")
    print(f"Open Critical/High:        {gate['metrics']['open_critical'] + gate['metrics']['open_high']}")
    print(f"Measured Coverage:         {cov if cov is not None else 'N/A'}%")

    if gate["blockers"]:
        print("\nBlockers:")
        for b in gate["blockers"]:
            print(f"  - {b}")
    else:
        print("\nAll quality criteria satisfied! Ready for release.")
    print()


def cmd_defects(args):
    """List defects for an application."""
    with connect() as conn:
        app = get_app(conn, args.app)
        rows = conn.execute("SELECT * FROM defects WHERE app_id = ? ORDER BY id DESC", (args.app,)).fetchall()

    if not rows:
        print(f"\nZero defects recorded for #{app['id']} {app['name']}.\n")
        return

    print(f"\nDefects for #{app['id']} {app['name']}:")
    print(f"{'ID':<6} {'Severity':<10} {'Status':<12} {'Test ID':<14} {'Title'}")
    print("-" * 75)
    for r in rows:
        print(f"#{r['id']:<5} {r['severity']:<10} {r['status']:<12} {r['test_id']:<14} {r['title']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="AgentGuard CLI — Test Runner & Quality Gate")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # apps
    p_apps = subparsers.add_parser("apps", help="List registered applications")

    # test
    p_test = subparsers.add_parser("test", help="Run automated test suite for an application")
    p_test.add_argument("--app", type=int, default=1, help="Application ID (default: 1)")
    p_test.add_argument("--test-id", type=str, default=None, help="Filter by specific Test ID")

    # agent
    p_agent = subparsers.add_parser("agent", help="Run AI-Agent behavioral check")
    p_agent.add_argument("--app", type=int, default=1, help="Application ID (default: 1)")
    p_agent.add_argument("--prompt", type=str, default="What's the weather in Tokyo?", help="Prompt to send")
    p_agent.add_argument("--tool", type=str, default="weather_lookup", help="Expected tool routing")
    p_agent.add_argument("--endpoint", type=str, default="/agent", help="Agent endpoint path")
    p_agent.add_argument("--status", type=int, default=200, help="Expected HTTP status code")
    p_agent.add_argument("--template", type=str, default='{"message": "{prompt}", "user_id": "{user_id}"}', help="Payload template")
    p_agent.add_argument("--forbidden", type=str, default="", help="Forbidden string(s) comma-separated")
    p_agent.add_argument("--type", type=str, default="Deterministic", choices=["Deterministic", "Probabilistic"])
    p_agent.add_argument("--repeat", type=int, default=1, help="Repeat count")

    # scan
    p_scan = subparsers.add_parser("scan", help="Run passive HTTP security baseline scan")
    p_scan.add_argument("target", type=str, help="Target URL (e.g., http://127.0.0.1:5000/sut/health)")
    p_scan.add_argument("--confirm", action="store_true", help="Confirm ownership/authorization for external host")

    # gate
    p_gate = subparsers.add_parser("gate", help="Evaluate release quality gate")
    p_gate.add_argument("--app", type=int, default=1, help="Application ID (default: 1)")
    p_gate.add_argument("--min-cov", type=float, default=70.0, help="Minimum required coverage percentage")

    # defects
    p_def = subparsers.add_parser("defects", help="List defect records")
    p_def.add_argument("--app", type=int, default=1, help="Application ID (default: 1)")

    args = parser.parse_args()

    if args.command == "apps":
        cmd_apps(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "agent":
        cmd_agent(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "gate":
        cmd_gate(args)
    elif args.command == "defects":
        cmd_defects(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
