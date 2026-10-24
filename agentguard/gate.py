"""Risk-based release quality gate with configurable thresholds and evidence verification."""

def evaluate_release_gate(
    results: list[dict],
    defects: list[dict],
    coverage_percent: float | None = None,
    minimum_coverage: float = 70.0,
    require_coverage: bool = True,
    block_on_errors: bool = True
) -> dict:
    """
    Evaluates whether the application meets release criteria.
    Returns decision: 'GO' or 'NO-GO', with criteria, blocker breakdown, and metrics.
    """
    blockers = []

    failures = [r for r in results if r.get("status") == "FAIL"]
    errors = [r for r in results if r.get("status") == "ERROR"]
    passed_count = sum(r.get("status") == "PASS" for r in results)
    total_tests = len(results)
    pass_rate = round((passed_count / total_tests) * 100, 1) if total_tests > 0 else 0.0

    if not results:
        blockers.append("No test execution records found for this application")
    elif failures:
        blockers.append(f"{len(failures)} failing test(s) detected in latest run")

    if block_on_errors and errors:
        blockers.append(f"{len(errors)} execution error(s) (network, timeout, or configuration issue)")

    # Defect analysis
    open_defects = [d for d in defects if d.get("status", "Open") not in ("Resolved", "Closed")]
    open_crit = sum(1 for d in open_defects if d.get("severity") == "Critical")
    open_high = sum(1 for d in open_defects if d.get("severity") == "High")
    open_med = sum(1 for d in open_defects if d.get("severity") == "Medium")
    open_low = sum(1 for d in open_defects if d.get("severity") == "Low")

    if open_crit > 0 or open_high > 0:
        blockers.append(f"{open_crit + open_high} open Critical/High defect(s)")

    # Coverage verification
    coverage_satisfied = True
    if require_coverage:
        if coverage_percent is None:
            blockers.append("coverage not measured")
            coverage_satisfied = False
        elif coverage_percent < minimum_coverage:
            blockers.append(f"coverage {coverage_percent}% is below {minimum_coverage}%")
            coverage_satisfied = False
    elif coverage_percent is not None and coverage_percent < minimum_coverage:
        blockers.append(f"coverage {coverage_percent}% is below {minimum_coverage}%")
        coverage_satisfied = False

    decision = "NO-GO" if blockers else "GO"

    return {
        "decision": decision,
        "blockers": blockers,
        "metrics": {
            "total_tests": total_tests,
            "passed": passed_count,
            "failed": len(failures),
            "errors": len(errors),
            "pass_rate_percent": pass_rate,
            "open_critical": open_crit,
            "open_high": open_high,
            "open_medium": open_med,
            "open_low": open_low
        },
        "criteria": {
            "zero_failing_tests": len(failures) == 0 and len(errors) == 0 and total_tests > 0,
            "zero_open_critical_high": (open_crit + open_high) == 0,
            "coverage_satisfied": coverage_satisfied,
            "coverage_measured": coverage_percent is not None,
            "minimum_coverage_percent": minimum_coverage,
            "actual_coverage_percent": coverage_percent
        }
    }
