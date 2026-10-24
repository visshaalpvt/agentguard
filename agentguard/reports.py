"""Audit and Evidence Report generator in HTML and JSON formats."""
import json
import html
from pathlib import Path
from datetime import datetime, timezone


def build_report(results, defects, scan, coverage, gate, app_info=None, run_info=None):
    """Constructs comprehensive report dictionary."""
    app_info = app_info or {
        "id": 1,
        "name": "AgentGuard Bundled Demo SUT",
        "app_type": "AI agent API",
        "base_url": "http://127.0.0.1:5000/sut"
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": app_info,
        "run_info": run_info or {},
        "summary": {
            "total_tests": len(results),
            "passed": sum(r.get("status") == "PASS" for r in results),
            "failed": sum(r.get("status") in ("FAIL", "ERROR") for r in results),
            "coverage_percent": coverage,
            "release_decision": gate.get("decision", "NOT EVALUATED")
        },
        "tests": results,
        "defects": defects,
        "security_scan": scan,
        "release_gate": gate
    }


def save_reports(report, folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    json_path = folder / "latest-report.json"
    html_path = folder / "latest-report.html"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    app = report.get("application", {})
    summary = report.get("summary", {})
    gate = report.get("release_gate", {})
    blockers = gate.get("blockers", [])

    test_rows = "".join(
        f"""<tr>
            <td style="font-family:monospace;font-weight:bold;">{html.escape(str(r.get('test_id', '')))}</td>
            <td><strong>{html.escape(str(r.get('name', '')))}</strong><br><small style="color:#666;">{html.escape(str(r.get('category', '')))} · {html.escape(str(r.get('risk', '')))}</small></td>
            <td><span class="badge {str(r.get('status', '')).lower()}">{html.escape(str(r.get('status', '')))}</span></td>
            <td><code>{html.escape(str(r.get('expected', '')))}</code></td>
            <td><code>{html.escape(str(r.get('actual', '')))}</code></td>
            <td style="font-size:11px;max-width:250px;word-break:break-all;">{html.escape(str(r.get('evidence', '')))}</td>
        </tr>"""
        for r in report.get("tests", [])
    )

    defect_rows = "".join(
        f"""<tr>
            <td>#{html.escape(str(d.get('id', '')))}</td>
            <td><span class="badge {str(d.get('severity', '')).lower()}">{html.escape(str(d.get('severity', '')))}</span></td>
            <td><strong>{html.escape(str(d.get('title', '')))}</strong><br><small>{html.escape(str(d.get('test_id', '')))}</small></td>
            <td><span class="status-badge">{html.escape(str(d.get('status', '')))}</span></td>
            <td style="font-size:11px;max-width:250px;word-break:break-all;">{html.escape(str(d.get('evidence', '')))}</td>
        </tr>"""
        for d in report.get("defects", [])
    ) if report.get("defects") else "<tr><td colspan='5' style='text-align:center;color:#888;'>No defects recorded.</td></tr>"

    blocker_html = "".join(f"<li>{html.escape(str(b))}</li>" for b in blockers) if blockers else "<li style='color:#16a34a;'>All release gate criteria met. Zero blocking defects.</li>"

    scan = report.get("security_scan") or {}
    scan_html = f"<p>Target: <code>{html.escape(str(scan.get('target', 'N/A')))}</code> | Status: {html.escape(str(scan.get('status_code', 'N/A')))} | Findings: {html.escape(str(scan.get('finding_count', 0)))}</p>"
    if scan.get("findings"):
        scan_html += "<ul>" + "".join(f"<li><strong>[{html.escape(str(f.get('severity', '')))}] {html.escape(str(f.get('title', '')))}</strong>: {html.escape(str(f.get('detail', '')))}</li>" for f in scan.get("findings", [])) + "</ul>"

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AgentGuard Quality Gate Report — {html.escape(app.get('name', 'App'))}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 30px; color: #1e293b; background: #f8fafc; line-height: 1.5; }}
    .container {{ max-width: 1100px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 14px rgba(0,0,0,0.06); border: 1px solid #e2e8f0; }}
    h1 {{ margin: 0 0 6px; font-size: 26px; color: #0f172a; }}
    .meta-box {{ display: flex; flex-wrap: wrap; gap: 20px; background: #f1f5f9; padding: 14px 20px; border-radius: 8px; margin: 18px 0; font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 20px 0; }}
    .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; text-align: center; }}
    .card span {{ font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: bold; letter-spacing: 0.5px; }}
    .card strong {{ display: block; font-size: 24px; margin-top: 6px; color: #0f172a; }}
    .decision {{ font-size: 20px; font-weight: bold; padding: 6px 14px; border-radius: 6px; display: inline-block; }}
    .decision.go {{ background: #dcfce7; color: #15803d; }}
    .decision.no-go {{ background: #fee2e2; color: #b91c1c; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin: 16px 0 28px; }}
    th, td {{ padding: 10px 12px; border: 1px solid #e2e8f0; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; font-weight: 600; color: #475569; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
    .badge.pass {{ background: #dcfce7; color: #166534; }}
    .badge.fail {{ background: #fee2e2; color: #991b1b; }}
    .badge.error {{ background: #ffedd5; color: #9a3412; }}
    .badge.critical {{ background: #fee2e2; color: #b91c1c; }}
    .badge.high {{ background: #ffedd5; color: #c2410c; }}
    .badge.medium {{ background: #fef9c3; color: #854d0e; }}
    .badge.low {{ background: #e0f2fe; color: #0369a1; }}
    .status-badge {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-weight: 600; font-size: 11px; }}
    ul.blockers {{ background: #fff1f2; border: 1px solid #fecdd3; border-radius: 8px; padding: 14px 28px; color: #9f1239; }}
    code {{ background: #f1f5f9; padding: 2px 4px; border-radius: 4px; font-size: 11px; color: #334155; }}
</style>
</head>
<body>
<div class="container">
    <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
            <h1>AgentGuard — Software QA & Quality Gate Report</h1>
            <p style="color:#64748b; margin:0; font-size:13px;">Generated on {html.escape(report['generated_at'])} UTC</p>
        </div>
        <div>
            <span class="decision {'go' if gate.get('decision')=='GO' else 'no-go'}">
                RELEASE GATE: {html.escape(str(gate.get('decision', 'N/A')))}
            </span>
        </div>
    </div>

    <div class="meta-box">
        <div><strong>Application:</strong> {html.escape(str(app.get('name', 'N/A')))}</div>
        <div><strong>Type:</strong> {html.escape(str(app.get('app_type', 'N/A')))}</div>
        <div><strong>Base URL:</strong> <code>{html.escape(str(app.get('base_url', 'N/A')))}</code></div>
    </div>

    <div class="grid">
        <div class="card"><span>Total Tests</span><strong>{summary.get('total_tests', 0)}</strong></div>
        <div class="card"><span>Passed</span><strong style="color:#16a34a;">{summary.get('passed', 0)}</strong></div>
        <div class="card"><span>Failed / Error</span><strong style="color:#dc2626;">{summary.get('failed', 0)}</strong></div>
        <div class="card"><span>Coverage</span><strong>{summary.get('coverage_percent') if summary.get('coverage_percent') is not None else 'N/A'}%</strong></div>
    </div>

    <h2>Release Gate Evaluation</h2>
    <ul class="blockers">{blocker_html}</ul>

    <h2>Test Execution Evidence</h2>
    <table>
        <thead>
            <tr><th>Test ID</th><th>Name / Category</th><th>Status</th><th>Expected</th><th>Actual</th><th>Evidence</th></tr>
        </thead>
        <tbody>
            {test_rows}
        </tbody>
    </table>

    <h2>Defect Log</h2>
    <table>
        <thead>
            <tr><th>Defect ID</th><th>Severity</th><th>Test Case</th><th>Status</th><th>Evidence / Reproduction</th></tr>
        </thead>
        <tbody>
            {defect_rows}
        </tbody>
    </table>

    <h2>Security Baseline Scan</h2>
    <div>{scan_html}</div>

    <footer style="margin-top:30px; font-size:11px; color:#94a3b8; text-align:center; border-top:1px solid #e2e8f0; padding-top:14px;">
        AgentGuard Quality Gate Audit · Evidence-based software testing workbench · Non-destructive assessment
    </footer>
</div>
</body>
</html>"""

    html_path.write_text(page, encoding="utf-8")
    return str(json_path), str(html_path)
