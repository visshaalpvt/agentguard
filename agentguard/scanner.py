"""Non-destructive HTTP baseline security scanner.
Performs safe passive checks: security headers, server disclosure, TLS status, and safe input baseline validation.
Never performs destructive exploitation or brute force.
"""
from urllib.parse import urlparse
import time
import requests
import ssl
import socket
from .security import validate_target_url

SECURITY_HEADERS = {
    "Content-Security-Policy": "Content Security Policy (helps prevent XSS and code injection)",
    "X-Content-Type-Options": "MIME sniffing protection (prevents MIME type confusion attacks)",
    "Referrer-Policy": "Referrer policy (protects sensitive information in HTTP Referer)",
    "Strict-Transport-Security": "HSTS (enforces secure HTTPS connections)",
    "Permissions-Policy": "Permissions policy (restricts browser APIs and features)",
    "X-Frame-Options": "Clickjacking protection (restricts frame embedding)"
}

SAFE_PROBES = [
    {"type": "Malformed Input Handling", "param": "'\"<script>/*", "desc": "Tests whether server handles punctuation gracefully without 500 or stack trace leaks."},
    {"type": "Type Boundary Probe", "param": "99999999999999999999", "desc": "Tests numerical boundary tolerance."},
]


def check_tls_configuration(hostname: str, port: int = 443) -> dict:
    """Safely inspects TLS certificate and protocol version for https endpoints."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
                return {
                    "valid": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", []))
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def scan_http_target(target: str, auth_confirmed: bool = False, timeout: int = 5) -> dict:
    """
    Executes safe, non-destructive baseline security checks on an authorized target.
    Requires explicit authorization confirmation for external targets.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target URL cannot be empty.")

    target = target.strip()
    parsed = urlparse(target)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target must be a valid http:// or https:// URL.")

    host = parsed.hostname.lower()
    is_local = host in ("localhost", "127.0.0.1", "::1")

    # SSRF verification
    is_valid_url, err_msg = validate_target_url(target, allow_localhost=True)
    if not is_valid_url:
        raise ValueError(f"Security validation blocked scan: {err_msg}")

    # External authorization requirement
    if not is_local and not auth_confirmed:
        raise PermissionError(
            f"Scanning external target '{target}' requires explicit confirmation that you own or have permission to test this host."
        )

    started = time.perf_counter()
    findings = []

    # 1. Primary baseline request
    try:
        response = requests.get(target, timeout=timeout, allow_redirects=False, headers={"User-Agent": "AgentGuard-SecurityScanner/2.0"})
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Could not reach target '{target}': {e}")

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    # 2. Check Security Headers
    for header, label in SECURITY_HEADERS.items():
        if header not in response.headers:
            sev = "Medium"
            if header in ("Content-Security-Policy", "X-Content-Type-Options"):
                sev = "Medium"
            elif header == "Strict-Transport-Security" and parsed.scheme == "http":
                sev = "Low"
            else:
                sev = "Low"
            findings.append({
                "severity": sev,
                "title": f"Missing {header}",
                "detail": f"Response does not include {header} ({label})."
            })

    # 3. Server Banner Disclosure
    server_header = response.headers.get("Server")
    if server_header:
        findings.append({
            "severity": "Low",
            "title": "Server banner disclosed",
            "detail": f"Server header discloses technology stack: '{server_header}'."
        })

    x_powered_by = response.headers.get("X-Powered-By")
    if x_powered_by:
        findings.append({
            "severity": "Medium",
            "title": "X-Powered-By header disclosed",
            "detail": f"X-Powered-By discloses runtime framework: '{x_powered_by}'."
        })

    # 4. TLS Check if HTTPS
    tls_info = None
    if parsed.scheme.lower() == "https":
        tls_res = check_tls_configuration(parsed.hostname, parsed.port or 443)
        tls_info = tls_res
        if not tls_res.get("valid"):
            findings.append({
                "severity": "High",
                "title": "TLS validation failure",
                "detail": f"TLS handshake issue: {tls_res.get('error')}"
            })
        elif tls_res.get("version") in ("TLSv1", "TLSv1.1"):
            findings.append({
                "severity": "High",
                "title": "Outdated TLS protocol",
                "detail": f"Host uses legacy protocol {tls_res.get('version')}. TLS 1.2 or 1.3 is recommended."
            })

    # 5. Safe Input Boundary Probe (non-destructive)
    for probe in SAFE_PROBES:
        try:
            probe_url = target + ("&" if "?" in target else "?") + f"__probe={probe['param']}"
            p_resp = requests.get(probe_url, timeout=timeout, headers={"User-Agent": "AgentGuard-SecurityScanner/2.0"})
            resp_lower = p_resp.text.lower()
            # Check for stack trace leakage
            if p_resp.status_code == 500 and any(kw in resp_lower for kw in ["traceback", "syntaxerror", "exception", "sqlite3."]):
                findings.append({
                    "severity": "High",
                    "title": f"Stack trace or error leak under {probe['type']}",
                    "detail": "Server returned unhandled 500 status containing debug/traceback information."
                })
        except Exception:
            pass

    return {
        "target": target,
        "status_code": response.status_code,
        "response_time_ms": elapsed_ms,
        "content_type": response.headers.get("Content-Type", ""),
        "findings": findings,
        "finding_count": len(findings),
        "tls_info": tls_info,
        "disclaimer": "Safe HTTP baseline checks only. Not a full penetration test or replacement for OWASP ZAP."
    }
