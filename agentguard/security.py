"""Security validation, SSRF prevention, and sensitive data masking for AgentGuard."""
import ipaddress
import re
import socket
from urllib.parse import urlparse

BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.aws",
    "instance-data",
}

CLOUD_METADATA_IPS = {
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.169.250/32"),
}

LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "token",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "secret",
}


def validate_target_url(url: str, allow_localhost: bool = True) -> tuple[bool, str]:
    """
    Validates a URL against SSRF vulnerabilities.
    Returns (is_valid, error_message).
    """
    if not url or not isinstance(url, str):
        return False, "Target URL cannot be empty."

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' is not allowed. Only http:// and https:// are supported."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname or IP address."

    hostname_lower = hostname.lower()

    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Access to cloud metadata host '{hostname}' is strictly blocked."

    # Check IP resolution
    try:
        # Resolve hostname to IP addresses
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return False, f"Could not resolve host '{hostname}': {e}"

    for family, socktype, proto, canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        # Check metadata IPs
        for meta_net in CLOUD_METADATA_IPS:
            if ip in meta_net:
                return False, f"Target IP {ip_str} matches prohibited cloud metadata endpoint."

        # Check link-local
        for net in LINK_LOCAL_NETWORKS:
            if ip in net:
                return False, f"Target IP {ip_str} matches prohibited link-local address range."

        # Check loopback
        if ip.is_loopback:
            if not allow_localhost:
                return False, f"Localhost/loopback target {ip_str} is not permitted for external scans."

    return True, ""


def mask_sensitive_headers(headers: dict) -> dict:
    """Masks authorization tokens, API keys, and cookies."""
    if not headers or not isinstance(headers, dict):
        return {}
    masked = {}
    for k, v in headers.items():
        if str(k).lower() in SENSITIVE_HEADER_KEYS:
            masked[k] = "[REDACTED]"
        else:
            masked[k] = v
    return masked


def mask_sensitive_in_evidence(text: str) -> str:
    """Masks authorization header tokens in raw evidence strings."""
    if not isinstance(text, str):
        return text
    # Pattern for bearer tokens or basic auth
    text = re.sub(r"(?i)(authorization['\"]?\s*:\s*['\"]?)(bearer\s+[a-zA-Z0-9_\-\.]+)(['\"]?)", r"\1[REDACTED]\3", text)
    text = re.sub(r"(?i)(api[_\-]?key['\"]?\s*:\s*['\"]?)([a-zA-Z0-9_\-\.]+)(['\"]?)", r"\1[REDACTED]\3", text)
    return text
