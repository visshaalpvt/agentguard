import pytest
from agentguard.security import validate_target_url, mask_sensitive_headers, mask_sensitive_in_evidence
from agentguard.scanner import scan_http_target

def test_ssrf_blocks_cloud_metadata():
    is_valid, msg = validate_target_url("http://169.254.169.254/latest/meta-data")
    assert not is_valid
    assert "metadata" in msg.lower() or "blocked" in msg.lower()

def test_ssrf_blocks_metadata_hostname():
    is_valid, msg = validate_target_url("http://metadata.google.internal/computeMetadata/v1/")
    assert not is_valid
    assert "cloud metadata" in msg.lower() or "blocked" in msg.lower()

def test_ssrf_blocks_unsupported_schemes():
    is_valid, msg = validate_target_url("file:///etc/passwd")
    assert not is_valid
    assert "scheme" in msg.lower()

    is_valid, msg = validate_target_url("ftp://ftp.example.com/test")
    assert not is_valid
    assert "scheme" in msg.lower()

def test_sensitive_header_masking():
    headers = {
        "Authorization": "Bearer super_secret_jwt_token_12345",
        "X-Api-Key": "my-secret-key-abc",
        "Content-Type": "application/json",
        "Accept": "text/html"
    }
    masked = mask_sensitive_headers(headers)
    assert masked["Authorization"] == "[REDACTED]"
    assert masked["X-Api-Key"] == "[REDACTED]"
    assert masked["Content-Type"] == "application/json"

def test_sensitive_evidence_masking():
    evidence = "Status=200; Headers={'Authorization': 'Bearer secret_token_xyz'}; Done."
    sanitized = mask_sensitive_in_evidence(evidence)
    assert "secret_token_xyz" not in sanitized
    assert "[REDACTED]" in sanitized

def test_scanner_rejects_unconfirmed_external_target():
    with pytest.raises(PermissionError):
        scan_http_target("https://example.com", auth_confirmed=False)
