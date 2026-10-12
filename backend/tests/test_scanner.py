"""Tests for deterministic security scanner rules and pattern detection."""
import pytest
from backend.app.services.scanner import scanner


def test_scan_configuration_debug_and_cors():
    content = '{"debug": true, "allow_origins": ["*"]}'
    findings = scanner.scan_configuration("config.json", content)
    finding_ids = [f.id for f in findings]
    assert any("debug" in fid for fid in finding_ids)
    assert any("cors" in fid for fid in finding_ids)
    assert any(f.severity == "HIGH" for f in findings)


def test_scan_configuration_tls_disabled():
    content = "ssl: false\ntls: 0"
    findings = scanner.scan_configuration("settings.yaml", content)
    assert any("tls-disabled" in f.id for f in findings)
    assert any(f.deduction_points == 15 for f in findings)


def test_scan_dockerfile_root_user():
    content = "FROM python:3.11-slim\nUSER root\nCMD [\"python\", \"app.py\"]"
    findings = scanner.scan_configuration("Dockerfile", content)
    assert any("docker-root" in f.id for f in findings)


def test_scan_http_headers_missing_security_headers():
    raw_headers = "HTTP/1.1 200 OK\nContent-Type: text/html\nServer: Apache"
    findings = scanner.scan_http_headers(raw_headers)
    ids = [f.id for f in findings]
    assert "hdr-missing-csp" in ids
    assert "hdr-missing-hsts" in ids
    assert "hdr-missing-nosniff" in ids
    assert "hdr-missing-frame-protection" in ids


def test_scan_http_headers_cookie_flags():
    raw_headers = "Set-Cookie: session_id=12345; Path=/"
    findings = scanner.scan_http_headers(raw_headers)
    ids = [f.id for f in findings]
    assert "hdr-cookie-missing-httponly" in ids
    assert "hdr-cookie-missing-secure" in ids
    assert "hdr-cookie-missing-samesite" in ids


def test_scan_cryptography_weak_hashes_and_ciphers():
    code = """
import hashlib
from Crypto.Cipher import DES
h = hashlib.md5(b"test").digest()
cipher = DES.new(b"12345678", DES.MODE_ECB)
"""
    findings = scanner.scan_cryptography("crypto.py", code)
    assert any("crypto-weak-hash" in f.id for f in findings)
    assert any("crypto-insecure-cipher" in f.id for f in findings)


def test_scan_cryptography_weak_prng():
    code = "import random\nauth_token = random.random()"
    findings = scanner.scan_cryptography("token.py", code)
    assert any("crypto-pseudo-random" in f.id for f in findings)


def test_scan_dependencies_known_cves():
    manifest = "requests==2.28.0\nurllib3==1.26.5\nfastapi==0.110.0"
    findings = scanner.scan_dependencies("requirements.txt", manifest)
    cves = [f.id for f in findings]
    assert any("dep-requests" in cid for cid in cves)
    assert any("dep-urllib3" in cid for cid in cves)


def test_scan_dependencies_unpinned():
    manifest = "requests>=0.1\nflask=*"
    findings = scanner.scan_dependencies("requirements.txt", manifest)
    assert any("unpinned" in f.id for f in findings)
