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
def test_scan_taint_analysis_sql_injection():
    """Test SQL injection taint flow from Flask request to cursor.execute."""
    code = """
from flask import request
import sqlite3

conn = sqlite3.connect('test.db')
user_input = request.args.get('user_id')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users WHERE id = ' + user_input)
"""
    findings = scanner.scan_taint_analysis("app.py", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    assert len(taint_findings) >= 2  # source->var and var->sink
    flow_ids = [f.id for f in taint_findings]
    # Should detect flow from request.args.get to user_input
    assert any("request.args.get" in fid and "user_input" in fid for fid in flow_ids)
    # Should detect flow from user_input to cursor.execute
    assert any("user_input" in fid and "cursor.execute" in fid for fid in flow_ids)
    assert any(f.severity == "CRITICAL" for f in taint_findings)


def test_scan_taint_analysis_command_injection():
    """Test command injection taint flow to subprocess.run."""
    code = """
from flask import request
import subprocess

user_input = request.args.get('cmd')
subprocess.run(user_input, shell=True)
"""
    findings = scanner.scan_taint_analysis("cmd.py", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    assert len(taint_findings) >= 2  # source->var and var->sink
    flow_ids = [f.id for f in taint_findings]
    assert any("request.args.get" in fid and "user_input" in fid for fid in flow_ids)
    assert any("user_input" in fid and "subprocess.run" in fid for fid in flow_ids)
    assert any(f.severity == "HIGH" for f in taint_findings)


def test_scan_taint_analysis_os_system_injection():
    """Test os.system command injection."""
    code = """
from flask import request
import os

user_input = request.args.get('cmd')
os.system('echo ' + user_input)
"""
    findings = scanner.scan_taint_analysis("sys.py", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    assert len(taint_findings) >= 2  # source->var and var->sink
    flow_ids = [f.id for f in taint_findings]
    assert any("request.args.get" in fid and "user_input" in fid for fid in flow_ids)
    assert any("user_input" in fid and "os.system" in fid for fid in flow_ids)
    assert any(f.severity == "CRITICAL" for f in taint_findings)


def test_scan_taint_analysis_eval_injection():
    """Test eval code injection."""
    code = """
from flask import request

user_input = request.args.get('code')
eval(user_input)
"""
    findings = scanner.scan_taint_analysis("eval.py", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    assert len(taint_findings) >= 2  # source->var and var->sink
    flow_ids = [f.id for f in taint_findings]
    assert any("request.args.get" in fid and "user_input" in fid for fid in flow_ids)
    assert any("user_input" in fid and "eval" in fid for fid in flow_ids)
    assert any(f.severity == "CRITICAL" for f in taint_findings)


def test_scan_taint_analysis_path_traversal():
    """Test path traversal via open()."""
    code = """
from flask import request

filename = request.args.get('file')
with open(filename) as f:
    content = f.read()
"""
    findings = scanner.scan_taint_analysis("path.py", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    assert len(taint_findings) >= 2  # source->var and var->sink
    flow_ids = [f.id for f in taint_findings]
    assert any("request.args.get" in fid and "filename" in fid for fid in flow_ids)
    assert any("filename" in fid and "open" in fid for fid in flow_ids)


def test_scan_taint_analysis_fstring_sql_injection():
    """Test SQL injection via f-string."""
    code = """
from flask import request
import sqlite3

conn = sqlite3.connect('test.db')
user_input = request.args.get('user_id')
conn.execute(f'SELECT * FROM users WHERE id = {user_input}')
"""
    findings = scanner.scan_taint_analysis("fstring.py", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    assert len(taint_findings) >= 2  # source->var and var->sink
    flow_ids = [f.id for f in taint_findings]
    assert any("request.args.get" in fid and "user_input" in fid for fid in flow_ids)
    assert any("user_input" in fid and "conn.execute" in fid for fid in flow_ids)
    assert any(f.severity == "CRITICAL" for f in taint_findings)


def test_scan_taint_analysis_django_request():
    """Test Django request.GET as taint source."""
    code = """
from django.http import HttpRequest

def view(request):
    user_input = request.GET.get('user_id')
    conn.execute('SELECT * FROM users WHERE id = ' + user_input)
"""
    findings = scanner.scan_taint_analysis("django_view.py", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    assert len(taint_findings) >= 2  # source->var and var->sink
    flow_ids = [f.id for f in taint_findings]
    assert any("request.GET.get" in fid and "user_input" in fid for fid in flow_ids)
    assert any("user_input" in fid and "conn.execute" in fid for fid in flow_ids)


def test_scan_taint_analysis_reassignment_clears_taint():
    """Test that reassignment to safe value clears taint."""
    code = """
from flask import request
import sqlite3

conn = sqlite3.connect('test.db')
user_input = request.args.get('user_id')
user_input = 'safe_value'  # reassignment clears taint
conn.execute('SELECT * FROM users WHERE id = ' + user_input)
"""
    findings = scanner.scan_taint_analysis("reassign.py", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    # Should only have source->variable flow, not variable->sink flow
    sink_flows = [f for f in taint_findings if "conn.execute" in f.id]
    assert len(sink_flows) == 0


def test_scan_taint_analysis_non_python_file():
    """Test that non-Python files return no findings."""
    code = "const userInput = request.queryParams.get('id');"
    findings = scanner.scan_taint_analysis("app.js", code)
    taint_findings = [f for f in findings if f.category == "taint-analysis"]
    assert len(taint_findings) == 0


def test_scan_taint_analysis_syntax_error():
    """Test that syntax errors don't crash the scanner."""
    code = "from flask import request\nuser_input = request.args.get('id'\n"  # missing closing paren
    findings = scanner.scan_taint_analysis("broken.py", code)
    # Should not raise, just return empty or partial findings
    assert isinstance(findings, list)
