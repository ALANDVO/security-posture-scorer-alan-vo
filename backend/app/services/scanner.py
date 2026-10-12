"""Deterministic security posture scanner auditing configuration, headers, crypto, and dependencies."""
import re
from typing import List, Dict, Optional, Any
from backend.app.models.schemas import Finding

# Curated CVE catalogue for common dependency manifests
KNOWN_DEP_CVES = {
    "requests": {"max_vulnerable": "2.31.0", "cve": "CVE-2023-32681", "desc": "Unintended leak of Proxy-Authorization header on redirect", "severity": "MEDIUM", "points": 6},
    "urllib3": {"max_vulnerable": "2.0.7", "cve": "CVE-2023-45803", "desc": "Cookie stripping failure during cross-origin redirect", "severity": "MEDIUM", "points": 6},
    "cryptography": {"max_vulnerable": "41.0.6", "cve": "CVE-2023-49083", "desc": "Null pointer dereference parsing PKCS7 certificates", "severity": "HIGH", "points": 8},
    "django": {"max_vulnerable": "4.2.8", "cve": "CVE-2023-46695", "desc": "Potential denial of service via catastrophic regex in URL parsing", "severity": "HIGH", "points": 9},
    "flask": {"max_vulnerable": "2.2.5", "cve": "CVE-2023-30861", "desc": "Session disclosure in shared worker environments", "severity": "MEDIUM", "points": 6},
    "jsonwebtoken": {"max_vulnerable": "9.0.0", "cve": "CVE-2022-23529", "desc": "Insecure key object validation leading to arbitrary code execution", "severity": "CRITICAL", "points": 14},
    "axios": {"max_vulnerable": "1.6.0", "cve": "CVE-2023-45857", "desc": "Cross-site request forgery and header leakage in SSR", "severity": "MEDIUM", "points": 5},
    "lodash": {"max_vulnerable": "4.17.21", "cve": "CVE-2021-23337", "desc": "Command injection and prototype pollution via template function", "severity": "HIGH", "points": 9},
    "express": {"max_vulnerable": "4.19.2", "cve": "CVE-2024-29041", "desc": "Open redirect vulnerability via malformed path headers", "severity": "MEDIUM", "points": 6},
}


def _redact_token(match_text: str) -> str:
    """Safe token redaction replacing token character literals with masks."""
    parts = re.split(r'([=:\s"\']+)', match_text, maxsplit=1)
    if len(parts) >= 3:
        return f"{parts[0]}{parts[1]}[REDACTED_SECRET_MASKED]"
    return "[REDACTED_SECRET]"


class SecurityScanner:
    """Deterministic security audit scanner with zero external dependencies."""

    def scan_all(
        self,
        target_name: str,
        target_type: str,
        content: Optional[str] = None,
        file_tree: Optional[Dict[str, str]] = None
    ) -> List[Finding]:
        """Perform comprehensive deterministic audit across all applicable categories."""
        findings: List[Finding] = []

        files_to_scan: Dict[str, str] = {}
        if file_tree:
            files_to_scan.update(file_tree)
        if content:
            files_to_scan[target_name] = content

        for filename, file_content in files_to_scan.items():
            lower_name = filename.lower()
            # 1. Config and container scanning
            if any(lower_name.endswith(ext) for ext in (".json", ".yaml", ".yml", ".toml", ".ini", ".env", "dockerfile")) or "config" in lower_name:
                findings.extend(self.scan_configuration(filename, file_content))

            # 2. Source code crypto & secrets scanning
            if any(lower_name.endswith(ext) for ext in (".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php")):
                findings.extend(self.scan_cryptography(filename, file_content))
                findings.extend(self.scan_secrets(filename, file_content))

            # 3. HTTP Header scans if target is headers or response
            if target_type == "headers" or "header" in lower_name or lower_name.endswith(".http"):
                findings.extend(self.scan_http_headers(file_content))

            # 4. Dependency manifests
            if any(manifest in lower_name for manifest in ("requirements.txt", "package.json", "go.mod", "cargo.toml")):
                findings.extend(self.scan_dependencies(filename, file_content))

        # If pure raw content was provided with specific target_type
        if content and not file_tree:
            if target_type == "headers":
                findings.extend(self.scan_http_headers(content))
            elif target_type == "manifest":
                findings.extend(self.scan_dependencies(target_name, content))

        # De-duplicate findings by unique ID
        unique_findings: Dict[str, Finding] = {}
        for f in findings:
            if f.id not in unique_findings:
                unique_findings[f.id] = f

        return list(unique_findings.values())

    def scan_configuration(self, filename: str, content: str) -> List[Finding]:
        """Audit configuration files for insecure defaults and debug flags."""
        findings: List[Finding] = []

        # Debug mode enabled
        if re.search(r'(?i)(["\']?debug["\']?\s*[:=]\s*(true|1|"true")|DEBUG\s*=\s*True)', content):
            findings.append(Finding(
                id=f"cfg-debug-enabled-{filename}",
                title="Debug mode enabled in production configuration",
                category="configuration",
                severity="HIGH",
                description="Application has debug mode enabled, exposing stack traces and diagnostic endpoints.",
                file_path=filename,
                evidence="debug = true / 1",
                deduction_points=10,
                remediation="Ensure DEBUG is disabled (debug=False or debug: false) in production environments."
            ))

        # CORS allow all origins
        if re.search(r'(?i)(["\']?allow_origins["\']?\s*[:=]\s*\[?\s*["\']\*["\']|access-control-allow-origin\s*:\s*\*)', content):
            findings.append(Finding(
                id=f"cfg-cors-wildcard-{filename}",
                title="Overly permissive CORS wildcard (allow_origins: *)",
                category="configuration",
                severity="HIGH",
                description="CORS is configured with wildcard origin '*', allowing unauthorized third-party sites to read responses.",
                file_path=filename,
                evidence="allow_origins: ['*']",
                deduction_points=10,
                remediation="Restrict CORS origins to explicit, verified domain names."
            ))

        # TLS / SSL disabled
        if re.search(r'(?i)(["\']?ssl["\']?\s*[:=]\s*(false|0|"false")|["\']?tls["\']?\s*[:=]\s*(false|0)|require_ssl\s*=\s*False)', content):
            findings.append(Finding(
                id=f"cfg-tls-disabled-{filename}",
                title="TLS/SSL transport encryption explicitly disabled",
                category="configuration",
                severity="CRITICAL",
                description="Transport Layer Security is disabled in configuration, exposing traffic to man-in-the-middle eavesdropping.",
                file_path=filename,
                evidence="ssl/tls: false",
                deduction_points=15,
                remediation="Enforce TLS/HTTPS across all public and internal communications."
            ))

        # Dockerfile running as root
        if "dockerfile" in filename.lower():
            if re.search(r'(?i)^USER\s+root', content, re.MULTILINE) or not re.search(r'(?i)^USER\s+\w+', content, re.MULTILINE):
                findings.append(Finding(
                    id=f"cfg-docker-root-{filename}",
                    title="Container configured to execute as root user",
                    category="configuration",
                    severity="MEDIUM",
                    description="Dockerfile does not declare a non-root USER instruction or explicitly runs as root.",
                    file_path=filename,
                    evidence="Missing non-root USER or USER root present",
                    deduction_points=6,
                    remediation="Create a dedicated system user/group (e.g. appuser) and add 'USER appuser' before entrypoint."
                ))

        return findings

    def scan_http_headers(self, headers_text: str) -> List[Finding]:
        """Audit HTTP security headers and cookie flags."""
        findings: List[Finding] = []
        normalized = headers_text.lower()

        # Content-Security-Policy
        if "content-security-policy" not in normalized:
            findings.append(Finding(
                id="hdr-missing-csp",
                title="Missing Content-Security-Policy (CSP) header",
                category="configuration",
                severity="HIGH",
                description="No Content-Security-Policy header detected; browser has no baseline defense against Cross-Site Scripting (XSS).",
                deduction_points=8,
                remediation="Configure a restrictive Content-Security-Policy header (e.g., default-src 'self'; script-src 'self')."
            ))
        elif "'unsafe-inline'" in normalized and "'nonce-" not in normalized:
            findings.append(Finding(
                id="hdr-weak-csp-inline",
                title="Content-Security-Policy allows 'unsafe-inline' without nonce",
                category="configuration",
                severity="MEDIUM",
                description="CSP allows unsafe inline scripts without cryptographic nonces or hashes.",
                deduction_points=5,
                remediation="Refactor inline scripts to external modules or protect them with cryptographic nonces."
            ))

        # Strict-Transport-Security (HSTS)
        if "strict-transport-security" not in normalized:
            findings.append(Finding(
                id="hdr-missing-hsts",
                title="Missing HTTP Strict-Transport-Security (HSTS) header",
                category="configuration",
                severity="HIGH",
                description="Strict-Transport-Security is not present, allowing protocol downgrade attacks and cookie interception.",
                deduction_points=8,
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
            ))

        # X-Content-Type-Options
        if "x-content-type-options" not in normalized or "nosniff" not in normalized:
            findings.append(Finding(
                id="hdr-missing-nosniff",
                title="Missing X-Content-Type-Options: nosniff header",
                category="configuration",
                severity="MEDIUM",
                description="Browser MIME-type sniffing is not disabled, exposing users to executable content confusion attacks.",
                deduction_points=4,
                remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses."
            ))

        # X-Frame-Options or frame-ancestors
        if "x-frame-options" not in normalized and "frame-ancestors" not in normalized:
            findings.append(Finding(
                id="hdr-missing-frame-protection",
                title="Missing Clickjacking defense (X-Frame-Options / frame-ancestors)",
                category="configuration",
                severity="MEDIUM",
                description="Application can be embedded inside external iframes, leaving users vulnerable to clickjacking attacks.",
                deduction_points=5,
                remediation="Set 'X-Frame-Options: DENY' or configure CSP 'frame-ancestors 'none''."
            ))

        # Cookie security flags
        if "set-cookie" in normalized:
            if "httponly" not in normalized:
                findings.append(Finding(
                    id="hdr-cookie-missing-httponly",
                    title="Set-Cookie header missing HttpOnly flag",
                    category="authentication",
                    severity="HIGH",
                    description="Session cookies lack HttpOnly flag, allowing client-side JavaScript to read authentication tokens.",
                    deduction_points=8,
                    remediation="Add the HttpOnly attribute to all sensitive session and authentication cookies."
                ))
            if "secure" not in normalized:
                findings.append(Finding(
                    id="hdr-cookie-missing-secure",
                    title="Set-Cookie header missing Secure flag",
                    category="authentication",
                    severity="HIGH",
                    description="Session cookies lack Secure flag, permitting transmission over unencrypted HTTP connections.",
                    deduction_points=8,
                    remediation="Add the Secure attribute so cookies are only sent over TLS/HTTPS."
                ))
            if "samesite" not in normalized:
                findings.append(Finding(
                    id="hdr-cookie-missing-samesite",
                    title="Set-Cookie header missing SameSite attribute",
                    category="authentication",
                    severity="MEDIUM",
                    description="Cookies lack SameSite policy, leaving sessions exposed to Cross-Site Request Forgery (CSRF).",
                    deduction_points=5,
                    remediation="Set SameSite=Lax or SameSite=Strict on all application cookies."
                ))

        return findings

    def scan_cryptography(self, filename: str, content: str) -> List[Finding]:
        """Audit source code for weak ciphers, broken hash algorithms, and flawed PRNGs."""
        findings: List[Finding] = []

        # Broken hash algorithms: MD5 or SHA1
        for match in re.finditer(r'(?i)\b(md5|sha1)\b(?:\s*\(|\.new|\.createHash|\.digest)', content):
            line_no = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                id=f"crypto-weak-hash-{filename}-{line_no}",
                title=f"Broken cryptographic hash algorithm detected ({match.group(1).upper()})",
                category="cryptography",
                severity="HIGH",
                description=f"Algorithm {match.group(1).upper()} is collision-vulnerable and must not be used for cryptographic integrity or signatures.",
                file_path=filename,
                line_number=line_no,
                evidence=match.group(0),
                deduction_points=10,
                remediation="Upgrade to SHA-256 (SHA2), SHA-3, or BLAKE2."
            ))

        # Obsolete ciphers & ECB mode: DES, 3DES, RC4, Blowfish, AES-ECB
        for match in re.finditer(r'(?i)\b(DES|3DES|Blowfish|RC4|ARC4|MODE_ECB|AES\.MODE_ECB|Cipher\.getInstance\s*\(\s*["\']AES/ECB)\b', content):
            line_no = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                id=f"crypto-insecure-cipher-{filename}-{line_no}",
                title=f"Insecure cipher algorithm or ECB mode ({match.group(1)})",
                category="cryptography",
                severity="CRITICAL",
                description="ECB mode leaks plaintext data patterns, and legacy ciphers (DES/RC4) are trivially breakable.",
                file_path=filename,
                line_number=line_no,
                evidence=match.group(0),
                deduction_points=15,
                remediation="Migrate to AES-GCM or ChaCha20-Poly1305 with authenticated encryption (AEAD)."
            ))

        # Insecure PRNG in security context
        for match in re.finditer(r'(?i)\b(random\.random\(\)|random\.randint\(|Math\.random\(\))\s*(?:.*?(?:token|secret|key|salt|iv|nonce))', content):
            line_no = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                id=f"crypto-pseudo-random-{filename}-{line_no}",
                title="Cryptographically weak pseudo-random number generator used for sensitive token",
                category="cryptography",
                severity="MEDIUM",
                description="Non-cryptographic PRNGs are predictable and should never generate secrets, tokens, or salts.",
                file_path=filename,
                line_number=line_no,
                evidence=match.group(0),
                deduction_points=7,
                remediation="Use secrets (Python: secrets.token_bytes or secrets.token_urlsafe) or crypto.getRandomValues()."
            ))

        return findings

    def scan_secrets(self, filename: str, content: str) -> List[Finding]:
        """Scan source files for hardcoded credentials and secrets with strict redaction."""
        findings: List[Finding] = []
        secret_patterns = [
            (r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|private[_-]?key|password)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{12,})["\']', "Hardcoded secret credential or API key"),
            (r'(?i)(bearer\s+[A-Za-z0-9\-_]{20,})', "Hardcoded Bearer authentication token"),
        ]

        for pattern, desc in secret_patterns:
            for match in re.finditer(pattern, content):
                # Ignore placeholder strings
                matched_val = match.group(0)
                if any(x in matched_val.lower() for x in ("your-api-key", "placeholder", "changeme", "example", "redacted", "test-secret")):
                    continue
                line_no = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    id=f"sec-hardcoded-{filename}-{line_no}",
                    title=desc,
                    category="authentication",
                    severity="CRITICAL",
                    description="Plaintext credentials found in source code, risking exposure via source control or logs.",
                    file_path=filename,
                    line_number=line_no,
                    evidence=_redact_token(matched_val),
                    deduction_points=15,
                    remediation="Store credentials in environment variables or a secret vault; never commit secrets to code."
                ))

        return findings

    def scan_dependencies(self, filename: str, content: str) -> List[Finding]:
        """Scan dependency manifests for known CVEs and unpinned packages."""
        findings: List[Finding] = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Python requirements.txt parsing
            if "requirements" in filename.lower():
                parts = re.split(r'(==|>=|<=|>|<|~=)', line)
                if len(parts) >= 3:
                    pkg_name = parts[0].strip().lower()
                    op = parts[1].strip()
                    version = parts[2].split(";")[0].strip()

                    # Check CVE database
                    if pkg_name in KNOWN_DEP_CVES:
                        info = KNOWN_DEP_CVES[pkg_name]
                        # If operator indicates vulnerable version or range
                        if op in ("<=", "<", "==") and version <= info["max_vulnerable"]:
                            findings.append(Finding(
                                id=f"dep-{pkg_name}-{info['cve']}",
                                title=f"Vulnerable dependency: {pkg_name} ({info['cve']})",
                                category="dependencies",
                                severity=info["severity"],
                                description=f"{info['desc']} in {pkg_name} <= {info['max_vulnerable']}.",
                                file_path=filename,
                                evidence=f"{pkg_name}{op}{version}",
                                deduction_points=info["points"],
                                remediation=f"Upgrade {pkg_name} to a patched release > {info['max_vulnerable']}."
                            ))

            # Unpinned dependency check
            if line.endswith("=*") or ">=0." in line:
                findings.append(Finding(
                    id=f"dep-unpinned-{line[:15]}",
                    title="Unpinned dependency version specification",
                    category="dependencies",
                    severity="LOW",
                    description="Dependency does not specify a pinned version, risking unpredictable upstream supply-chain updates.",
                    file_path=filename,
                    evidence=line,
                    deduction_points=3,
                    remediation="Pin dependency to an exact immutable version and verify hashes."
                ))

        return findings


scanner = SecurityScanner()
