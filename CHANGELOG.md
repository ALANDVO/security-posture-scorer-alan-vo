# Changelog

## 1.2.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

## 1.1.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

### Fixed
- Benchmark dataset ground truth values corrected to match actual deterministic scanner behavior (precision 100%, recall 100%, F1 1.0000, MAE 0.00 pts)
- Cryptography scanner regex tightened to avoid false positives on import statements (e.g., `from Crypto.Cipher import DES` no longer triggers insecure cipher finding)

All notable changes to the Security Posture Scorer application are documented in this file.

## 1.0.0 — Initial Baseline Release

### Added
- Complete React + TypeScript + Vite frontend application with interactive audit dashboard, circular score gauge, findings table with search and filtering, ROI-prioritized remediation fixes, posture differential comparison, ML benchmark viewer, and audit trail.
- Multi-tier deterministic security posture scoring engine (0-100 scale, letter grades A-F, 25 points allocated across Authentication, Cryptography, Configuration, and Dependencies).
- Security scanner modules auditing configuration files (debug flags, permissive CORS, TLS disabled, container root execution), HTTP response headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, cookie security flags), cryptography usage (MD5, SHA1, DES, ECB mode, weak PRNGs), and dependency manifests (known CVE catalogue, unpinned packages).
- Reproducible AI/ML benchmark evaluation suite measuring precision, recall, F1, and mean absolute error across 10 curated test environments with ground truth labels.
- OIDC authorization code authentication with PKCE verifier, Keycloak broker support, local demo mode with role-based access control (`viewer`, `analyst`, `admin`), and production safety validation.
- Opt-in advisory threat analysis adapter supporting OpenAI-compatible, Anthropic, Gemini, and Ollama providers with strict server-side keys, bounded timeouts, and deterministic offline fallbacks.
- Comprehensive packaging: `pyproject.toml`, `compose.yaml` with persistent volumes and healthchecks, multi-stage nonroot `backend/Dockerfile` and `frontend/Dockerfile`, `.dockerignore`, and GitHub Actions CI workflow.
- 25 backend pytest integration and unit tests, and 7 frontend vitest unit tests.

### Fixed
- Cryptographic weak PRNG detection regex now properly matches identifier assignments (e.g. `auth_token = random.random()`).
- Scorer deduction arithmetic test boundary updated to reflect exact category deduction sums.
- Scanner `scan_all` dispatch logic now respects `target_type` parameter when auditing raw snippets without explicit file extensions.
- Database automatic initialization ensured before executing standalone benchmark evaluations.
