# Product development plan

Each round completes one feature or repair. Future items are planned, not implemented claims.

## Current round

continue-implementation

## Roadmap

### continue-implementation — Continue implementation and resolve known failures

Status: done

Acceptance:
- Run checks, fix failures, and implement the next planned feature
- Deterministic vulnerability scanner audits config, crypto, headers, and dependency manifests
- Deterministic 0-100 scoring with letter grades and ROI-prioritized remediation fixes
- React + Vite frontend dashboard with interactive audit, posture diff, ML benchmark, and audit trail
- End-to-end integration tests crossing real HTTP boundary with OIDC PKCE and RBAC authorization

Implementation: `backend/app/services/scanner.py`, `backend/app/services/scorer.py`, `backend/app/services/ml_eval.py`, `backend/app/services/llm_service.py`, `backend/app/api/posture.py`, `backend/app/api/auth.py`, `frontend/src/App.tsx`, `frontend/src/api/client.ts`, `frontend/src/components/ScanWorkflow.tsx`, `frontend/src/components/ScoreGauge.tsx`, `frontend/src/components/FindingsTable.tsx`, `frontend/src/components/FixesList.tsx`, `frontend/src/components/BenchmarkView.tsx`, `frontend/src/components/DiffWorkflow.tsx`, `frontend/src/components/AuditLogsView.tsx`

Tests: `backend/tests/test_scanner.py`, `backend/tests/test_scorer.py`, `backend/tests/test_auth.py`, `backend/tests/test_integration.py`, `frontend/src/__tests__/App.test.tsx`, `frontend/src/__tests__/ScoreGauge.test.tsx`, `frontend/src/__tests__/FindingsTable.test.tsx`

### ast-semantic-taint-analyzer — Abstract Syntax Tree Semantic Taint Analysis

Status: planned

Acceptance:
- Multi-step data flow tracking from untrusted HTTP request inputs to sensitive database and command sinks

### github-actions-posture-reporter — Automated Pull Request Security Posture PR Commenter

Status: planned

Acceptance:
- GitHub action action bot posting posture score deltas and regression alerts directly on pull requests

