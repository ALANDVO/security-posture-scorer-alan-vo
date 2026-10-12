"""Security posture scoring, audit, advisory, and comparison endpoints."""
import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, status, Depends, Query
from backend.app.core.security import TokenPayload, get_current_user, require_role
from backend.app.core.database import db, get_utc_now
from backend.app.services.scanner import scanner
from backend.app.services.scorer import scorer
from backend.app.services.llm_service import llm_service
from backend.app.services.audit import audit_service
from backend.app.services.ml_eval import run_posture_evaluation
from backend.app.models.schemas import (
    ScanSubmission,
    ScanResponse,
    ScanDiffRequest,
    ScanDiffResponse,
    HeaderAuditRequest,
    CryptoAuditRequest,
    DepsAuditRequest,
    BenchmarkResult,
    AuditLogEntry,
    Finding,
    LLMAdvisory
)

router = APIRouter(prefix="/api", tags=["posture"])


@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    submission: ScanSubmission,
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Execute deterministic security scan and score posture."""
    scan_id = str(uuid.uuid4())
    findings = scanner.scan_all(
        target_name=submission.target_name,
        target_type=submission.target_type,
        content=submission.content,
        file_tree=submission.file_tree
    )

    score, grade, category_scores, deductions, fixes, summary = scorer.compute_score(findings)

    scan_record = {
        "id": scan_id,
        "target_name": submission.target_name,
        "target_type": submission.target_type,
        "overall_score": score,
        "grade": grade,
        "category_scores": category_scores,
        "findings": [f.model_dump() for f in findings],
        "deductions": [d.model_dump() for d in deductions],
        "fixes": [fx.model_dump() for fx in fixes],
        "summary": summary,
        "llm_advisory": None,
        "created_at": get_utc_now(),
        "created_by": user.email,
        "status": "completed"
    }

    db.save_scan(scan_record)
    audit_service.log_event(
        event_type="SCAN_CREATED",
        actor=user.email,
        resource_id=scan_id,
        details={"score": score, "target": submission.target_name, "findings_count": len(findings)}
    )

    return ScanResponse(**scan_record)


@router.get("/scans")
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    target: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Retrieve paginated scan history with optional target and score filters."""
    scans, total = db.list_scans(
        skip=skip,
        limit=limit,
        target_filter=target,
        min_score=min_score,
        max_score=max_score
    )
    return {
        "items": scans,
        "total": total,
        "skip": skip,
        "limit": limit
    }


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan_detail(
    scan_id: str,
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Retrieve detailed scan results, deductions, and fix recommendations."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return ScanResponse(**scan)


@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    user: TokenPayload = Depends(require_role(["admin"]))
):
    """Delete a scan record (Admin role required)."""
    success = db.delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    audit_service.log_event(
        event_type="SCAN_DELETED",
        actor=user.email,
        resource_id=scan_id,
        details={"deleted_by": user.email}
    )
    return {"message": "Scan deleted successfully", "scan_id": scan_id}


@router.post("/scans/{scan_id}/advise", response_model=ScanResponse)
async def request_scan_advisory(
    scan_id: str,
    user: TokenPayload = Depends(require_role(["analyst", "admin"]))
):
    """Generate advisory threat analysis using multi-provider LLM adapter."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    findings = [Finding(**f) for f in scan["findings"]]
    advisory: LLMAdvisory = llm_service.generate_advisory(
        target_name=scan["target_name"],
        overall_score=scan["overall_score"],
        grade=scan["grade"],
        findings=findings
    )

    db.update_scan_advisory(scan_id, advisory.model_dump())
    audit_service.log_event(
        event_type="SCAN_ADVISED",
        actor=user.email,
        resource_id=scan_id,
        details={"provider": advisory.provider, "is_fallback": advisory.is_fallback}
    )

    updated_scan = db.get_scan(scan_id)
    return ScanResponse(**updated_scan)


@router.post("/scans/diff", response_model=ScanDiffResponse)
async def compare_scans(
    diff_req: ScanDiffRequest,
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Compare posture delta between two historical scans."""
    before_scan = db.get_scan(diff_req.before_scan_id)
    after_scan = db.get_scan(diff_req.after_scan_id)

    if not before_scan or not after_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both scan IDs not found for comparison"
        )

    before_findings = {f["id"]: Finding(**f) for f in before_scan["findings"]}
    after_findings = {f["id"]: Finding(**f) for f in after_scan["findings"]}

    resolved = [f for f_id, f in before_findings.items() if f_id not in after_findings]
    regressions = [f for f_id, f in after_findings.items() if f_id not in before_findings]

    delta = after_scan["overall_score"] - before_scan["overall_score"]
    if delta > 0:
        trend = "IMPROVED"
        summary_text = f"Security posture improved by +{delta} points ({before_scan['overall_score']} -> {after_scan['overall_score']}). Resolved {len(resolved)} findings."
    elif delta < 0:
        trend = "REGRESSED"
        summary_text = f"Security posture degraded by {delta} points ({before_scan['overall_score']} -> {after_scan['overall_score']}). Introduced {len(regressions)} new regressions."
    else:
        trend = "UNCHANGED"
        summary_text = f"Security posture score remained identical at {after_scan['overall_score']}/100."

    return ScanDiffResponse(
        before_id=diff_req.before_scan_id,
        after_id=diff_req.after_scan_id,
        score_before=before_scan["overall_score"],
        score_after=after_scan["overall_score"],
        score_delta=delta,
        resolved_findings=resolved,
        new_regressions=regressions,
        summary=summary_text,
        trend=trend
    )


@router.post("/audit/headers")
async def audit_headers_quick(
    req: HeaderAuditRequest,
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Audit HTTP security headers string."""
    findings = scanner.scan_http_headers(req.raw_headers)
    score, grade, cat_scores, deductions, fixes, summary = scorer.compute_score(findings)
    return {
        "score": score,
        "grade": grade,
        "findings": findings,
        "deductions": deductions,
        "fixes": fixes,
        "summary": summary
    }


@router.post("/audit/crypto")
async def audit_crypto_quick(
    req: CryptoAuditRequest,
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Audit cryptography usage in source snippet."""
    findings = scanner.scan_cryptography("source_snippet.py", req.source_code)
    score, grade, cat_scores, deductions, fixes, summary = scorer.compute_score(findings)
    return {
        "score": score,
        "grade": grade,
        "findings": findings,
        "deductions": deductions,
        "fixes": fixes,
        "summary": summary
    }


@router.post("/audit/deps")
async def audit_deps_quick(
    req: DepsAuditRequest,
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Audit dependency manifest for vulnerabilities."""
    findings = scanner.scan_dependencies(req.manifest_type, req.manifest_content)
    score, grade, cat_scores, deductions, fixes, summary = scorer.compute_score(findings)
    return {
        "score": score,
        "grade": grade,
        "findings": findings,
        "deductions": deductions,
        "fixes": fixes,
        "summary": summary
    }


@router.get("/eval/benchmark", response_model=BenchmarkResult)
async def execute_ml_benchmark(
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Execute reproducible AI/ML security posture evaluation suite."""
    result = run_posture_evaluation()
    audit_service.log_event(
        event_type="BENCHMARK_EXECUTED",
        actor=user.email,
        resource_id=result.id,
        details={"f1": result.f1_score, "mae": result.mean_absolute_error}
    )
    return result


@router.get("/audit-logs", response_model=List[AuditLogEntry])
async def get_audit_trail(
    limit: int = Query(50, ge=1, le=200),
    user: TokenPayload = Depends(require_role(["analyst", "admin"]))
):
    """Retrieve security audit logs (Analyst or Admin role required)."""
    return audit_service.get_logs(limit=limit)


@router.get("/stats")
async def get_overview_statistics(
    user: TokenPayload = Depends(require_role(["viewer", "analyst", "admin"]))
):
    """Retrieve aggregate statistics across all recorded posture audits."""
    return db.get_statistics()
