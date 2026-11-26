"""PR Security Posture Comment API endpoint."""
from fastapi import APIRouter, Body, HTTPException, status
from backend.app.core.database import db
from backend.app.models.schemas import Finding
from backend.app.services.pr_commenter import generate_pr_comment
from typing import List, Dict, Any

router = APIRouter(prefix="/api", tags=["pr-comment"])


@router.post("/pr-comment", response_model=Dict[str, Any])
async def generate_pr_comment_endpoint(
    before_scan_id: str = Body(..., description="ID of the baseline/previous scan"),
    after_scan_id: str = Body(..., description="ID of the current scan"),
) -> Dict[str, Any]:
    """Generate a markdown PR comment summarizing security posture delta between two scans.

    Returns a markdown string suitable for GitHub PR comments, including score delta,
    resolved findings, and newly introduced regressions.

    This endpoint is called by the GitHub Action PR Security Posture Commenter workflow
    to post posture score changes directly on pull requests.
    """
    try:
        comment_md = generate_pr_comment(before_scan_id, after_scan_id)
        return {
            "comment": comment_md,
            "before_scan_id": before_scan_id,
            "after_scan_id": after_scan_id,
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
