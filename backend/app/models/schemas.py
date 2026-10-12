"""Pydantic data models and API request/response contracts."""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str = Field(..., description="Unique deterministic finding identifier")
    title: str = Field(..., description="Short descriptive finding title")
    category: str = Field(..., description="Security category: authentication, cryptography, configuration, dependencies")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description: str = Field(..., description="Detailed technical explanation of the security risk")
    file_path: Optional[str] = Field(None, description="Location of the issue if scanning a file")
    line_number: Optional[int] = Field(None, description="Line number if applicable")
    evidence: Optional[str] = Field(None, description="Redacted snippet or observed value")
    deduction_points: int = Field(..., description="Points deducted from posture score (1-25)")
    remediation: str = Field(..., description="Concrete actionable remediation advice")


class Deduction(BaseModel):
    category: str
    points: int
    reason: str
    finding_id: str


class RemediationFix(BaseModel):
    priority: int = Field(..., description="Priority ranking based on ROI (1 = highest)")
    action: str = Field(..., description="Actionable title for the fix")
    effort: str = Field(..., description="Estimated effort: low, medium, high")
    impact: str = Field(..., description="Security impact: critical, high, medium, low")
    roi_score: float = Field(..., description="Computed risk reduction divided by effort cost")
    suggested_patch: Optional[str] = Field(None, description="Suggested configuration or code snippet")


class ScanSubmission(BaseModel):
    target_name: str = Field(..., min_length=1, max_length=120, description="Name or identifier of the audit target")
    target_type: str = Field("codebase", description="Audit target type: codebase, config, headers, manifest")
    content: Optional[str] = Field(None, description="Raw source, configuration, header text, or manifest")
    file_tree: Optional[Dict[str, str]] = Field(None, description="Dictionary mapping relative filenames to file contents")
    stack: Optional[str] = Field("python", description="Technology stack context")


class LLMAdvisory(BaseModel):
    advisory_enabled: bool
    provider: str
    model: str
    executive_summary: str
    threat_analysis: str
    prioritized_guidance: List[str]
    is_fallback: bool
    error: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    target_name: str
    target_type: str
    overall_score: int
    grade: str
    category_scores: Dict[str, int]
    findings: List[Finding]
    deductions: List[Deduction]
    fixes: List[RemediationFix]
    summary: str
    llm_advisory: Optional[LLMAdvisory] = None
    created_at: str
    created_by: str
    status: str


class ScanDiffRequest(BaseModel):
    before_scan_id: str
    after_scan_id: str


class ScanDiffResponse(BaseModel):
    before_id: str
    after_id: str
    score_before: int
    score_after: int
    score_delta: int
    resolved_findings: List[Finding]
    new_regressions: List[Finding]
    summary: str
    trend: str


class HeaderAuditRequest(BaseModel):
    raw_headers: str = Field(..., description="Raw HTTP response headers string")


class CryptoAuditRequest(BaseModel):
    source_code: str = Field(..., description="Source code snippet to audit for weak crypto and bad randomness")


class DepsAuditRequest(BaseModel):
    manifest_type: str = Field("requirements.txt", description="Manifest type: requirements.txt or package.json")
    manifest_content: str = Field(..., description="Raw dependency manifest file contents")


class BenchmarkResult(BaseModel):
    id: str
    benchmark_name: str
    sample_count: int
    precision_score: float
    recall_score: float
    f1_score: float
    mean_absolute_error: float
    details: Dict[str, Any]
    created_at: str


class AuditLogEntry(BaseModel):
    id: int
    event_type: str
    actor: str
    resource_id: str
    details: Dict[str, Any]
    created_at: str


class TokenRequest(BaseModel):
    grant_type: str = Field("password", description="Grant type: password (demo) or authorization_code (OIDC)")
    username: Optional[str] = Field(None, description="Demo username / email for demo mode")
    code: Optional[str] = Field(None, description="OIDC authorization code")
    code_verifier: Optional[str] = Field(None, description="PKCE code verifier")
    redirect_uri: Optional[str] = Field(None, description="OIDC redirect URI")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: Dict[str, Any]


class UserProfile(BaseModel):
    sub: str
    email: str
    name: str
    roles: List[str]
