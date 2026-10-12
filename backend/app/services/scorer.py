"""Deterministic posture scoring engine, category weight calculation, and ROI-based fix prioritization."""
from typing import List, Dict, Tuple
from backend.app.models.schemas import Finding, Deduction, RemediationFix

CATEGORY_MAX_POINTS = {
    "authentication": 25,
    "cryptography": 25,
    "configuration": 25,
    "dependencies": 25
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 15.0,
    "HIGH": 10.0,
    "MEDIUM": 6.0,
    "LOW": 3.0,
    "INFO": 1.0
}

EFFORT_COSTS = {
    "low": 1.0,
    "medium": 2.5,
    "high": 5.0
}


def _estimate_effort(finding: Finding) -> str:
    """Deterministic heuristic for effort required to remediate finding."""
    if "header" in finding.id or "nosniff" in finding.id or "debug" in finding.id:
        return "low"
    if "cookie" in finding.id or "cors" in finding.id or "unpinned" in finding.id or "root" in finding.id:
        return "low"
    if "dep-" in finding.id or "crypto-pseudo" in finding.id:
        return "medium"
    if "crypto-insecure-cipher" in finding.id or "crypto-weak-hash" in finding.id:
        return "high"
    return "medium"


def _generate_patch_snippet(finding: Finding) -> str:
    """Generate sample configuration or code snippet to resolve issue."""
    if "debug" in finding.id:
        return "# config.json\n{\n  \"debug\": false\n}"
    if "cors" in finding.id:
        return "# server config\nallow_origins = [\"https://app.example.com\"]"
    if "nosniff" in finding.id:
        return "X-Content-Type-Options: nosniff"
    if "hsts" in finding.id:
        return "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    if "csp" in finding.id:
        return "Content-Security-Policy: default-src 'self'; img-src 'self' data:; object-src 'none';"
    if "docker-root" in finding.id:
        return "# Dockerfile\nRUN groupadd -r app && useradd -r -g app app\nUSER app"
    if "crypto-weak-hash" in finding.id:
        return "# Python migration:\nimport hashlib\ndigest = hashlib.sha256(data).hexdigest()"
    if "crypto-insecure-cipher" in finding.id:
        return "# Replace ECB/DES with AES-GCM authenticated cipher:\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\naesgcm = AESGCM(key)"
    if "dep-" in finding.id and "cve" in finding.id:
        return f"# Upgrade dependency to latest patch release:\npip install --upgrade {finding.evidence}"
    return f"// Remediation:\n// {finding.remediation}"


class PostureScorer:
    """Deterministic score calculation and fix ranker."""

    def compute_score(
        self,
        findings: List[Finding]
    ) -> Tuple[int, str, Dict[str, int], List[Deduction], List[RemediationFix], str]:
        """Compute score (0-100), letter grade, category breakdowns, deductions, and ranked fixes."""
        category_deductions: Dict[str, int] = {k: 0 for k in CATEGORY_MAX_POINTS}
        deductions: List[Deduction] = []

        for f in findings:
            cat = f.category if f.category in category_deductions else "configuration"
            category_deductions[cat] += f.deduction_points
            deductions.append(Deduction(
                category=cat,
                points=f.deduction_points,
                reason=f"{f.title}: {f.description}",
                finding_id=f.id
            ))

        category_scores: Dict[str, int] = {}
        for cat, max_pts in CATEGORY_MAX_POINTS.items():
            spent = category_deductions.get(cat, 0)
            score_in_cat = max(0, max_pts - spent)
            category_scores[cat] = score_in_cat

        overall_score = sum(category_scores.values())
        overall_score = max(0, min(100, overall_score))

        # Letter grade
        if overall_score >= 90:
            grade = "A"
        elif overall_score >= 75:
            grade = "B"
        elif overall_score >= 60:
            grade = "C"
        elif overall_score >= 40:
            grade = "D"
        else:
            grade = "F"

        # Prioritize fixes by ROI = (Impact Weight) / (Effort Cost)
        unranked_fixes = []
        for f in findings:
            effort = _estimate_effort(f)
            impact = f.severity.lower()
            impact_weight = SEVERITY_WEIGHTS.get(f.severity, 3.0)
            effort_cost = EFFORT_COSTS.get(effort, 2.5)
            roi = round(impact_weight / effort_cost, 2)
            patch = _generate_patch_snippet(f)

            unranked_fixes.append({
                "action": f.remediation,
                "effort": effort,
                "impact": impact,
                "roi_score": roi,
                "suggested_patch": patch,
                "severity": f.severity
            })

        # Sort descending by ROI score, then by severity weight
        unranked_fixes.sort(key=lambda x: (x["roi_score"], SEVERITY_WEIGHTS.get(x["severity"], 0)), reverse=True)

        fixes: List[RemediationFix] = []
        for i, item in enumerate(unranked_fixes, 1):
            fixes.append(RemediationFix(
                priority=i,
                action=item["action"],
                effort=item["effort"],
                impact=item["impact"],
                roi_score=item["roi_score"],
                suggested_patch=item["suggested_patch"]
            ))

        # Executive summary
        summary = (
            f"Security Posture Score: {overall_score}/100 (Grade {grade}). "
            f"Evaluated {len(findings)} deterministic findings resulting in {len(deductions)} score deductions. "
            f"Authentication: {category_scores['authentication']}/25, "
            f"Cryptography: {category_scores['cryptography']}/25, "
            f"Configuration: {category_scores['configuration']}/25, "
            f"Dependencies: {category_scores['dependencies']}/25. "
            f"Top remediation recommendation: {fixes[0].action if fixes else 'No critical remediations required'}."
        )

        return overall_score, grade, category_scores, deductions, fixes, summary


scorer = PostureScorer()
