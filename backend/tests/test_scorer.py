"""Tests for posture score calculation and ROI fix ranking."""
import pytest
from backend.app.models.schemas import Finding
from backend.app.services.scorer import scorer


def test_scorer_perfect_score():
    score, grade, cat_scores, deductions, fixes, summary = scorer.compute_score([])
    assert score == 100
    assert grade == "A"
    assert all(pts == 25 for pts in cat_scores.values())
    assert len(deductions) == 0
    assert len(fixes) == 0


def test_scorer_deductions_and_grade_boundaries():
    findings = [
        Finding(
            id="f1",
            title="Weak crypto",
            category="cryptography",
            severity="CRITICAL",
            description="DES ECB used",
            deduction_points=15,
            remediation="Use AES-GCM"
        ),
        Finding(
            id="f2",
            title="Broken hash",
            category="cryptography",
            severity="HIGH",
            description="MD5 used",
            deduction_points=10,
            remediation="Use SHA-256"
        ),
        Finding(
            id="f3",
            title="Debug enabled",
            category="configuration",
            severity="HIGH",
            description="Debug true",
            deduction_points=10,
            remediation="Turn off debug"
        )
    ]
    score, grade, cat_scores, deductions, fixes, summary = scorer.compute_score(findings)

    # Cryptography lost 15+10=25 -> 0/25
    # Configuration lost 10 -> 15/25
    # Overall score = 0 (crypto) + 15 (config) + 25 (auth) + 25 (deps) = 65
    assert score == 65
    assert grade == "C"
    assert cat_scores["cryptography"] == 0
    assert cat_scores["configuration"] == 15
    assert cat_scores["authentication"] == 25
    assert cat_scores["dependencies"] == 25
    assert len(deductions) == 3


def test_scorer_fix_roi_ranking():
    findings = [
        Finding(
            id="f-hard",
            title="Rewrite cipher engine",
            category="cryptography",
            severity="HIGH",
            description="Replace cipher",
            deduction_points=10,
            remediation="Migrate cipher"
        ),
        Finding(
            id="hdr-nosniff",
            title="Missing nosniff",
            category="configuration",
            severity="HIGH",
            description="Add header",
            deduction_points=8,
            remediation="Add X-Content-Type-Options: nosniff"
        )
    ]
    score, grade, cat_scores, deductions, fixes, summary = scorer.compute_score(findings)
    assert len(fixes) == 2
    # Low effort item (header) has higher ROI than high effort item
    assert fixes[0].action == "Add X-Content-Type-Options: nosniff"
    assert fixes[0].priority == 1
    assert fixes[0].roi_score > fixes[1].roi_score
