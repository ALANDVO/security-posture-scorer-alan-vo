"""Reproducible AI/ML security posture benchmark, evaluation metrics, and calibration engine."""
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from backend.app.services.scanner import scanner
from backend.app.services.scorer import scorer
from backend.app.models.schemas import BenchmarkResult
from backend.app.core.database import db

# Curated benchmark dataset of 12 test environments with ground truth security labels
BENCHMARK_DATASET = [
    {
        "id": "bench-clean-fastapi",
        "name": "Hardened FastAPI Production Setup",
        "type": "codebase",
        "files": {
            "config.json": '{"debug": false, "allow_origins": ["https://app.alanvo.dev"], "ssl": true}',
            "headers.http": "Content-Security-Policy: default-src 'self';\nStrict-Transport-Security: max-age=31536000\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nSet-Cookie: session=xyz; Secure; HttpOnly; SameSite=Strict",
            "crypto.py": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nimport hashlib\nh = hashlib.sha256(b'test').hexdigest()",
            "requirements.txt": "fastapi==0.110.0\nuvicorn==0.28.0\npydantic==2.6.4"
        },
        "expected_vulns": 0,
        "ground_truth_score": 100
    },
    {
        "id": "bench-debug-cors",
        "name": "Development Leak with Debug and Permissive CORS",
        "type": "codebase",
        "files": {
            "config.json": '{"debug": true, "allow_origins": ["*"]}',
            "headers.http": "X-Content-Type-Options: nosniff"
        },
        "expected_vulns": 5, # debug, cors, missing csp, missing hsts, missing frame
        "ground_truth_score": 63
    },
    {
        "id": "bench-weak-crypto",
        "name": "Legacy Cryptography with MD5 and ECB Ciphers",
        "type": "codebase",
        "files": {
            "cipher.py": "import hashlib\nfrom Crypto.Cipher import AES\nh = hashlib.md5(data).digest()\ncipher = AES.new(key, AES.MODE_ECB)"
        },
        "expected_vulns": 2, # weak md5, insecure ecb
        "ground_truth_score": 75
    },
    {
        "id": "bench-insecure-cookies",
        "name": "Missing Cookie Flags on Auth Session",
        "type": "headers",
        "files": {
            "response.http": "HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: token=secret123"
        },
        "expected_vulns": 7, # missing csp, hsts, nosniff, frame, httponly, secure, samesite
        "ground_truth_score": 62
    },
    {
        "id": "bench-vulnerable-deps",
        "name": "Dependency Manifest with Known Vulnerabilities",
        "type": "manifest",
        "files": {
            "requirements.txt": "requests==2.28.0\nurllib3==1.26.5\ncryptography==40.0.1"
        },
        "expected_vulns": 3, # requests cve, urllib3 cve, cryptography cve
        "ground_truth_score": 80
    },
    {
        "id": "bench-unpinned-deps",
        "name": "Supply Chain Risks with Unpinned Dependencies",
        "type": "manifest",
        "files": {
            "requirements.txt": "flask=* \nrequests>=0.1"
        },
        "expected_vulns": 2, # unpinned x2
        "ground_truth_score": 94
    },
    {
        "id": "bench-container-root",
        "name": "Container Dockerfile Executing as Root",
        "type": "codebase",
        "files": {
            "Dockerfile": "FROM python:3.11-slim\nUSER root\nCMD [\"python\", \"app.py\"]"
        },
        "expected_vulns": 1, # docker root
        "ground_truth_score": 94
    },
    {
        "id": "bench-pseudo-random",
        "name": "Insecure Pseudo-Random Token Generation",
        "type": "codebase",
        "files": {
            "auth.py": "import random\nsession_token = random.random()"
        },
        "expected_vulns": 1, # pseudo random
        "ground_truth_score": 93
    },
    {
        "id": "bench-severely-compromised",
        "name": "Severely Vulnerable Microservice",
        "type": "codebase",
        "files": {
            "settings.json": '{"debug": true, "allow_origins": ["*"], "ssl": false}',
            "app.py": "import hashlib\nfrom Crypto.Cipher import DES\nh = hashlib.sha1(b'x').hexdigest()\nc = DES.new(k, DES.MODE_ECB)",
            "headers.txt": "Set-Cookie: auth=xyz",
            "requirements.txt": "requests==2.28.0\njsonwebtoken==8.5.1"
        },
        "expected_vulns": 11,
        "ground_truth_score": 18
    },
    {
        "id": "bench-partially-hardened",
        "name": "Partially Hardened Backend API",
        "type": "codebase",
        "files": {
            "config.yaml": "debug: false\nallow_origins:\n  - 'https://dashboard.lan'",
            "headers.http": "Content-Security-Policy: default-src 'self'\nStrict-Transport-Security: max-age=31536000\nX-Content-Type-Options: nosniff",
            "crypto.py": "import hashlib\nhashlib.sha256(b'ok').digest()"
        },
        "expected_vulns": 1, # missing frame-options
        "ground_truth_score": 95
    }
]


def run_posture_evaluation() -> BenchmarkResult:
    """Execute reproducible evaluation against the benchmark suite."""
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    score_errors = []

    per_sample_details = []

    for item in BENCHMARK_DATASET:
        findings = scanner.scan_all(
            target_name=item["name"],
            target_type=item["type"],
            file_tree=item["files"]
        )
        pred_score, grade, _, deductions, fixes, _ = scorer.compute_score(findings)
        detected_count = len(findings)
        expected_count = item["expected_vulns"]
        ground_score = item["ground_truth_score"]

        # Approximate TP/FP/FN based on expected vs detected counts
        tp = min(detected_count, expected_count)
        fp = max(0, detected_count - expected_count)
        fn = max(0, expected_count - detected_count)

        true_positives += tp
        false_positives += fp
        false_negatives += fn

        score_error = abs(pred_score - ground_score)
        score_errors.append(score_error)

        per_sample_details.append({
            "sample_id": item["id"],
            "name": item["name"],
            "expected_vulns": expected_count,
            "detected_vulns": detected_count,
            "ground_truth_score": ground_score,
            "predicted_score": pred_score,
            "score_delta": pred_score - ground_score,
            "grade": grade,
            "findings": [f.id for f in findings]
        })

    precision = round(true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 1.0, 4)
    recall = round(true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 1.0, 4)
    f1 = round((2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0, 4)
    mae = round(sum(score_errors) / len(score_errors) if score_errors else 0.0, 2)

    result = BenchmarkResult(
        id=str(uuid.uuid4()),
        benchmark_name="Security Posture Scorer Evaluation Suite v1.0",
        sample_count=len(BENCHMARK_DATASET),
        precision_score=precision,
        recall_score=recall,
        f1_score=f1,
        mean_absolute_error=mae,
        details={
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "samples": per_sample_details,
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat()
        },
        created_at=datetime.now(timezone.utc).isoformat()
    )

    db.save_benchmark({
        "id": result.id,
        "benchmark_name": result.benchmark_name,
        "sample_count": result.sample_count,
        "precision_score": result.precision_score,
        "recall_score": result.recall_score,
        "f1_score": result.f1_score,
        "mean_absolute_error": result.mean_absolute_error,
        "details": result.details,
        "created_at": result.created_at
    })

    return result


if __name__ == "__main__":
    res = run_posture_evaluation()
    print("=" * 60)
    print("REPRODUCIBLE AI/ML SECURITY POSTURE BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Sample Count:  {res.sample_count}")
    print(f"Precision:     {res.precision_score:.4f}")
    print(f"Recall:        {res.recall_score:.4f}")
    print(f"F1 Score:      {res.f1_score:.4f}")
    print(f"Score MAE:     {res.mean_absolute_error:.2f} pts")
    print("=" * 60)
