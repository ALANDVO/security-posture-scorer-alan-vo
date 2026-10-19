"""Comprehensive HTTP boundary integration tests covering OIDC auth, PKCE, API workflows, and role RBAC."""
import pytest
from starlette.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import db

client = TestClient(app)


@pytest.fixture(autouse=True)
def init_test_db():
    db.init_db()


def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert "version" in data


def test_oidc_demo_login_and_token_exchange():
    # 1. Acquire token for analyst
    response = client.post("/api/auth/token", json={
        "grant_type": "password",
        "username": "analyst@demo.local",
        "password": "demo-password"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert "analyst" in data["user"]["roles"]


def test_oidc_pkce_authorization_code_exchange():
    # Authorization code grant with PKCE
    response = client.post("/api/auth/token", json={
        "grant_type": "authorization_code",
        "code": "test_auth_code_xyz",
        "code_verifier": "test_verifier_sample"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"


def test_oidc_unsupported_grant_type_rejected():
    response = client.post("/api/auth/token", json={
        "grant_type": "client_credentials"
    })
    assert response.status_code == 400
    assert "Unsupported grant_type" in response.json()["detail"]


def test_unauthenticated_api_request_rejected():
    # Accessing scans without bearer token must return 401
    response = client.get("/api/scans")
    assert response.status_code == 401


def test_full_scan_lifecycle_and_http_boundary():
    # 1. Login as analyst
    auth_resp = client.post("/api/auth/token", json={
        "grant_type": "password",
        "username": "analyst@demo.local"
    })
    token = auth_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create scan
    submission = {
        "target_name": "Integration Test API",
        "target_type": "config",
        "content": '{"debug": true, "allow_origins": ["*"], "ssl": false}'
    }
    create_resp = client.post("/api/scans", json=submission, headers=headers)
    assert create_resp.status_code == 201
    scan = create_resp.json()
    assert scan["target_name"] == "Integration Test API"
    assert scan["overall_score"] < 100
    assert len(scan["findings"]) >= 2
    assert len(scan["fixes"]) >= 2
    scan_id = scan["id"]

    # 3. Read scan detail by ID
    get_resp = client.get(f"/api/scans/{scan_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == scan_id

    # 4. List scans with filter
    list_resp = client.get("/api/scans?limit=10&target=Integration", headers=headers)
    assert list_resp.status_code == 200
    items = list_resp.json()["items"]
    assert any(s["id"] == scan_id for s in items)

    # 5. Request advisory threat analysis (grounded fallback)
    advise_resp = client.post(f"/api/scans/{scan_id}/advise", headers=headers)
    assert advise_resp.status_code == 200
    advised = advise_resp.json()
    assert advised["llm_advisory"] is not None
    assert "executive_summary" in advised["llm_advisory"]


def test_posture_differential_comparison_workflow():
    # Login as analyst
    auth_resp = client.post("/api/auth/token", json={
        "grant_type": "password",
        "username": "analyst@demo.local"
    })
    token = auth_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create baseline scan (insecure)
    scan1 = client.post("/api/scans", json={
        "target_name": "Revision 1 (Insecure)",
        "target_type": "config",
        "content": '{"debug": true, "allow_origins": ["*"]}'
    }, headers=headers).json()

    # Create hardened scan
    scan2 = client.post("/api/scans", json={
        "target_name": "Revision 2 (Hardened)",
        "target_type": "config",
        "content": '{"debug": false, "allow_origins": ["https://app.alanvo.dev"]}'
    }, headers=headers).json()

    # Diff scans
    diff_resp = client.post("/api/scans/diff", json={
        "before_scan_id": scan1["id"],
        "after_scan_id": scan2["id"]
    }, headers=headers)
    assert diff_resp.status_code == 200
    diff = diff_resp.json()
    assert diff["score_delta"] > 0
    assert diff["trend"] == "IMPROVED"
    assert len(diff["resolved_findings"]) > 0


def test_role_authorization_and_denial():
    # Login as viewer
    auth_viewer = client.post("/api/auth/token", json={
        "grant_type": "password",
        "username": "viewer@demo.local"
    })
    viewer_token = auth_viewer.json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # Login as admin
    auth_admin = client.post("/api/auth/token", json={
        "grant_type": "password",
        "username": "admin@demo.local"
    })
    admin_token = auth_admin.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Create scan as viewer (viewer is allowed to scan)
    create_resp = client.post("/api/scans", json={
        "target_name": "RBAC Test",
        "target_type": "headers",
        "content": "X-Frame-Options: DENY"
    }, headers=viewer_headers)
    assert create_resp.status_code == 201
    scan_id = create_resp.json()["id"]

    # Viewer attempting to delete scan must be denied with 403
    del_forbidden = client.delete(f"/api/scans/{scan_id}", headers=viewer_headers)
    assert del_forbidden.status_code == 403

    # Viewer attempting to request advisory must be denied with 403 (analyst/admin only)
    advise_forbidden = client.post(f"/api/scans/{scan_id}/advise", headers=viewer_headers)
    assert advise_forbidden.status_code == 403

    # Admin deleting scan must succeed with 200
    del_ok = client.delete(f"/api/scans/{scan_id}", headers=admin_headers)
    assert del_ok.status_code == 200


def test_ml_benchmark_evaluation_endpoint():
    auth_resp = client.post("/api/auth/token", json={
        "grant_type": "password",
        "username": "analyst@demo.local"
    })
    token = auth_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/eval/benchmark", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["sample_count"] == 10
    assert 0.0 <= data["precision_score"] <= 1.0
    assert 0.0 <= data["recall_score"] <= 1.0
    assert 0.0 <= data["f1_score"] <= 1.0
    assert data["mean_absolute_error"] >= 0.0
