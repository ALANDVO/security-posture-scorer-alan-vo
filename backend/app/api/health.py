"""Health check and service status diagnostic endpoint."""
from fastapi import APIRouter
from backend.app.core.config import settings
from backend.app.core.database import db

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health_check():
    """Service health and database readiness check."""
    db_ok = True
    try:
        conn = db.get_connection()
        conn.execute("SELECT 1").fetchone()
    except Exception:
        db_ok = False

    return {
        "status": "ok" if db_ok else "degraded",
        "service": settings.project_name,
        "version": settings.version,
        "environment": settings.environment,
        "demo_mode": settings.demo_mode,
        "llm_provider": settings.llm_provider,
        "database": "connected" if db_ok else "error"
    }
