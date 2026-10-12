"""Security audit event logging service."""
from typing import Dict, Any, List
from backend.app.core.database import db


class AuditService:
    @staticmethod
    def log_event(event_type: str, actor: str, resource_id: str, details: Dict[str, Any]) -> None:
        db.record_audit(
            event_type=event_type,
            actor=actor,
            resource_id=resource_id,
            details=details
        )

    @staticmethod
    def get_logs(limit: int = 50) -> List[Dict[str, Any]]:
        return db.list_audit_logs(limit=limit)


audit_service = AuditService()
