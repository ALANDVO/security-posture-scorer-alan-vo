"""Persistent SQLite storage with thread safety and parameterized transactions."""
import sqlite3
import json
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from backend.app.core.config import settings

_local = threading.local()


def get_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.database_path

    def get_connection(self) -> sqlite3.Connection:
        conn = getattr(_local, "connection", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            _local.connection = conn
        return conn

    def init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        conn = self.get_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target_name TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    overall_score INTEGER NOT NULL,
                    grade TEXT NOT NULL,
                    category_scores TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    deductions TEXT NOT NULL,
                    fixes TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    llm_advisory TEXT,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS benchmarks (
                    id TEXT PRIMARY KEY,
                    benchmark_name TEXT NOT NULL,
                    sample_count INTEGER NOT NULL,
                    precision_score REAL NOT NULL,
                    recall_score REAL NOT NULL,
                    f1_score REAL NOT NULL,
                    mean_absolute_error REAL NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

    def save_scan(self, scan_data: Dict[str, Any]) -> None:
        conn = self.get_connection()
        with conn:
            conn.execute("""
                INSERT INTO scans (
                    id, target_name, target_type, overall_score, grade,
                    category_scores, findings, deductions, fixes,
                    summary, llm_advisory, created_at, created_by, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_data["id"],
                scan_data["target_name"],
                scan_data["target_type"],
                scan_data["overall_score"],
                scan_data["grade"],
                json.dumps(scan_data["category_scores"]),
                json.dumps(scan_data["findings"]),
                json.dumps(scan_data["deductions"]),
                json.dumps(scan_data["fixes"]),
                scan_data["summary"],
                json.dumps(scan_data["llm_advisory"]) if scan_data.get("llm_advisory") else None,
                scan_data["created_at"],
                scan_data["created_by"],
                scan_data["status"],
            ))

    def update_scan_advisory(self, scan_id: str, advisory_data: Dict[str, Any]) -> bool:
        conn = self.get_connection()
        with conn:
            cursor = conn.execute("""
                UPDATE scans
                SET llm_advisory = ?
                WHERE id = ?
            """, (json.dumps(advisory_data), scan_id))
            return cursor.rowcount > 0

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_scan(row)

    def list_scans(
        self,
        skip: int = 0,
        limit: int = 20,
        target_filter: Optional[str] = None,
        min_score: Optional[int] = None,
        max_score: Optional[int] = None
    ) -> (List[Dict[str, Any]], int):
        conn = self.get_connection()
        conditions = ["1=1"]
        params: List[Any] = []

        if target_filter:
            conditions.append("target_name LIKE ?")
            params.append(f"%{target_filter}%")
        if min_score is not None:
            conditions.append("overall_score >= ?")
            params.append(min_score)
        if max_score is not None:
            conditions.append("overall_score <= ?")
            params.append(max_score)

        where_clause = " AND ".join(conditions)

        count_cursor = conn.execute(f"SELECT COUNT(*) FROM scans WHERE {where_clause}", tuple(params))
        total = count_cursor.fetchone()[0]

        query = f"""
            SELECT * FROM scans
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(query, tuple(params + [limit, skip])).fetchall()
        scans = [self._row_to_scan(r) for r in rows]
        return scans, total

    def delete_scan(self, scan_id: str) -> bool:
        conn = self.get_connection()
        with conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0

    def record_audit(self, event_type: str, actor: str, resource_id: str, details: Dict[str, Any]) -> None:
        conn = self.get_connection()
        with conn:
            conn.execute("""
                INSERT INTO audit_logs (event_type, actor, resource_id, details, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (event_type, actor, resource_id, json.dumps(details), get_utc_now()))

    def list_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "event_type": r["event_type"],
                "actor": r["actor"],
                "resource_id": r["resource_id"],
                "details": json.loads(r["details"]),
                "created_at": r["created_at"]
            })
        return result

    def save_benchmark(self, bench_data: Dict[str, Any]) -> None:
        conn = self.get_connection()
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO benchmarks (
                    id, benchmark_name, sample_count, precision_score,
                    recall_score, f1_score, mean_absolute_error, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                bench_data["id"],
                bench_data["benchmark_name"],
                bench_data["sample_count"],
                bench_data["precision_score"],
                bench_data["recall_score"],
                bench_data["f1_score"],
                bench_data["mean_absolute_error"],
                json.dumps(bench_data["details"]),
                bench_data["created_at"],
            ))

    def get_latest_benchmark(self) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        row = conn.execute(
            "SELECT * FROM benchmarks ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "benchmark_name": row["benchmark_name"],
            "sample_count": row["sample_count"],
            "precision_score": row["precision_score"],
            "recall_score": row["recall_score"],
            "f1_score": row["f1_score"],
            "mean_absolute_error": row["mean_absolute_error"],
            "details": json.loads(row["details"]),
            "created_at": row["created_at"],
        }

    def get_statistics(self) -> Dict[str, Any]:
        conn = self.get_connection()
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        if total_scans == 0:
            return {
                "total_scans": 0,
                "average_score": 0.0,
                "lowest_score": 0,
                "highest_score": 0,
                "critical_findings_count": 0,
                "total_fixes_suggested": 0
            }
        avg_score = conn.execute("SELECT AVG(overall_score) FROM scans").fetchone()[0] or 0.0
        min_score = conn.execute("SELECT MIN(overall_score) FROM scans").fetchone()[0] or 0
        max_score = conn.execute("SELECT MAX(overall_score) FROM scans").fetchone()[0] or 0

        # Scan rows for aggregate critical count
        rows = conn.execute("SELECT findings, fixes FROM scans").fetchall()
        crit_count = 0
        fix_count = 0
        for r in rows:
            findings = json.loads(r["findings"])
            crit_count += sum(1 for f in findings if f.get("severity") == "CRITICAL")
            fixes = json.loads(r["fixes"])
            fix_count += len(fixes)

        return {
            "total_scans": total_scans,
            "average_score": round(float(avg_score), 1),
            "lowest_score": min_score,
            "highest_score": max_score,
            "critical_findings_count": crit_count,
            "total_fixes_suggested": fix_count
        }

    def _row_to_scan(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "target_name": row["target_name"],
            "target_type": row["target_type"],
            "overall_score": row["overall_score"],
            "grade": row["grade"],
            "category_scores": json.loads(row["category_scores"]),
            "findings": json.loads(row["findings"]),
            "deductions": json.loads(row["deductions"]),
            "fixes": json.loads(row["fixes"]),
            "summary": row["summary"],
            "llm_advisory": json.loads(row["llm_advisory"]) if row["llm_advisory"] else None,
            "created_at": row["created_at"],
            "created_by": row["created_by"],
            "status": row["status"]
        }


db = Database()
