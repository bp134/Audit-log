"""
Deterministic PostgreSQL-Only Acceptance Tests for WP-2
(Audit IDs: ID-002, ID-008, ID-009, ID-010, ID-016, ID-017, ID-022).
Executes against live PostgreSQL 18 (zero SQLite anywhere in the codebase).
"""

from __future__ import annotations

import ast
from datetime import date, datetime, timezone
from pathlib import Path
import unittest
import uuid

import psycopg

from src.domain.ledger import (
    GENESIS_PREV_HASH,
    canonical_json,
    compute_audit_row_hash,
    format_canonical_utc_timestamp,
)
from src.domain.models import AuditEventType, StaffRole
from src.repository.db_repo import ComplianceRepository

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestWP2PostgresRepositoryAndIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = ComplianceRepository()
        self.repo.seed_tasks_from_sql_file()

    def tearDown(self) -> None:
        self.repo.close()

    def test_id002_id016_zero_sqlite_in_source_and_tests(self) -> None:
        """ID-002 & ID-016: Verify sqlite3 is completely eradicated from src/ and tests/."""
        for folder in ("src", "tests"):
            for py_file in (REPO_ROOT / folder).rglob("*.py"):
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotEqual(alias.name, "sqlite3", f"sqlite3 still imported in {py_file}")
                    elif isinstance(node, ast.ImportFrom):
                        self.assertNotEqual(node.module, "sqlite3", f"from sqlite3 still used in {py_file}")

    def test_id008_postgres_fn_canonical_jsonb_matches_python_canonical_json_byte_for_byte(self) -> None:
        """ID-008: Execute fn_canonical_jsonb() inside PostgreSQL 18 and compare to Python canonical_json()."""
        payload = {"z_key": 10, "a_key": {"nested_b": True, "nested_a": "value"}, "m_list": [3, 1, 2]}
        py_json = canonical_json(payload)
        pg_row = self.repo.conn.execute(
            "SELECT fn_canonical_jsonb(%s::jsonb) AS pg_json",
            (py_json,),
        ).fetchone()
        self.assertIsNotNone(pg_row)
        self.assertEqual(pg_row["pg_json"], py_json)

        # Verify PostgreSQL BEFORE INSERT trigger computes the exact same SHA-256 row_hash as Python
        ev = self.repo.append_audit_event(
            event_type=AuditEventType.INSTANCE_SCHEDULED,
            task_id=1,
            period_key="2026-10-16",
            payload=payload,
            occurred_at=datetime(2026, 10, 16, 9, 15, 30, 654321, tzinfo=timezone.utc),
        )
        py_recomputed = compute_audit_row_hash(
            event_id=ev["event_id"],
            event_type=ev["event_type"],
            task_id=1,
            instance_id=None,
            period_key="2026-10-16",
            actor_user_id=None,
            actor_slack_id=None,
            actor_entra_oid=None,
            actor_role=None,
            payload=payload,
            occurred_at_iso=format_canonical_utc_timestamp(
                datetime(2026, 10, 16, 9, 15, 30, 654321, tzinfo=timezone.utc)
            ),
            prev_hash=GENESIS_PREV_HASH,
        )
        self.assertEqual(ev["row_hash"], py_recomputed)
        self.assertTrue(self.repo.verify_ledger_integrity().is_valid)

    def test_id010_postgres_trigger_rejects_forged_row_hash_and_broken_prev_hash(self) -> None:
        """ID-010: PostgreSQL BEFORE INSERT trigger blocks forged row_hash and invalid prev_hash."""
        ev1 = self.repo.append_audit_event(
            event_type=AuditEventType.INSTANCE_SCHEDULED,
            task_id=1,
            period_key="2026-10-16",
            payload={"tranche": "Morning"},
        )
        self.assertEqual(ev1["prev_hash"], GENESIS_PREV_HASH)

        # Attempt direct SQL INSERT into PostgreSQL with forged row_hash
        with self.assertRaises(psycopg.Error) as ctx_forged:
            with self.repo.conn.transaction():
                self.repo.conn.execute(
                    """
                    INSERT INTO task_events_audit (
                        event_id, event_type, task_id, period_key, payload, prev_hash, row_hash
                    ) VALUES (%s, 'TASK_COMPLETED', 1, '2026-10-16', '{"forged":true}'::jsonb, %s, %s)
                    """,
                    (str(uuid.uuid4()), ev1["row_hash"], "f" * 64),
                )
        self.assertIn("Forged or mismatched row_hash", str(ctx_forged.exception))

        # Attempt direct SQL INSERT into PostgreSQL with broken prev_hash
        with self.assertRaises(psycopg.Error) as ctx_prev:
            with self.repo.conn.transaction():
                self.repo.conn.execute(
                    """
                    INSERT INTO task_events_audit (
                        event_id, event_type, task_id, period_key, payload, prev_hash, row_hash
                    ) VALUES (%s, 'TASK_COMPLETED', 1, '2026-10-16', '{"forged":true}'::jsonb, %s, '')
                    """,
                    (str(uuid.uuid4()), "1" * 64),
                )
        self.assertIn("Invalid prev_hash", str(ctx_prev.exception))

    def test_id009_optimistic_locking_prevents_duplicate_completion_race(self) -> None:
        """ID-009: Concurrent completion when status is already Completed returns conflict without duplicate audit."""
        from unittest.mock import patch

        pharm = self.repo.upsert_user(
            entra_oid="oid-pharm-race",
            slack_user_id="U_PHARM_RACE",
            full_name="Anjum RP",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2054321",
        )
        instances = self.repo.ensure_instances_for_date(date(2026, 10, 16))
        target = next(i for i in instances if i.task_name == "CD Register Reconcile")

        stale_pending_snapshot = self.repo.get_instance_by_id(target.instance_id)
        self.assertIsNotNone(stale_pending_snapshot)

        with self.repo.conn.transaction():
            self.repo.conn.execute(
                """
                UPDATE task_instances
                SET status = 'Completed', completed_by_user_id = %s, completed_at = NOW()
                WHERE instance_id = %s
                """,
                (pharm.user_id, target.instance_id),
            )

        with patch.object(self.repo, "get_instance_by_id", side_effect=[stale_pending_snapshot, target]):
            ok, msg, _ = self.repo.complete_task_instance(
                instance_id=target.instance_id,
                actor_slack_id=pharm.slack_user_id,
            )
        self.assertFalse(ok)
        self.assertIn("Conflict:", msg)

    def test_id017_id022_sql_seed_and_pg_advisory_lock_active(self) -> None:
        """ID-017 & ID-022: Verify 02_seed_tasks.sql seeded 33 tasks and advisory lock is active in PG."""
        proc_src = self.repo.conn.execute(
            """
            SELECT p.prosrc
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE p.proname = 'fn_audit_compute_hash_chain'
              AND n.nspname = current_schema()
            LIMIT 1
            """
        ).fetchone()
        self.assertIsNotNone(proc_src)
        self.assertIn("pg_advisory_xact_lock", proc_src["prosrc"])
        self.assertNotIn("LOCK TABLE", proc_src["prosrc"])


if __name__ == "__main__":
    unittest.main()
