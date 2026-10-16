"""
Phase 1 Critic Verification Gate (PostgreSQL-Exclusive):
Tests PostgreSQL Schema (`db/01_schema.sql`), 33-Task SQL Seeding (`db/02_seed_tasks.sql`),
RBAC Constraints, Append-Only Immutability Triggers, and SHA-256 Cryptographic Hash Chain Tamper Detection.
Zero SQLite usage anywhere in this suite.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
import unittest

import psycopg

from src.domain.models import (
    DailyWindow,
    RoleRequirement,
    StaffRole,
    TaskFrequency,
    normalize_role_label,
)
from src.repository.db_repo import ComplianceRepository


class Phase1CriticTestSuite(unittest.TestCase):
    def test_all_33_tasks_seeded_and_normalized_accurately(self) -> None:
        repo = ComplianceRepository()
        count = repo.seed_tasks_from_sql_file()
        self.assertEqual(count, 33)

        rows = repo.conn.execute("SELECT * FROM tasks_master ORDER BY task_id").fetchall()
        daily = [r for r in rows if r["frequency"] == TaskFrequency.DAILY.value]
        weekly = [r for r in rows if r["frequency"] == TaskFrequency.WEEKLY.value]
        monthly = [r for r in rows if r["frequency"] == TaskFrequency.MONTHLY.value]

        self.assertEqual(len(daily), 14)
        self.assertEqual(len(weekly), 10)
        self.assertEqual(len(monthly), 9)

        # Verify Daily timing windows
        morning = [r for r in daily if r["daily_timing_window"] == DailyWindow.MORNING.value]
        anytime = [r for r in daily if r["daily_timing_window"] == DailyWindow.ANYTIME.value]
        eod = [r for r in daily if r["daily_timing_window"] == DailyWindow.END_OF_DAY.value]
        self.assertEqual(len(morning), 4)
        self.assertEqual(len(anytime), 5)
        self.assertEqual(len(eod), 5)

        # Verify Weekly and Monthly tasks have NULL daily_timing_window
        self.assertTrue(all(r["daily_timing_window"] is None for r in weekly))
        self.assertTrue(all(r["daily_timing_window"] is None for r in monthly))

        # Verify 'Dispenser / Pharm' and 'Pharm / Dispenser' both normalize to 'Either'
        self.assertEqual(normalize_role_label("Dispenser / Pharm"), RoleRequirement.EITHER)
        self.assertEqual(normalize_role_label("Pharm / Dispenser"), RoleRequirement.EITHER)
        self.assertEqual(normalize_role_label("Pharm"), RoleRequirement.PHARM)
        self.assertEqual(normalize_role_label("Dispenser"), RoleRequirement.DISPENSER)

        # Verify only Fridge Check requires structured input
        structured = [r for r in rows if bool(r["requires_structured_input"]) is True]
        self.assertEqual(len(structured), 1)
        self.assertEqual(structured[0]["task_name"], "Fridge Check (Min/Max/Current)")
        repo.close()

    def test_pharmacist_requires_gphc_registration_number(self) -> None:
        repo = ComplianceRepository()
        with self.assertRaises(psycopg.Error):
            repo.upsert_user(
                entra_oid="oid-pharm-invalid",
                slack_user_id="U_PHARM_BAD",
                full_name="Unregistered Pharm",
                email="bad@pharmacy.co.uk",
                staff_role=StaffRole.PHARM,
                gphc_reg_number=None,
            )

        valid_pharm = repo.upsert_user(
            entra_oid="oid-pharm-valid",
            slack_user_id="U_PHARM_OK",
            full_name="Anjum Superintendent RP",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2054321",
        )
        self.assertEqual(valid_pharm.gphc_reg_number, "2054321")
        repo.close()

    def test_audit_ledger_blocks_sql_update_and_delete_at_db_trigger_level(self) -> None:
        repo = ComplianceRepository()
        repo.seed_tasks_from_sql_file()
        repo.ensure_instances_for_date(date(2026, 10, 13))

        events = repo.get_all_audit_events()
        self.assertEqual(len(events), 33)

        # Critic Attack 1: Attempt direct SQL UPDATE on PostgreSQL task_events_audit
        with self.assertRaisesRegex(
            psycopg.Error,
            "COMPLIANCE VIOLATION: task_events_audit is strictly append-only",
        ):
            with repo.conn.transaction():
                repo.conn.execute("UPDATE task_events_audit SET actor_role = 'Pharm' WHERE audit_seq = 1")

        # Critic Attack 2: Attempt direct SQL DELETE on PostgreSQL task_events_audit
        with self.assertRaisesRegex(
            psycopg.Error,
            "COMPLIANCE VIOLATION: task_events_audit is strictly append-only",
        ):
            with repo.conn.transaction():
                repo.conn.execute("DELETE FROM task_events_audit WHERE audit_seq = 1")
        repo.close()

    def test_sha256_hash_chain_detects_storage_level_tampering(self) -> None:
        repo = ComplianceRepository()
        repo.seed_tasks_from_sql_file()
        repo.ensure_instances_for_date(date(2026, 10, 13))

        verification = repo.verify_ledger_integrity()
        self.assertTrue(verification.is_valid)
        self.assertEqual(verification.total_rows_checked, 33)

        # Critic Attack 3: Simulate a rogue cloud superuser dropping the PostgreSQL trigger and altering a timestamp
        with repo.conn.transaction():
            repo.conn.execute("DROP TRIGGER trg_prevent_audit_row_mutation ON task_events_audit;")
            repo.conn.execute(
                "UPDATE task_events_audit SET occurred_at = '2026-10-13T08:00:00.000000Z' WHERE audit_seq = 10"
            )

        tampered_check = repo.verify_ledger_integrity()
        self.assertFalse(tampered_check.is_valid)
        self.assertEqual(tampered_check.first_broken_seq, 10)
        self.assertIn("Tampering detected at audit_seq=10", tampered_check.failure_reason or "")
        repo.close()

    def test_postgres_ddl_and_seed_files_are_complete(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ddl_sql = (root / "db" / "01_schema.sql").read_text(encoding="utf-8")
        seed_sql = (root / "db" / "02_seed_tasks.sql").read_text(encoding="utf-8")

        self.assertIn("CREATE TRIGGER trg_audit_compute_hash_chain", ddl_sql)
        self.assertIn("CREATE TRIGGER trg_prevent_audit_row_mutation", ddl_sql)
        self.assertIn("REVOKE UPDATE, DELETE, TRUNCATE ON task_events_audit FROM app_compliance_writer", ddl_sql)
        self.assertIn("Collection Box Audit", seed_sql)
        self.assertIn("Fridge Check (Min/Max/Current)", seed_sql)


if __name__ == "__main__":
    unittest.main()
