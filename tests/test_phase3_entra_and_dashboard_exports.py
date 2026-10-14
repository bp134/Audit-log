"""
Phase 3 Critic Verification Gate:
Tests Microsoft Entra ID OIDC claim verification, tenant isolation, RBAC enforcement,
dashboard summary metrics, and one-click GPhC inspection CSV & Markdown report generation.
"""

from __future__ import annotations

from datetime import date
import unittest

from src.dashboard.auth import EntraIDAuthenticator
from src.dashboard.reporting import (
    build_dashboard_summary,
    export_inspection_csv,
    generate_daily_compliance_report_markdown,
)
from src.domain.models import AuditEventType, StaffRole
from src.repository.db_repo import ComplianceRepository


class Phase3CriticTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = ComplianceRepository(":memory:")
        self.repo.seed_tasks_from_sql_file()
        self.tenant_id = "tenant-pharmacy-uk-001"
        self.auth = EntraIDAuthenticator(self.repo, expected_tenant_id=self.tenant_id)

        self.pharm = self.repo.upsert_user(
            entra_oid="oid-anjum-pharm-001",
            slack_user_id="U_PHARM_ANJUM",
            full_name="Anjum Superintendent RP",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2054321",
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_entra_oidc_blocks_wrong_tenant_and_unmapped_users(self) -> None:
        # Critic Attack 1: Token from an external/foreign Microsoft Entra tenant
        foreign_res = self.auth.verify_oidc_claims(
            {"tid": "foreign-tenant-999", "oid": self.pharm.entra_oid}
        )
        self.assertFalse(foreign_res.authenticated)
        self.assertIn("tenant ID does not match", foreign_res.error_message or "")

        # Critic Attack 2: Valid tenant, but user OID is not mapped in users_rbac
        unmapped_res = self.auth.verify_oidc_claims(
            {"tid": self.tenant_id, "oid": "oid-unknown-contractor"}
        )
        self.assertFalse(unmapped_res.authenticated)
        self.assertIn("not assigned an active pharmacy RBAC role", unmapped_res.error_message or "")

        # Verify both unauthorized dashboard login attempts were recorded in task_events_audit
        denials = [
            e
            for e in self.repo.get_all_audit_events()
            if e["event_type"] == AuditEventType.RBAC_ACCESS_DENIED.value
        ]
        self.assertEqual(len(denials), 2)

        # Valid Entra ID login succeeds
        ok_res = self.auth.verify_oidc_claims(
            {"tid": self.tenant_id, "oid": self.pharm.entra_oid}
        )
        self.assertTrue(ok_res.authenticated)
        self.assertEqual(ok_res.user.full_name, "Anjum Superintendent RP")  # type: ignore[union-attr]

    def test_dashboard_summary_and_gphc_inspection_exports(self) -> None:
        op_date = date(2026, 10, 13)
        instances = self.repo.ensure_instances_for_date(op_date)

        # Complete Fridge Check and CD Register Reconcile
        fridge = next(i for i in instances if i.task_name == "Fridge Check (Min/Max/Current)")
        cd_rec = next(i for i in instances if i.task_name == "CD Register Reconcile")

        self.repo.complete_task_instance(
            instance_id=fridge.instance_id,
            actor_slack_id=self.pharm.slack_user_id,
            fridge_readings={"min_temp_c": 2.9, "max_temp_c": 6.1, "current_temp_c": 4.4},
            notes="Checked and thermometer reset.",
        )
        self.repo.complete_task_instance(
            instance_id=cd_rec.instance_id,
            actor_slack_id=self.pharm.slack_user_id,
        )

        summary = build_dashboard_summary(self.repo, op_date)
        self.assertEqual(summary.daily_completed, 2)
        self.assertEqual(summary.daily_total, 14)
        self.assertEqual(summary.morning_completed, 1)
        self.assertEqual(summary.eod_completed, 1)
        self.assertTrue(summary.fridge_completed_today)
        self.assertTrue(summary.fridge_in_safe_range)
        self.assertTrue(summary.ledger_verification.is_valid)

        csv_out = export_inspection_csv(self.repo, op_date)
        self.assertIn("Fridge Check (Min/Max/Current)", csv_out)
        self.assertIn("2.9", csv_out)
        self.assertIn("Anjum Superintendent RP", csv_out)

        md_report = generate_daily_compliance_report_markdown(self.repo, op_date)
        self.assertIn("SAFE (2.0C-8.0C) | Min: 2.9C, Max: 6.1C, Current: 4.4C", md_report)
        self.assertIn("Ledger Integrity Valid:** `PASSED`", md_report)


if __name__ == "__main__":
    unittest.main()
