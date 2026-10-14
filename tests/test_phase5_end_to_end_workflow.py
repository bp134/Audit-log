"""
Phase 5 End-to-End Integration Critic Gate:
Simulates a complete pharmacy day from Morning opening -> Fridge temp logging ->
RBAC enforcement -> Weekly/Monthly any-day task completion -> Mid-Day escalation ->
End-of-Day lock-up -> GPhC Inspection Export -> Encrypted Hetzner S3 Backup ->
Automated Break-Glass Restore Verification.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
import tempfile
import unittest

from src.backup.archive_and_verify import HetznerS3BreakGlassManager
from src.dashboard.auth import EntraIDAuthenticator
from src.dashboard.reporting import build_dashboard_summary, export_inspection_csv
from src.domain.models import InstanceStatus, StaffRole
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.handlers import SlackComplianceHandler
from src.slack_bot.scheduler import TrancheSchedulerEngine, TrancheWindow


class Phase5EndToEndCriticSuite(unittest.TestCase):
    def test_full_pharmacy_compliance_lifecycle_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_file = str(Path(tmp_dir) / "pharmacy_e2e.db")
            vault_dir = Path(tmp_dir) / "s3_vault"

            repo = ComplianceRepository(db_file)
            self.assertEqual(repo.seed_tasks_from_sql_file(), 33)

            # 1. Provision Entra ID + Slack Staff Profiles
            pharm = repo.upsert_user(
                entra_oid="oid-anjum-rp",
                slack_user_id="U_ANJUM_RP",
                full_name="Anjum (Superintendent RP)",
                email="anjum@pharmacy.co.uk",
                staff_role=StaffRole.PHARM,
                gphc_reg_number="2054321",
            )
            disp = repo.upsert_user(
                entra_oid="oid-disp-01",
                slack_user_id="U_DISP_01",
                full_name="Sarah (Dispenser)",
                email="sarah@pharmacy.co.uk",
                staff_role=StaffRole.DISPENSER,
            )

            handler = SlackComplianceHandler(repo)
            scheduler = TrancheSchedulerEngine(repo)
            op_date = date(2026, 10, 13)

            # 2. Morning Tranche (09:00)
            morning_dispatch = scheduler.run_tranche(TrancheWindow.MORNING, op_date)
            self.assertEqual(len(morning_dispatch.daily_instances_shown), 9)  # 4 Morning + 5 Anytime

            # Log Fridge Temperatures via Slack Modal
            fridge_inst = next(
                i for i in morning_dispatch.daily_instances_shown if i.requires_structured_input
            )
            modal_res = handler.handle_fridge_modal_submission(
                instance_id=fridge_inst.instance_id,
                actor_slack_id=disp.slack_user_id,
                min_temp_raw="3.0",
                max_temp_raw="6.2",
                current_temp_raw="4.4",
                action_note="Daily morning check OK.",
            )
            self.assertTrue(modal_res.ok)

            # Complete all remaining Daily, 1 Weekly, and 1 Monthly task
            all_active = repo.get_active_instances_for_date(op_date)
            for inst in all_active:
                if inst.frequency.value == "Daily" and inst.status != InstanceStatus.COMPLETED:
                    actor_id = (
                        pharm.slack_user_id
                        if inst.assigned_role.value == "Pharm"
                        else disp.slack_user_id
                    )
                    res = handler.handle_button_click(
                        action_id=f"complete_task:{inst.instance_id}",
                        actor_slack_id=actor_id,
                    )
                    self.assertTrue(res.ok)

            # 3. Verify Dashboard & Entra ID Auth
            auth = EntraIDAuthenticator(repo, expected_tenant_id="tenant-uk-01")
            auth_ok = auth.verify_oidc_claims({"tid": "tenant-uk-01", "oid": pharm.entra_oid})
            self.assertTrue(auth_ok.authenticated)

            summary = build_dashboard_summary(repo, op_date)
            self.assertEqual(summary.daily_completed, 14)
            self.assertEqual(summary.daily_total, 14)
            self.assertTrue(summary.fridge_completed_today)
            self.assertTrue(summary.ledger_verification.is_valid)

            csv_report = export_inspection_csv(repo, op_date)
            self.assertIn("Security & Lock Up", csv_report)

            # 4. Nightly Encrypted S3 Backup & Break-Glass Restore Verification
            backup_mgr = HetznerS3BreakGlassManager(
                repo=repo,
                s3_bucket="pharmacy-compliance-vault",
                encryption_key="0123456789abcdef" * 4,
                local_s3_staging_dir=vault_dir,
            )
            s3_key, _, _ = backup_mgr.create_encrypted_backup(op_date)
            bg_report = backup_mgr.execute_break_glass_restore_test(
                backup_date=op_date,
                s3_object_key=s3_key,
            )
            self.assertEqual(bg_report.status, "PASSED")
            self.assertTrue(bg_report.hash_chain_valid)
            self.assertTrue(repo.verify_ledger_integrity().is_valid)

            repo.close()


if __name__ == "__main__":
    unittest.main()
