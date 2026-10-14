"""
Phase 2 Critic Verification Gate:
Tests Slack Block Kit generation, Morning/Mid-Day/End-of-Day tranche scheduling,
Weekly & Monthly any-day completion persistence, RBAC enforcement on Pharmacist-only tasks,
and Fridge Temperature Modal validation (including mandatory corrective action on excursions).
"""

from __future__ import annotations

from datetime import date
import unittest

from src.domain.models import (
    AuditEventType,
    InstanceStatus,
    StaffRole,
    TaskFrequency,
)
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.handlers import SlackComplianceHandler
from src.slack_bot.scheduler import TrancheSchedulerEngine, TrancheWindow


class Phase2CriticTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = ComplianceRepository(":memory:")
        self.repo.seed_tasks_from_sql_file()
        self.pharm = self.repo.upsert_user(
            entra_oid="entra-pharm-001",
            slack_user_id="U_PHARM_ANJUM",
            full_name="Anjum (RP Pharmacist)",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2049999",
        )
        self.dispenser = self.repo.upsert_user(
            entra_oid="entra-disp-001",
            slack_user_id="U_DISP_SARAH",
            full_name="Sarah (Lead Dispenser)",
            email="sarah@pharmacy.co.uk",
            staff_role=StaffRole.DISPENSER,
        )
        self.handler = SlackComplianceHandler(self.repo)
        self.scheduler = TrancheSchedulerEngine(self.repo)

    def tearDown(self) -> None:
        self.repo.close()

    def test_dispenser_blocked_from_pharmacist_only_task_and_logged(self) -> None:
        instances = self.repo.ensure_instances_for_date(date(2026, 10, 13))
        cd_reconcile = next(i for i in instances if i.task_name == "CD Register Reconcile")

        # Critic Attack: Dispenser clicks 'Mark Complete' on a Pharmacist-only task ('CD Register Reconcile')
        resp = self.handler.handle_button_click(
            action_id=f"complete_task:{cd_reconcile.instance_id}",
            actor_slack_id=self.dispenser.slack_user_id,
        )
        self.assertFalse(resp.ok)
        self.assertIn("Access Denied", resp.ephemeral_message)

        # Verify task remains Pending
        refreshed = self.repo.get_instance_by_id(cd_reconcile.instance_id)
        self.assertIsNotNone(refreshed)
        self.assertEqual(refreshed.status, InstanceStatus.PENDING)  # type: ignore[union-attr]

        # Verify RBAC_ACCESS_DENIED was written to immutable audit trail
        audit_events = self.repo.get_all_audit_events()
        denials = [e for e in audit_events if e["event_type"] == AuditEventType.RBAC_ACCESS_DENIED.value]
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["actor_slack_id"], self.dispenser.slack_user_id)

        # Now Pharmacist completes the same task -> succeeds
        ok_resp = self.handler.handle_button_click(
            action_id=f"complete_task:{cd_reconcile.instance_id}",
            actor_slack_id=self.pharm.slack_user_id,
        )
        self.assertTrue(ok_resp.ok)
        refreshed_after = self.repo.get_instance_by_id(cd_reconcile.instance_id)
        self.assertEqual(refreshed_after.status, InstanceStatus.COMPLETED)  # type: ignore[union-attr]

    def test_fridge_check_modal_enforces_2_to_8_celsius_or_corrective_note(self) -> None:
        instances = self.repo.ensure_instances_for_date(date(2026, 10, 13))
        fridge_task = next(i for i in instances if i.task_name == "Fridge Check (Min/Max/Current)")

        # Step 1: Clicking button opens the Slack modal
        click_resp = self.handler.handle_button_click(
            action_id=f"open_fridge_modal:{fridge_task.instance_id}",
            actor_slack_id=self.dispenser.slack_user_id,
        )
        self.assertTrue(click_resp.ok)
        self.assertIsNotNone(click_resp.modal_view)
        self.assertEqual(click_resp.modal_view["type"], "modal")  # type: ignore[index]

        # Step 2: Critic Attack - Submit impossible temperatures (Min > Max)
        bad_physics = self.handler.handle_fridge_modal_submission(
            instance_id=fridge_task.instance_id,
            actor_slack_id=self.dispenser.slack_user_id,
            min_temp_raw="7.0",
            max_temp_raw="3.0",
            current_temp_raw="5.0",
        )
        self.assertFalse(bad_physics.ok)
        self.assertIn("cannot exceed Maximum", bad_physics.ephemeral_message)

        # Step 3: Critic Attack - Submit excursion (9.4°C) WITHOUT a corrective action note -> rejected!
        excursion_no_note = self.handler.handle_fridge_modal_submission(
            instance_id=fridge_task.instance_id,
            actor_slack_id=self.dispenser.slack_user_id,
            min_temp_raw="3.1",
            max_temp_raw="9.4",
            current_temp_raw="6.2",
            action_note="",
        )
        self.assertFalse(excursion_no_note.ok)
        self.assertIn("corrective action note is mandatory", excursion_no_note.ephemeral_message)

        # Step 4: Submit excursion WITH mandatory corrective action note -> accepted & logs FRIDGE_OUT_OF_RANGE_ALERT
        excursion_with_note = self.handler.handle_fridge_modal_submission(
            instance_id=fridge_task.instance_id,
            actor_slack_id=self.dispenser.slack_user_id,
            min_temp_raw="3.1",
            max_temp_raw="9.4",
            current_temp_raw="5.2",
            action_note="Door left ajar during delivery unpacking for 4 mins; stock checked with RP, thermometer reset.",
        )
        self.assertTrue(excursion_with_note.ok)

        events = self.repo.get_all_audit_events()
        excursion_alerts = [
            e for e in events if e["event_type"] == AuditEventType.FRIDGE_OUT_OF_RANGE_ALERT.value
        ]
        self.assertEqual(len(excursion_alerts), 1)

    def test_weekly_and_monthly_tasks_complete_once_on_any_day_and_persist(self) -> None:
        # Monday Oct 12, 2026
        monday = date(2026, 10, 12)
        tuesday = date(2026, 10, 13)

        mon_instances = self.repo.ensure_instances_for_date(monday)
        weekly_box_audit = next(i for i in mon_instances if i.task_name == "Collection Box Audit")
        monthly_fp34c = next(i for i in mon_instances if i.task_name == "End of Month (NHSBSA / FP34C)")

        # Complete both on Monday
        r1 = self.handler.handle_button_click(
            action_id=f"complete_task:{weekly_box_audit.instance_id}",
            actor_slack_id=self.dispenser.slack_user_id,
        )
        r2 = self.handler.handle_button_click(
            action_id=f"complete_task:{monthly_fp34c.instance_id}",
            actor_slack_id=self.pharm.slack_user_id,
        )
        self.assertTrue(r1.ok)
        self.assertTrue(r2.ok)

        # On Tuesday Oct 13, 2026: Daily tasks reset for Tuesday, but Weekly & Monthly stay Completed!
        tue_dispatch = self.scheduler.run_tranche(TrancheWindow.MORNING, tuesday)
        pending_weekly_names = [w.task_name for w in tue_dispatch.weekly_instances_pending]
        pending_monthly_names = [m.task_name for m in tue_dispatch.monthly_instances_pending]

        self.assertNotIn("Collection Box Audit", pending_weekly_names)
        self.assertNotIn("End of Month (NHSBSA / FP34C)", pending_monthly_names)
        self.assertEqual(len(tue_dispatch.weekly_instances_pending), 9)
        self.assertEqual(len(tue_dispatch.monthly_instances_pending), 8)

    def test_tranche_escalations_for_uncompleted_morning_tasks_at_midday(self) -> None:
        day = date(2026, 10, 13)
        morning_res = self.scheduler.run_tranche(TrancheWindow.MORNING, day)
        self.assertEqual(len(morning_res.escalated_instances), 0)

        # Complete only 1 of the 4 Morning tasks before Mid-Day
        handover = next(i for i in morning_res.daily_instances_shown if i.task_name == "Handover & Diary Review")
        self.handler.handle_button_click(
            action_id=f"complete_task:{handover.instance_id}",
            actor_slack_id=self.pharm.slack_user_id,
        )

        # Run Mid-Day tranche -> the other 3 Morning tasks must automatically escalate!
        midday_res = self.scheduler.run_tranche(TrancheWindow.MID_DAY, day)
        self.assertEqual(len(midday_res.escalated_instances), 3)
        escalated_names = {t.task_name for t in midday_res.escalated_instances}
        self.assertEqual(
            escalated_names,
            {"Fridge Check (Min/Max/Current)", "EPS & NHSmail Download", "Till Prep & Float"},
        )

        # Verify ledger integrity remains 100% intact after all operations
        self.assertTrue(self.repo.verify_ledger_integrity().is_valid)


if __name__ == "__main__":
    unittest.main()
