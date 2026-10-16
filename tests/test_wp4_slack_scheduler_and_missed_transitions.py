"""
Deterministic PostgreSQL Acceptance Tests for WP-4
(Audit IDs: ID-003 [Slack & APScheduler], ID-018, ID-019, ID-024).
"""

from __future__ import annotations

from datetime import date
import hashlib
import hmac
import time
import unittest

from src.config import AppConfig
from src.domain.models import DailyWindow, InstanceStatus, StaffRole
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.handlers import SlackComplianceHandler, verify_slack_request_signature
from src.slack_bot.scheduler import TrancheSchedulerEngine, TrancheWindow
from src.slack_bot.service import build_bolt_app, build_tranche_scheduler


class TestWP4SlackSchedulerAndMissedTransitions(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = ComplianceRepository()
        self.repo.seed_tasks_from_sql_file()
        self.signing_secret = "slack-test-signing-secret-2026"
        self.handler = SlackComplianceHandler(
            self.repo,
            signing_secret=self.signing_secret,
        )
        self.scheduler = TrancheSchedulerEngine(self.repo)
        self.pharm = self.repo.upsert_user(
            entra_oid="oid-pharm-wp4",
            slack_user_id="U_PHARM_WP4",
            full_name="Anjum Superintendent RP",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2054321",
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_id024_slack_hmac_sha256_signature_and_replay_protection(self) -> None:
        now_ts = str(int(time.time()))
        raw_body = "payload=%7B%22type%22%3A%22block_actions%22%7D"
        digest = hmac.new(
            self.signing_secret.encode("utf-8"),
            f"v0:{now_ts}:{raw_body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        valid_sig = f"v0={digest}"

        self.assertTrue(
            verify_slack_request_signature(
                signing_secret=self.signing_secret,
                timestamp=now_ts,
                body=raw_body,
                signature=valid_sig,
            )
        )

        # Replay attack (> 300s old) is rejected
        stale_ts = str(int(time.time()) - 600)
        stale_digest = hmac.new(
            self.signing_secret.encode("utf-8"),
            f"v0:{stale_ts}:{raw_body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertFalse(
            verify_slack_request_signature(
                signing_secret=self.signing_secret,
                timestamp=stale_ts,
                body=raw_body,
                signature=f"v0={stale_digest}",
            )
        )

        # Forged signature rejected at handler boundary and logged to PostgreSQL audit ledger
        instances = self.repo.ensure_instances_for_date(date(2026, 10, 16))
        target = next(i for i in instances if i.task_name == "CD Register Reconcile")
        bad_resp = self.handler.handle_button_click(
            action_id=f"complete_task:{target.instance_id}",
            actor_slack_id=self.pharm.slack_user_id,
            signature="v0=0000000000000000000000000000000000000000000000000000000000000000",
            timestamp=now_ts,
            raw_body=raw_body,
        )
        self.assertFalse(bad_resp.ok)
        self.assertIn("signature verification failed", bad_resp.ephemeral_message)

        ok_resp = self.handler.handle_button_click(
            action_id=f"complete_task:{target.instance_id}",
            actor_slack_id=self.pharm.slack_user_id,
            signature=valid_sig,
            timestamp=now_ts,
            raw_body=raw_body,
        )
        self.assertTrue(ok_resp.ok)

    def test_id018_closing_audit_escalates_end_of_day_window_tasks_only(self) -> None:
        op_date = date(2026, 10, 16)
        self.repo.ensure_instances_for_date(op_date)

        closing_res = self.scheduler.run_tranche(TrancheWindow.CLOSING_AUDIT, op_date)
        # Only the 5 End_Of_Day tasks should be escalated by CLOSING_AUDIT (not Morning/Anytime)
        self.assertEqual(len(closing_res.escalated_instances), 5)
        self.assertTrue(
            all(i.daily_timing_window == DailyWindow.END_OF_DAY for i in closing_res.escalated_instances)
        )

    def test_id019_overdue_uncompleted_tasks_automatically_transition_to_missed(self) -> None:
        day_one = date(2026, 10, 15)
        day_two = date(2026, 10, 16)

        day_one_instances = self.repo.ensure_instances_for_date(day_one)
        cd_task = next(i for i in day_one_instances if i.task_name == "CD Register Reconcile")
        self.repo.complete_task_instance(
            instance_id=cd_task.instance_id,
            actor_slack_id=self.pharm.slack_user_id,
        )

        # Running Day 2 Morning tranche automatically closes expired Day 1 daily instances -> Missed
        self.scheduler.run_tranche(TrancheWindow.MORNING, day_two)

        refreshed_cd = self.repo.get_instance_by_id(cd_task.instance_id)
        self.assertIsNotNone(refreshed_cd)
        self.assertEqual(refreshed_cd.status, InstanceStatus.COMPLETED)  # type: ignore[union-attr]

        uncompleted_day_one = [
            self.repo.get_instance_by_id(i.instance_id)
            for i in day_one_instances
            if i.frequency.value == "Daily" and i.instance_id != cd_task.instance_id
        ]
        self.assertEqual(len(uncompleted_day_one), 13)
        self.assertTrue(all(inst is not None and inst.status == InstanceStatus.MISSED for inst in uncompleted_day_one))
        self.assertTrue(self.repo.verify_ledger_integrity().is_valid)

    def test_id003_bolt_app_and_apscheduler_cron_jobs_wired(self) -> None:
        cfg = AppConfig()
        bolt_app = build_bolt_app(cfg, self.handler)
        self.assertIsNotNone(bolt_app)

        bg_sched = build_tranche_scheduler(cfg, self.scheduler, bolt_app=bolt_app)
        job_ids = {job.id for job in bg_sched.get_jobs()}
        self.assertEqual(
            job_ids,
            {
                "tranche_morning",
                "tranche_midday",
                "tranche_eod",
                "tranche_closing_audit",
                "close_expired_periods",
            },
        )


if __name__ == "__main__":
    unittest.main()
