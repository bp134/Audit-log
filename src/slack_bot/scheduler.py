"""
Tranche Scheduler & Escalation Engine:
Orchestrates Morning, Mid-Day, and End-of-Day Slack notifications and automatic escalations
across Daily (Morning / Anytime / End_Of_Day), Weekly (any-day), and Monthly (any-day) tasks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any, Optional

from src.domain.models import (
    AuditEventType,
    DailyWindow,
    InstanceStatus,
    TaskFrequency,
    TaskInstanceRecord,
)
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.blocks import build_tranche_checklist_blocks


class TrancheWindow(str, Enum):
    MORNING = "Morning"
    MID_DAY = "Mid-Day"
    END_OF_DAY = "End-of-Day"
    CLOSING_AUDIT = "Closing-Escalation"


@dataclass
class TrancheDispatchResult:
    tranche: TrancheWindow
    target_date: date
    escalated_instances: list[TaskInstanceRecord]
    daily_instances_shown: list[TaskInstanceRecord]
    weekly_instances_pending: list[TaskInstanceRecord]
    monthly_instances_pending: list[TaskInstanceRecord]
    slack_blocks: list[dict[str, Any]]


class TrancheSchedulerEngine:
    """
    Executes the pharmacy's 3 daily reminder tranches + closing escalation check:
    1. Morning Tranche (e.g. 09:00):
       - Ensures all Daily, Weekly, and Monthly instances exist for today's cycle.
       - Posts Early Morning Daily tasks + Anytime Daily tasks + open Weekly/Monthly tasks.
    2. Mid-Day Tranche (e.g. 13:00):
       - Escalates any Early Morning Daily tasks that have still not been completed by Mid-Day!
       - Posts escalated Early Morning tasks + pending Anytime Daily tasks + open Weekly/Monthly tasks.
    3. End-of-Day Tranche (e.g. 17:30):
       - Escalates any Morning or Anytime Daily tasks still pending at End-of-Day.
       - If it is Friday/Saturday/Sunday (ISO weekday >= 5), escalates any Weekly tasks still pending for the week.
       - If within the last 3 days of the month, escalates any Monthly tasks still pending for the month.
       - Posts End-of-Day closing tasks + any escalated tasks.
    4. Closing Audit Check (e.g. 18:15):
       - Escalates any End-of-Day closing tasks (e.g. CD Register Reconcile, Security & Lock Up) not yet signed off.
    """

    def __init__(self, repo: ComplianceRepository) -> None:
        self.repo = repo

    def run_tranche(
        self,
        tranche: TrancheWindow,
        target_date: date,
        dispatched_at: Optional[datetime] = None,
    ) -> TrancheDispatchResult:
        all_instances = self.repo.ensure_instances_for_date(target_date)

        daily_all = [i for i in all_instances if i.frequency == TaskFrequency.DAILY]
        weekly_all = [i for i in all_instances if i.frequency == TaskFrequency.WEEKLY]
        monthly_all = [i for i in all_instances if i.frequency == TaskFrequency.MONTHLY]

        escalated_now: list[TaskInstanceRecord] = []

        if tranche == TrancheWindow.MORNING:
            # Show Morning + Anytime daily tasks in the Morning tranche
            daily_shown = [
                i
                for i in daily_all
                if i.daily_timing_window in (DailyWindow.MORNING, DailyWindow.ANYTIME)
            ]

        elif tranche == TrancheWindow.MID_DAY:
            # Any Morning tasks still not completed by Mid-Day are escalated!
            overdue_morning_ids = [
                i.instance_id
                for i in daily_all
                if i.daily_timing_window == DailyWindow.MORNING
                and i.status != InstanceStatus.COMPLETED
            ]
            if overdue_morning_ids:
                escalated_now.extend(
                    self.repo.escalate_overdue_instances(
                        overdue_morning_ids,
                        reason="Morning task still incomplete at Mid-Day tranche.",
                        escalated_at=dispatched_at,
                    )
                )
            # Refresh instances after escalation
            all_instances = self.repo.get_active_instances_for_date(target_date)
            daily_all = [i for i in all_instances if i.frequency == TaskFrequency.DAILY]
            daily_shown = [
                i
                for i in daily_all
                if i.daily_timing_window in (DailyWindow.MORNING, DailyWindow.ANYTIME)
            ]

        elif tranche == TrancheWindow.END_OF_DAY:
            # Escalate any Morning or Anytime tasks still incomplete by End-of-Day
            overdue_day_ids = [
                i.instance_id
                for i in daily_all
                if i.daily_timing_window in (DailyWindow.MORNING, DailyWindow.ANYTIME)
                and i.status != InstanceStatus.COMPLETED
            ]
            if overdue_day_ids:
                escalated_now.extend(
                    self.repo.escalate_overdue_instances(
                        overdue_day_ids,
                        reason="Morning/Anytime daily task still incomplete at End-of-Day tranche.",
                        escalated_at=dispatched_at,
                    )
                )

            # Escalate Weekly tasks if Friday/Saturday/Sunday and still pending
            if target_date.isoweekday() >= 5:
                overdue_weekly_ids = [
                    w.instance_id for w in weekly_all if w.status != InstanceStatus.COMPLETED
                ]
                if overdue_weekly_ids:
                    escalated_now.extend(
                        self.repo.escalate_overdue_instances(
                            overdue_weekly_ids,
                            reason="Weekly task still incomplete approaching end of week.",
                            escalated_at=dispatched_at,
                        )
                    )

            # Escalate Monthly tasks if within final 3 days of the month and still pending
            days_left_in_month = (monthly_all[0].period_end_date - target_date).days if monthly_all else 30
            if days_left_in_month <= 2:
                overdue_monthly_ids = [
                    m.instance_id for m in monthly_all if m.status != InstanceStatus.COMPLETED
                ]
                if overdue_monthly_ids:
                    escalated_now.extend(
                        self.repo.escalate_overdue_instances(
                            overdue_monthly_ids,
                            reason="Monthly task still incomplete in final 3 days of month.",
                            escalated_at=dispatched_at,
                        )
                    )

            all_instances = self.repo.get_active_instances_for_date(target_date)
            daily_all = [i for i in all_instances if i.frequency == TaskFrequency.DAILY]
            weekly_all = [i for i in all_instances if i.frequency == TaskFrequency.WEEKLY]
            monthly_all = [i for i in all_instances if i.frequency == TaskFrequency.MONTHLY]
            daily_shown = daily_all

        elif tranche == TrancheWindow.CLOSING_AUDIT:
            overdue_eod_ids = [
                i.instance_id
                for i in daily_all
                if i.status != InstanceStatus.COMPLETED
            ]
            if overdue_eod_ids:
                escalated_now.extend(
                    self.repo.escalate_overdue_instances(
                        overdue_eod_ids,
                        reason="Daily task still incomplete at Closing Audit check.",
                        escalated_at=dispatched_at,
                    )
                )
            all_instances = self.repo.get_active_instances_for_date(target_date)
            daily_all = [i for i in all_instances if i.frequency == TaskFrequency.DAILY]
            daily_shown = [i for i in daily_all if i.status != InstanceStatus.COMPLETED]
        else:
            raise ValueError(f"Unsupported tranche: {tranche}")

        blocks = build_tranche_checklist_blocks(
            tranche_name=tranche.value,
            target_date=target_date,
            daily_tasks=daily_shown,
            weekly_tasks=weekly_all,
            monthly_tasks=monthly_all,
            escalated_tasks=escalated_now,
        )

        self.repo.append_audit_event(
            event_type=AuditEventType.REMINDER_DISPATCHED,
            period_key=target_date.isoformat(),
            payload={
                "tranche": tranche.value,
                "daily_shown_count": len(daily_shown),
                "escalated_count": len(escalated_now),
                "weekly_pending_count": sum(1 for w in weekly_all if w.status != InstanceStatus.COMPLETED),
                "monthly_pending_count": sum(1 for m in monthly_all if m.status != InstanceStatus.COMPLETED),
            },
            occurred_at=dispatched_at,
        )

        return TrancheDispatchResult(
            tranche=tranche,
            target_date=target_date,
            escalated_instances=escalated_now,
            daily_instances_shown=daily_shown,
            weekly_instances_pending=[w for w in weekly_all if w.status != InstanceStatus.COMPLETED],
            monthly_instances_pending=[m for m in monthly_all if m.status != InstanceStatus.COMPLETED],
            slack_blocks=blocks,
        )
