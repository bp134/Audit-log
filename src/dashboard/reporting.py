"""Pre-configured compliance analytics and one-click GPhC inspection pack exporter."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date
import io
from typing import Any, Optional

from src.domain.ledger import LedgerVerificationResult
from src.domain.models import (
    DailyWindow,
    InstanceStatus,
    TaskFrequency,
    TaskInstanceRecord,
)
from src.repository.db_repo import ComplianceRepository


@dataclass(frozen=True)
class ComplianceDashboardSummary:
    target_date: date
    daily_completed: int
    daily_total: int
    morning_completed: int
    morning_total: int
    anytime_completed: int
    anytime_total: int
    eod_completed: int
    eod_total: int
    weekly_completed: int
    weekly_total: int
    monthly_completed: int
    monthly_total: int
    escalated_count: int
    fridge_completed_today: bool
    fridge_in_safe_range: Optional[bool]
    fridge_readings: dict[str, Any]
    ledger_verification: LedgerVerificationResult


def build_dashboard_summary(repo: ComplianceRepository, target_date: date) -> ComplianceDashboardSummary:
    instances = repo.ensure_instances_for_date(target_date)

    daily = [i for i in instances if i.frequency == TaskFrequency.DAILY]
    weekly = [i for i in instances if i.frequency == TaskFrequency.WEEKLY]
    monthly = [i for i in instances if i.frequency == TaskFrequency.MONTHLY]

    morning = [i for i in daily if i.daily_timing_window == DailyWindow.MORNING]
    anytime = [i for i in daily if i.daily_timing_window == DailyWindow.ANYTIME]
    eod = [i for i in daily if i.daily_timing_window == DailyWindow.END_OF_DAY]

    fridge = next((i for i in daily if i.requires_structured_input), None)
    fridge_done = bool(fridge and fridge.status == InstanceStatus.COMPLETED)
    fridge_data = fridge.structured_data if (fridge and fridge.structured_data) else {}
    fridge_safe = fridge_data.get("in_safe_range") if fridge_done else None

    ledger_check = repo.verify_ledger_integrity()

    return ComplianceDashboardSummary(
        target_date=target_date,
        daily_completed=sum(1 for i in daily if i.status == InstanceStatus.COMPLETED),
        daily_total=len(daily),
        morning_completed=sum(1 for i in morning if i.status == InstanceStatus.COMPLETED),
        morning_total=len(morning),
        anytime_completed=sum(1 for i in anytime if i.status == InstanceStatus.COMPLETED),
        anytime_total=len(anytime),
        eod_completed=sum(1 for i in eod if i.status == InstanceStatus.COMPLETED),
        eod_total=len(eod),
        weekly_completed=sum(1 for i in weekly if i.status == InstanceStatus.COMPLETED),
        weekly_total=len(weekly),
        monthly_completed=sum(1 for i in monthly if i.status == InstanceStatus.COMPLETED),
        monthly_total=len(monthly),
        escalated_count=sum(1 for i in instances if i.status == InstanceStatus.ESCALATED),
        fridge_completed_today=fridge_done,
        fridge_in_safe_range=fridge_safe,
        fridge_readings=fridge_data,
        ledger_verification=ledger_check,
    )


def export_inspection_csv(repo: ComplianceRepository, target_date: date) -> str:
    """
    Exports a flat, inspector-friendly CSV of all active Daily, Weekly, and Monthly tasks,
    their completion status, who signed them off, timestamps, and Fridge temperature readings.
    """
    instances: list[TaskInstanceRecord] = repo.ensure_instances_for_date(target_date)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "Period Key",
            "Frequency",
            "Daily Window",
            "Task Name",
            "Required Role",
            "Status",
            "Completed By",
            "Completed Role",
            "Completed At (UTC)",
            "Fridge Min (C)",
            "Fridge Max (C)",
            "Fridge Current (C)",
            "Notes / Action",
            "Escalations",
        ]
    )
    for inst in instances:
        sd = inst.structured_data or {}
        writer.writerow(
            [
                inst.period_key,
                inst.frequency.value,
                inst.daily_timing_window.value if inst.daily_timing_window else "Any Day in Period",
                inst.task_name,
                inst.assigned_role.value,
                inst.status.value,
                inst.completed_by_name or "",
                inst.completed_by_role or "",
                inst.completed_at.isoformat() if inst.completed_at else "",
                sd.get("min_temp_c", ""),
                sd.get("max_temp_c", ""),
                sd.get("current_temp_c", ""),
                inst.notes or sd.get("corrective_action_note", ""),
                inst.escalation_count,
            ]
        )
    return buf.getvalue()


def generate_daily_compliance_report_markdown(repo: ComplianceRepository, target_date: date) -> str:
    """
    Generates a signed, human-readable Markdown compliance report suitable for GPhC inspection
    and nightly encrypted archival to Hetzner S3.
    """
    summary = build_dashboard_summary(repo, target_date)
    ledger = summary.ledger_verification

    fridge_line = "PENDING"
    if summary.fridge_completed_today:
        r = summary.fridge_readings
        range_label = "SAFE (2.0C-8.0C)" if summary.fridge_in_safe_range else "EXCURSION LOGGED"
        fridge_line = (
            f"{range_label} | Min: {r.get('min_temp_c')}C, "
            f"Max: {r.get('max_temp_c')}C, Current: {r.get('current_temp_c')}C"
        )

    lines = [
        f"# Pharmacy Compliance & Audit Report — {target_date.isoformat()}",
        "",
        "## 1. Executive Summary",
        f"- **Daily Tasks Completed:** {summary.daily_completed} / {summary.daily_total} "
        f"(Morning: {summary.morning_completed}/{summary.morning_total}, "
        f"Anytime: {summary.anytime_completed}/{summary.anytime_total}, "
        f"End-of-Day: {summary.eod_completed}/{summary.eod_total})",
        f"- **Weekly Tasks Completed (Current Week):** {summary.weekly_completed} / {summary.weekly_total}",
        f"- **Monthly Tasks Completed (Current Month):** {summary.monthly_completed} / {summary.monthly_total}",
        f"- **Active Overdue Escalations:** {summary.escalated_count}",
        f"- **Cold-Chain Fridge Status:** {fridge_line}",
        "",
        "## 2. Cryptographic Audit Ledger Verification",
        f"- **Ledger Integrity Valid:** `{'PASSED' if ledger.is_valid else 'FAILED'}`",
        f"- **Total Immutable Audit Events Checked:** `{ledger.total_rows_checked}`",
        f"- **Ledger Head SHA-256 Digest:** `{ledger.head_hash}`",
    ]
    return "\n".join(lines)
