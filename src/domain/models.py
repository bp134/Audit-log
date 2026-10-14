"""Core domain models, RBAC permission logic, Fridge temperature validation, and Period calculations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from enum import Enum
import calendar
from typing import Any, Optional


class TaskFrequency(str, Enum):
    DAILY = "Daily"
    WEEKLY = "Weekly"
    MONTHLY = "Monthly"


class DailyWindow(str, Enum):
    MORNING = "Morning"
    ANYTIME = "Anytime"
    END_OF_DAY = "End_Of_Day"


class StaffRole(str, Enum):
    PHARM = "Pharm"
    DISPENSER = "Dispenser"
    MANAGER = "Manager"


class RoleRequirement(str, Enum):
    PHARM = "Pharm"
    DISPENSER = "Dispenser"
    EITHER = "Either"


class InstanceStatus(str, Enum):
    PENDING = "Pending"
    COMPLETED = "Completed"
    ESCALATED = "Escalated"
    MISSED = "Missed"


class AuditEventType(str, Enum):
    INSTANCE_SCHEDULED = "INSTANCE_SCHEDULED"
    REMINDER_DISPATCHED = "REMINDER_DISPATCHED"
    TASK_COMPLETED = "TASK_COMPLETED"
    FRIDGE_TEMP_LOGGED = "FRIDGE_TEMP_LOGGED"
    FRIDGE_OUT_OF_RANGE_ALERT = "FRIDGE_OUT_OF_RANGE_ALERT"
    RBAC_ACCESS_DENIED = "RBAC_ACCESS_DENIED"
    TASK_ESCALATED = "TASK_ESCALATED"
    BREAK_GLASS_VERIFIED = "BREAK_GLASS_VERIFIED"


def normalize_role_label(raw_label: str) -> RoleRequirement:
    """
    Normalizes the user's SQL role labels into strict RBAC requirements.
    Per user agreement:
      - 'Dispenser / Pharm' and 'Pharm / Dispenser' are identical -> RoleRequirement.EITHER
      - 'Pharm' -> RoleRequirement.PHARM
      - 'Dispenser' -> RoleRequirement.DISPENSER
    """
    cleaned = raw_label.strip()
    if cleaned in ("Dispenser / Pharm", "Pharm / Dispenser", "Either"):
        return RoleRequirement.EITHER
    if cleaned == "Pharm":
        return RoleRequirement.PHARM
    if cleaned == "Dispenser":
        return RoleRequirement.DISPENSER
    raise ValueError(f"Unrecognized role label: {raw_label!r}")


def is_role_authorized(user_role: StaffRole, required_role: RoleRequirement) -> bool:
    """
    Determines whether a user with `user_role` is permitted to complete a task requiring `required_role`.
    - RoleRequirement.PHARM: Strictly requires a Pharmacist ('Pharm').
      Dispensers and non-pharmacist Managers cannot sign off RP/Pharmacist-only tasks.
    - RoleRequirement.DISPENSER: Can be completed by a Dispenser OR a Pharmacist covering dispensary duties.
    - RoleRequirement.EITHER: Can be completed by either a Pharmacist or a Dispenser.
    """
    if required_role == RoleRequirement.PHARM:
        return user_role == StaffRole.PHARM
    if required_role in (RoleRequirement.DISPENSER, RoleRequirement.EITHER):
        return user_role in (StaffRole.PHARM, StaffRole.DISPENSER)
    return False


@dataclass(frozen=True)
class PeriodBounds:
    period_key: str
    start_date: date
    end_date: date


def compute_period_bounds(frequency: TaskFrequency, target_date: date) -> PeriodBounds:
    """
    Calculates the unique cycle period_key and start/end dates:
    - Daily:   'YYYY-MM-DD' (must be completed every day)
    - Weekly:  'YYYY-Www'   (completed once on ANY day of the ISO week Monday..Sunday)
    - Monthly: 'YYYY-MM'    (completed once on ANY day of the calendar month)
    """
    if frequency == TaskFrequency.DAILY:
        return PeriodBounds(
            period_key=target_date.isoformat(),
            start_date=target_date,
            end_date=target_date,
        )
    if frequency == TaskFrequency.WEEKLY:
        iso_year, iso_week, iso_weekday = target_date.isocalendar()
        week_start = target_date - timedelta(days=iso_weekday - 1)
        week_end = week_start + timedelta(days=6)
        return PeriodBounds(
            period_key=f"{iso_year}-W{iso_week:02d}",
            start_date=week_start,
            end_date=week_end,
        )
    if frequency == TaskFrequency.MONTHLY:
        first_day = target_date.replace(day=1)
        _, last_day_num = calendar.monthrange(target_date.year, target_date.month)
        last_day = target_date.replace(day=last_day_num)
        return PeriodBounds(
            period_key=f"{target_date.year:04d}-{target_date.month:02d}",
            start_date=first_day,
            end_date=last_day,
        )
    raise ValueError(f"Unsupported task frequency: {frequency}")


@dataclass(frozen=True)
class FridgeReadingValidation:
    is_valid_input: bool
    in_safe_range: bool
    min_temp_c: float
    max_temp_c: float
    current_temp_c: float
    corrective_action_note: str
    error_message: Optional[str] = None


def validate_fridge_reading(
    min_temp_c: float,
    max_temp_c: float,
    current_temp_c: float,
    corrective_action_note: str = "",
    safe_min_c: float = 2.0,
    safe_max_c: float = 8.0,
) -> FridgeReadingValidation:
    """
    Validates pharmacy cold-chain fridge temperature readings (2.0°C to 8.0°C standard).
    - Physical sanity check: min_temp_c <= current_temp_c <= max_temp_c
    - Cold-chain compliance check: if any reading is < 2.0°C or > 8.0°C, a corrective action note is mandatory.
    """
    if min_temp_c > max_temp_c:
        return FridgeReadingValidation(
            is_valid_input=False,
            in_safe_range=False,
            min_temp_c=min_temp_c,
            max_temp_c=max_temp_c,
            current_temp_c=current_temp_c,
            corrective_action_note=corrective_action_note,
            error_message=f"Minimum temperature ({min_temp_c}°C) cannot exceed Maximum temperature ({max_temp_c}°C).",
        )

    if not (min_temp_c <= current_temp_c <= max_temp_c):
        return FridgeReadingValidation(
            is_valid_input=False,
            in_safe_range=False,
            min_temp_c=min_temp_c,
            max_temp_c=max_temp_c,
            current_temp_c=current_temp_c,
            corrective_action_note=corrective_action_note,
            error_message=(
                f"Current temperature ({current_temp_c}°C) must lie between "
                f"Min ({min_temp_c}°C) and Max ({max_temp_c}°C)."
            ),
        )

    in_range = (
        safe_min_c <= min_temp_c <= safe_max_c
        and safe_min_c <= max_temp_c <= safe_max_c
        and safe_min_c <= current_temp_c <= safe_max_c
    )

    if not in_range and not corrective_action_note.strip():
        return FridgeReadingValidation(
            is_valid_input=False,
            in_safe_range=False,
            min_temp_c=min_temp_c,
            max_temp_c=max_temp_c,
            current_temp_c=current_temp_c,
            corrective_action_note=corrective_action_note,
            error_message=(
                f"Temperature excursion detected outside {safe_min_c}°C–{safe_max_c}°C! "
                "A corrective action note is mandatory for GPhC compliance."
            ),
        )

    return FridgeReadingValidation(
        is_valid_input=True,
        in_safe_range=in_range,
        min_temp_c=min_temp_c,
        max_temp_c=max_temp_c,
        current_temp_c=current_temp_c,
        corrective_action_note=corrective_action_note.strip(),
        error_message=None,
    )


@dataclass
class UserRecord:
    user_id: str
    entra_oid: str
    slack_user_id: str
    full_name: str
    email: str
    staff_role: StaffRole
    gphc_reg_number: Optional[str] = None
    is_active: bool = True


@dataclass
class TaskMasterRecord:
    task_id: int
    task_name: str
    frequency: TaskFrequency
    daily_timing_window: Optional[DailyWindow]
    assigned_role: RoleRequirement
    original_role_label: str
    requires_structured_input: bool = False
    input_schema: dict[str, Any] = field(default_factory=dict)
    is_active: bool = True


@dataclass
class TaskInstanceRecord:
    instance_id: str
    task_id: int
    task_name: str
    frequency: TaskFrequency
    daily_timing_window: Optional[DailyWindow]
    assigned_role: RoleRequirement
    requires_structured_input: bool
    period_key: str
    period_start_date: date
    period_end_date: date
    status: InstanceStatus
    completed_by_user_id: Optional[str] = None
    completed_by_name: Optional[str] = None
    completed_by_role: Optional[ str] = None
    completed_at: Optional[datetime] = None
    structured_data: dict[str, Any] = field(default_factory=dict)
    notes: Optional[str] = None
    escalation_count: int = 0
