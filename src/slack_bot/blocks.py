"""Slack Block Kit payload builders for Tranche checklists, Fridge Temperature Modal, and Escalations."""

from __future__ import annotations

from datetime import date
from typing import Any

from src.domain.models import InstanceStatus, RoleRequirement, TaskInstanceRecord


def _role_badge(role: RoleRequirement) -> str:
    if role == RoleRequirement.PHARM:
        return "🔒 *[Pharmacist Only]*"
    if role == RoleRequirement.DISPENSER:
        return "💊 *[Dispenser / Pharm]*"
    return "👥 *[Either Pharm or Dispenser]*"


def build_task_row_block(instance: TaskInstanceRecord) -> dict[str, Any]:
    """
    Renders a single task inside a Slack Block Kit checklist.
    - If completed: displays a green check, actor name, role, and structured temperature data (if Fridge Check).
    - If pending/escalated: displays an interactive button ('Log Fridge Temps' or 'Mark Complete').
    """
    if instance.status == InstanceStatus.COMPLETED:
        temp_summary = ""
        if instance.requires_structured_input and instance.structured_data:
            sd = instance.structured_data
            status_tag = "🟢 Safe (2–8°C)" if sd.get("in_safe_range", True) else "🚨 EXCURSION LOGGED"
            temp_summary = (
                f"\n      • Readings: `Min: {sd.get('min_temp_c')}°C` | "
                f"`Max: {sd.get('max_temp_c')}°C` | `Current: {sd.get('current_temp_c')}°C` ({status_tag})"
            )
            if sd.get("corrective_action_note"):
                temp_summary += f"\n      • Action: _{sd['corrective_action_note']}_"

        completed_time = (
            instance.completed_at.strftime("%H:%M") if instance.completed_at else "recorded"
        )
        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"✅ ~*{instance.task_name}*~ — Completed by *{instance.completed_by_name}* "
                    f"(`{instance.completed_by_role}`) at `{completed_time}`{temp_summary}"
                ),
            },
        }

    prefix = "🚨 *[OVERDUE ESCALATION]* " if instance.status == InstanceStatus.ESCALATED else "⬜ "
    badge = _role_badge(instance.assigned_role)

    if instance.requires_structured_input:
        accessory = {
            "type": "button",
            "text": {"type": "plain_text", "text": "🌡️ Log Temperatures", "emoji": True},
            "style": "primary",
            "action_id": f"open_fridge_modal:{instance.instance_id}",
            "value": instance.instance_id,
        }
    else:
        accessory = {
            "type": "button",
            "text": {"type": "plain_text", "text": "✓ Mark Complete", "emoji": True},
            "style": "danger" if instance.status == InstanceStatus.ESCALATED else "primary",
            "action_id": f"complete_task:{instance.instance_id}",
            "value": instance.instance_id,
        }

    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"{prefix}*{instance.task_name}*  {badge}\n      _Cycle: `{instance.period_key}`_",
        },
        "accessory": accessory,
    }


def build_tranche_checklist_blocks(
    *,
    tranche_name: str,
    target_date: date,
    daily_tasks: list[TaskInstanceRecord],
    weekly_tasks: list[TaskInstanceRecord],
    monthly_tasks: list[TaskInstanceRecord],
    escalated_tasks: list[TaskInstanceRecord],
) -> list[dict[str, Any]]:
    """
    Constructs the full Slack Block Kit payload for Morning, Mid-Day, or End-of-Day tranches.
    """
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"📋 Pharmacy Compliance Checklist — {tranche_name} Tranche ({target_date.isoformat()})",
                "emoji": True,
            },
        }
    ]

    if escalated_tasks:
        overdue_names = ", ".join(f"*{t.task_name}*" for t in escalated_tasks)
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"🚨 *ESCALATION ALERT:* {len(escalated_tasks)} overdue task(s) require immediate attention: "
                        f"{overdue_names}"
                    ),
                },
            }
        )
        blocks.append({"type": "divider"})

    if daily_tasks:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*🗓️ Today's Daily Tasks*"},
            }
        )
        for t in daily_tasks:
            blocks.append(build_task_row_block(t))
        blocks.append({"type": "divider"})

    pending_weekly = [w for w in weekly_tasks if w.status != InstanceStatus.COMPLETED]
    completed_weekly_count = len(weekly_tasks) - len(pending_weekly)
    blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*📅 This Week's Tasks ({completed_weekly_count}/{len(weekly_tasks)} Completed)* "
                    "— _Complete once on any day this week_"
                ),
            },
        }
    )
    for w in pending_weekly:
        blocks.append(build_task_row_block(w))
    blocks.append({"type": "divider"})

    pending_monthly = [m for m in monthly_tasks if m.status != InstanceStatus.COMPLETED]
    completed_monthly_count = len(monthly_tasks) - len(pending_monthly)
    blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*📆 This Month's Tasks ({completed_monthly_count}/{len(monthly_tasks)} Completed)* "
                    "— _Complete once on any day this month_"
                ),
            },
        }
    )
    for m in pending_monthly:
        blocks.append(build_task_row_block(m))

    return blocks


def build_fridge_temperature_modal(instance: TaskInstanceRecord) -> dict[str, Any]:
    """
    Constructs the Slack Block Kit Modal for `Fridge Check (Min/Max/Current)`
    requiring Min (°C), Max (°C), Current (°C), and Corrective Action Note if outside 2.0–8.0°C.
    """
    return {
        "type": "modal",
        "callback_id": f"submit_fridge_modal:{instance.instance_id}",
        "private_metadata": instance.instance_id,
        "title": {"type": "plain_text", "text": "Fridge Temperature Check"},
        "submit": {"type": "plain_text", "text": "Record & Sign Off"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{instance.task_name}* (`{instance.period_key}`)\n"
                        "Safe cold-chain operating range is *2.0°C to 8.0°C*. "
                        "If any reading is outside this range, you *must* enter a corrective action note."
                    ),
                },
            },
            {
                "type": "input",
                "block_id": "min_temp_block",
                "label": {"type": "plain_text", "text": "Minimum Temperature (°C)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "min_temp_input",
                    "placeholder": {"type": "plain_text", "text": "e.g. 2.8"},
                },
            },
            {
                "type": "input",
                "block_id": "max_temp_block",
                "label": {"type": "plain_text", "text": "Maximum Temperature (°C)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "max_temp_input",
                    "placeholder": {"type": "plain_text", "text": "e.g. 6.4"},
                },
            },
            {
                "type": "input",
                "block_id": "current_temp_block",
                "label": {"type": "plain_text", "text": "Current Temperature (°C)"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "current_temp_input",
                    "placeholder": {"type": "plain_text", "text": "e.g. 4.5"},
                },
            },
            {
                "type": "input",
                "block_id": "action_note_block",
                "optional": True,
                "label": {
                    "type": "plain_text",
                    "text": "Corrective Action / Reset Note (Mandatory if <2°C or >8°C)",
                },
                "element": {
                    "type": "plain_text_input",
                    "action_id": "action_note_input",
                    "multiline": True,
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Thermometer reset after check. If excursion occurred, state stock quarantine/investigation steps.",
                    },
                },
            },
        ],
    }
