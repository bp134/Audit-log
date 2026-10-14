"""Slack Socket Mode interaction handlers enforcing RBAC and immutable audit logging."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from src.domain.models import is_role_authorized
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.blocks import build_fridge_temperature_modal


@dataclass
class SlackInteractionResponse:
    ok: bool
    ephemeral_message: str
    modal_view: Optional[dict[str, Any]] = None
    updated_instance_id: Optional[str] = None


class SlackComplianceHandler:
    """
    Handles interactive Slack Block Kit button clicks and modal submissions.
    Decoupled from network transport so it can be driven by Slack Bolt Socket Mode in production
    and directly stress-tested by the Critic suite.
    """

    def __init__(self, repo: ComplianceRepository) -> None:
        self.repo = repo

    def handle_button_click(
        self,
        *,
        action_id: str,
        actor_slack_id: str,
        clicked_at: Optional[datetime] = None,
    ) -> SlackInteractionResponse:
        """
        Handles either:
        - `complete_task:<instance_id>` -> 1-click completion (after RBAC check)
        - `open_fridge_modal:<instance_id>` -> RBAC check, then returns the Fridge Temperature Modal view
        """
        if ":" not in action_id:
            return SlackInteractionResponse(ok=False, ephemeral_message="Malformed Slack action_id.")

        verb, instance_id = action_id.split(":", 1)

        if verb == "open_fridge_modal":
            instance = self.repo.get_instance_by_id(instance_id)
            if not instance:
                return SlackInteractionResponse(ok=False, ephemeral_message="Task instance not found.")

            actor = self.repo.get_user_by_slack_id(actor_slack_id)
            if not actor or not is_role_authorized(actor.staff_role, instance.assigned_role):
                # Trigger RBAC denial log via complete_task_instance
                ok, msg, _ = self.repo.complete_task_instance(
                    instance_id=instance_id,
                    actor_slack_id=actor_slack_id,
                    completed_at=clicked_at,
                )
                return SlackInteractionResponse(ok=ok, ephemeral_message=msg)

            modal = build_fridge_temperature_modal(instance)
            return SlackInteractionResponse(
                ok=True,
                ephemeral_message="Opening Fridge Temperature Log modal...",
                modal_view=modal,
                updated_instance_id=instance_id,
            )

        if verb == "complete_task":
            ok, msg, updated = self.repo.complete_task_instance(
                instance_id=instance_id,
                actor_slack_id=actor_slack_id,
                completed_at=clicked_at,
            )
            return SlackInteractionResponse(
                ok=ok,
                ephemeral_message=msg,
                updated_instance_id=updated.instance_id if updated else instance_id,
            )

        return SlackInteractionResponse(ok=False, ephemeral_message=f"Unsupported action verb: {verb}")

    def handle_fridge_modal_submission(
        self,
        *,
        instance_id: str,
        actor_slack_id: str,
        min_temp_raw: str,
        max_temp_raw: str,
        current_temp_raw: str,
        action_note: str = "",
        submitted_at: Optional[datetime] = None,
    ) -> SlackInteractionResponse:
        """
        Validates numeric temperature inputs from the Slack modal and records completion + cold-chain audit events.
        """
        try:
            min_c = float(min_temp_raw.strip())
            max_c = float(max_temp_raw.strip())
            curr_c = float(current_temp_raw.strip())
        except ValueError:
            return SlackInteractionResponse(
                ok=False,
                ephemeral_message="Invalid temperature format: Min, Max, and Current temperatures must be valid numbers (e.g. 4.2).",
            )

        ok, msg, updated = self.repo.complete_task_instance(
            instance_id=instance_id,
            actor_slack_id=actor_slack_id,
            notes=action_note,
            fridge_readings={
                "min_temp_c": min_c,
                "max_temp_c": max_c,
                "current_temp_c": curr_c,
            },
            completed_at=submitted_at,
        )
        return SlackInteractionResponse(
            ok=ok,
            ephemeral_message=msg,
            updated_instance_id=updated.instance_id if updated else instance_id,
        )
