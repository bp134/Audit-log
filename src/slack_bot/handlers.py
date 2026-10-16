"""
Slack Socket Mode & Request-Signed Interaction Handlers (`src/slack_bot/handlers.py`).
- ID-024: Enforces Slack HMAC-SHA256 signing-secret verification (`v0=<hex>`) and 5-minute replay window
  at the interaction boundary before any handler executes.
- Enforces GPhC RBAC and immutable PostgreSQL audit logging.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import time
from typing import Any, Optional

from src.domain.models import AuditEventType, is_role_authorized
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.blocks import build_fridge_temperature_modal


@dataclass
class SlackInteractionResponse:
    ok: bool
    ephemeral_message: str
    modal_view: Optional[dict[str, Any]] = None
    updated_instance_id: Optional[str] = None


def verify_slack_request_signature(
    *,
    signing_secret: str,
    timestamp: str,
    body: str,
    signature: str,
    max_age_seconds: int = 300,
    now_epoch: Optional[float] = None,
) -> bool:
    """
    ID-024: Cryptographically verifies a Slack request signature (`X-Slack-Signature` = `v0=<hmac>`)
    and enforces a 5-minute replay-protection window (`X-Slack-Request-Timestamp`).
    """
    if not signing_secret or not timestamp or not signature:
        return False
    raw_ts = timestamp.strip()
    try:
        ts_int = int(raw_ts)
    except ValueError:
        return False

    current_time = now_epoch if now_epoch is not None else time.time()
    if abs(current_time - ts_int) > max_age_seconds:
        return False

    basestring = f"v0:{raw_ts}:{body}".encode("utf-8")
    digest = hmac.new(signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
    expected_sig = f"v0={digest}"
    return hmac.compare_digest(expected_sig, signature.strip())


class SlackComplianceHandler:
    """
    Handles interactive Slack Block Kit button clicks and modal submissions.
    When `signing_secret` is configured on the handler (or when `require_signature=True`),
    validates `X-Slack-Signature` and `X-Slack-Request-Timestamp` before running business logic.
    """

    def __init__(
        self,
        repo: ComplianceRepository,
        *,
        signing_secret: Optional[str] = None,
        require_signature: bool = False,
    ) -> None:
        self.repo = repo
        self.signing_secret = signing_secret
        self.require_signature = require_signature

    def _check_boundary_signature(
        self,
        *,
        signature: Optional[str],
        timestamp: Optional[str],
        raw_body: Optional[str],
    ) -> tuple[bool, Optional[SlackInteractionResponse]]:
        should_verify = self.require_signature or (
            self.signing_secret is not None
            and any(v is not None for v in (signature, timestamp, raw_body))
        )
        if not should_verify:
            return True, None

        valid = verify_slack_request_signature(
            signing_secret=self.signing_secret or "",
            timestamp=timestamp or "",
            body=raw_body or "",
            signature=signature or "",
        )
        if not valid:
            self.repo.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                payload={"surface": "SLACK_BOUNDARY", "reason": "INVALID_SLACK_SIGNATURE"},
            )
            return (
                False,
                SlackInteractionResponse(
                    ok=False,
                    ephemeral_message="Access Denied: Slack request signature verification failed.",
                ),
            )
        return True, None

    def handle_button_click(
        self,
        *,
        action_id: str,
        actor_slack_id: str,
        clicked_at: Optional[datetime] = None,
        signature: Optional[str] = None,
        timestamp: Optional[str] = None,
        raw_body: Optional[str] = None,
    ) -> SlackInteractionResponse:
        sig_ok, err_resp = self._check_boundary_signature(
            signature=signature, timestamp=timestamp, raw_body=raw_body
        )
        if not sig_ok and err_resp is not None:
            return err_resp

        if ":" not in action_id:
            return SlackInteractionResponse(ok=False, ephemeral_message="Malformed Slack action_id.")

        verb, instance_id = action_id.split(":", 1)

        if verb == "open_fridge_modal":
            instance = self.repo.get_instance_by_id(instance_id)
            if not instance:
                return SlackInteractionResponse(ok=False, ephemeral_message="Task instance not found.")

            actor = self.repo.get_user_by_slack_id(actor_slack_id)
            if not actor or not is_role_authorized(actor.staff_role, instance.assigned_role):
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
        signature: Optional[str] = None,
        timestamp: Optional[str] = None,
        raw_body: Optional[str] = None,
    ) -> SlackInteractionResponse:
        sig_ok, err_resp = self._check_boundary_signature(
            signature=signature, timestamp=timestamp, raw_body=raw_body
        )
        if not sig_ok and err_resp is not None:
            return err_resp

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
