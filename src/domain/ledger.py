"""Cryptographic SHA-256 hash-chain builder and verifier for the immutable compliance ledger."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Optional

GENESIS_PREV_HASH = "0" * 64


def canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic JSON serialization with sorted keys for repeatable SHA-256 hashing."""
    return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"))


def compute_audit_row_hash(
    *,
    event_id: str,
    event_type: str,
    task_id: Optional[int],
    instance_id: Optional[str],
    period_key: Optional[str],
    actor_user_id: Optional[str],
    actor_slack_id: Optional[str],
    actor_entra_oid: Optional[str],
    actor_role: Optional[str],
    payload: dict[str, Any],
    occurred_at_iso: str,
    prev_hash: str,
) -> str:
    """
    Computes the SHA-256 digest matching the PostgreSQL trigger `fn_audit_compute_hash_chain`.
    """
    canonical_str = "|".join(
        [
            str(event_id or ""),
            str(event_type or ""),
            "" if task_id is None else str(task_id),
            str(instance_id or ""),
            str(period_key or ""),
            str(actor_user_id or ""),
            str(actor_slack_id or ""),
            str(actor_entra_oid or ""),
            str(actor_role or ""),
            canonical_json(payload),
            str(occurred_at_iso),
            str(prev_hash),
        ]
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LedgerVerificationResult:
    is_valid: bool
    total_rows_checked: int
    first_broken_seq: Optional[int] = None
    failure_reason: Optional[str] = None
    head_hash: str = GENESIS_PREV_HASH


def verify_audit_chain(rows: Iterable[dict[str, Any]]) -> LedgerVerificationResult:
    """
    Verifies the entire sequence of `task_events_audit` rows from Genesis to Head:
    1. Checks strict sequential linking (`row.prev_hash == expected_prev_hash`).
    2. Recomputes the SHA-256 hash of every row's fields and compares to `row.row_hash`.
    """
    expected_prev_hash = GENESIS_PREV_HASH
    count = 0

    for row in rows:
        count += 1
        seq = row.get("audit_seq", count)
        actual_prev = row.get("prev_hash", "")
        actual_hash = row.get("row_hash", "")

        if actual_prev != expected_prev_hash:
            return LedgerVerificationResult(
                is_valid=False,
                total_rows_checked=count,
                first_broken_seq=seq,
                failure_reason=(
                    f"Chain link broken at audit_seq={seq}: "
                    f"expected prev_hash={expected_prev_hash[:12]}..., got {actual_prev[:12]}..."
                ),
                head_hash=expected_prev_hash,
            )

        payload_val = row.get("payload", {})
        if isinstance(payload_val, str):
            payload_val = json.loads(payload_val)

        recomputed_hash = compute_audit_row_hash(
            event_id=row["event_id"],
            event_type=row["event_type"],
            task_id=row.get("task_id"),
            instance_id=row.get("instance_id"),
            period_key=row.get("period_key"),
            actor_user_id=row.get("actor_user_id"),
            actor_slack_id=row.get("actor_slack_id"),
            actor_entra_oid=row.get("actor_entra_oid"),
            actor_role=row.get("actor_role"),
            payload=payload_val,
            occurred_at_iso=row["occurred_at"],
            prev_hash=actual_prev,
        )

        if recomputed_hash != actual_hash:
            return LedgerVerificationResult(
                is_valid=False,
                total_rows_checked=count,
                first_broken_seq=seq,
                failure_reason=(
                    f"Tampering detected at audit_seq={seq}: "
                    f"recomputed SHA-256 ({recomputed_hash[:12]}...) != stored row_hash ({actual_hash[:12]}...)"
                ),
                head_hash=expected_prev_hash,
            )

        expected_prev_hash = actual_hash

    return LedgerVerificationResult(
        is_valid=True,
        total_rows_checked=count,
        first_broken_seq=None,
        failure_reason=None,
        head_hash=expected_prev_hash,
    )
