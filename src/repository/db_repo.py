"""
PostgreSQL-Only Compliance Repository (`src/repository/db_repo.py`).
Routes all operations exclusively through PostgreSQL (`psycopg`) via `DATABASE_URL` (ID-002),
executes `db/01_schema.sql` and `db/02_seed_tasks.sql` as the single canonical schema/seed source (ID-017),
enforces database-layer SHA-256 hash chaining and immutability triggers (ID-008, ID-010, ID-022),
and uses optimistic locking on concurrent task completions (ID-009).
Zero SQLite dependencies remain anywhere in this module (ID-016).
"""

from __future__ import annotations

from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Optional
import uuid

import psycopg
from psycopg.rows import dict_row

from src.domain.ledger import (
    LedgerVerificationResult,
    canonical_json,
    format_canonical_utc_timestamp,
    verify_audit_chain,
)
from src.domain.models import (
    AuditEventType,
    DailyWindow,
    FridgeReadingValidation,
    InstanceStatus,
    RoleRequirement,
    StaffRole,
    TaskFrequency,
    TaskInstanceRecord,
    UserRecord,
    compute_period_bounds,
    is_role_authorized,
    validate_fridge_reading,
)

DEFAULT_TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/pharmacy_compliance_test"


class ImmutableLedgerViolationError(PermissionError):
    """Raised when any code or SQL query attempts to UPDATE or DELETE from task_events_audit."""


class ComplianceRepository:
    """
    PostgreSQL-exclusive compliance repository providing:
    - Master task seeding directly from `db/02_seed_tasks.sql` (all 33 pharmacy tasks)
    - RBAC user management (Entra OID <-> Slack ID <-> Pharmacy Role)
    - Period instance scheduling (Daily, Weekly any-day, Monthly any-day)
    - Role-enforced task completion with optimistic locking & Fridge temperature modal logging
    - Append-only, PostgreSQL-trigger-enforced, SHA-256 hash-chained audit trail
    - Live read-only inspection of Azure PostgreSQL `task_reminders` (`tasks_master`, `scheduled_instances`, `audit_logs`)
    """

    def __init__(
        self,
        database_url: Optional[str] = None,
        *,
        schema_name: Optional[str] = None,
        init_schema: bool = True,
    ) -> None:
        # If legacy test callers pass ":memory:" or a `.db` file path, route to an isolated PostgreSQL test schema
        if database_url is None or database_url == ":memory:" or not str(database_url).startswith("postgresql"):
            self.database_url = os.getenv("TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)
            self._ephemeral_schema = schema_name or f"test_pg_{uuid.uuid4().hex[:12]}"
            self._drop_schema_on_close = schema_name is None
        else:
            self.database_url = database_url
            self._ephemeral_schema = schema_name
            self._drop_schema_on_close = False

        self.conn = psycopg.connect(self.database_url, row_factory=dict_row, autocommit=True)
        if self._ephemeral_schema:
            with self.conn.transaction():
                self.conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{self._ephemeral_schema}";')
            self.conn.execute(f'SET search_path TO "{self._ephemeral_schema}", public;')

        if init_schema:
            self._init_schema_and_immutability_triggers()

    def _init_schema_and_immutability_triggers(self) -> None:
        schema_sql_path = Path(__file__).resolve().parents[2] / "db" / "01_schema.sql"
        sql_text = schema_sql_path.read_text(encoding="utf-8")
        cleaned_lines = [
            line for line in sql_text.splitlines() if line.strip().upper() not in ("BEGIN;", "COMMIT;")
        ]
        with self.conn.transaction():
            if self._ephemeral_schema:
                self.conn.execute(f'SET search_path TO "{self._ephemeral_schema}", public;')
            self.conn.execute("\n".join(cleaned_lines))

    def seed_tasks_from_sql_file(self, sql_seed_path: Optional[Path] = None) -> int:
        """
        ID-017: Loads and executes `db/02_seed_tasks.sql` directly against PostgreSQL
        as the single canonical source of truth for all 33 pharmacy compliance tasks.
        """
        if sql_seed_path is None:
            sql_seed_path = Path(__file__).resolve().parents[2] / "db" / "02_seed_tasks.sql"

        sql_text = sql_seed_path.read_text(encoding="utf-8")
        cleaned_lines = [
            line for line in sql_text.splitlines() if line.strip().upper() not in ("BEGIN;", "COMMIT;")
        ]
        with self.conn.transaction():
            self.conn.execute("\n".join(cleaned_lines))

        row = self.conn.execute("SELECT COUNT(*) AS cnt FROM tasks_master WHERE is_active = TRUE").fetchone()
        return int(row["cnt"]) if row else 0

    # -------------------------------------------------------------------------
    # Live Azure `task_reminders` Read-Only Inspection Adapter
    # -------------------------------------------------------------------------
    def fetch_live_task_reminders_counts(self) -> dict[str, int]:
        """
        Queries the live Azure PostgreSQL `task_reminders` schema (`tasks_master`,
        `scheduled_instances`, `audit_logs`) strictly read-only (`SELECT` only).
        """
        with self.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM public.tasks_master;")
            tasks_cnt = int((cur.fetchone() or {"cnt": 0})["cnt"])
            cur.execute("SELECT COUNT(*) AS cnt FROM public.scheduled_instances;")
            sched_cnt = int((cur.fetchone() or {"cnt": 0})["cnt"])
            cur.execute("SELECT COUNT(*) AS cnt FROM public.audit_logs;")
            audit_cnt = int((cur.fetchone() or {"cnt": 0})["cnt"])
        return {
            "tasks_master": tasks_cnt,
            "scheduled_instances": sched_cnt,
            "audit_logs": audit_cnt,
        }

    # -------------------------------------------------------------------------
    # User & RBAC Operations
    # -------------------------------------------------------------------------
    def upsert_user(
        self,
        *,
        entra_oid: str,
        slack_user_id: str,
        full_name: str,
        email: str,
        staff_role: StaffRole,
        gphc_reg_number: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> UserRecord:
        uid = user_id or str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with self.conn.transaction():
            self.conn.execute(
                """
                INSERT INTO users_rbac (
                    user_id, entra_oid, slack_user_id, full_name, email,
                    staff_role, gphc_reg_number, is_active, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, %s)
                ON CONFLICT(slack_user_id) DO UPDATE SET
                    entra_oid = EXCLUDED.entra_oid,
                    full_name = EXCLUDED.full_name,
                    email = EXCLUDED.email,
                    staff_role = EXCLUDED.staff_role,
                    gphc_reg_number = EXCLUDED.gphc_reg_number,
                    updated_at = NOW()
                """,
                (
                    uid,
                    entra_oid,
                    slack_user_id,
                    full_name,
                    email,
                    staff_role.value,
                    gphc_reg_number,
                    now_iso,
                ),
            )
        return self.get_user_by_slack_id(slack_user_id)  # type: ignore[return-value]

    def get_user_by_slack_id(self, slack_user_id: str) -> Optional[UserRecord]:
        row = self.conn.execute(
            "SELECT * FROM users_rbac WHERE slack_user_id = %s AND is_active = TRUE",
            (slack_user_id,),
        ).fetchone()
        if not row:
            return None
        return UserRecord(
            user_id=str(row["user_id"]),
            entra_oid=row["entra_oid"],
            slack_user_id=row["slack_user_id"],
            full_name=row["full_name"],
            email=row["email"],
            staff_role=StaffRole(row["staff_role"]),
            gphc_reg_number=row["gphc_reg_number"],
            is_active=bool(row["is_active"]),
        )

    def get_user_by_entra_oid(self, entra_oid: str) -> Optional[UserRecord]:
        row = self.conn.execute(
            "SELECT * FROM users_rbac WHERE entra_oid = %s AND is_active = TRUE",
            (entra_oid,),
        ).fetchone()
        if not row:
            return None
        return UserRecord(
            user_id=str(row["user_id"]),
            entra_oid=row["entra_oid"],
            slack_user_id=row["slack_user_id"],
            full_name=row["full_name"],
            email=row["email"],
            staff_role=StaffRole(row["staff_role"]),
            gphc_reg_number=row["gphc_reg_number"],
            is_active=bool(row["is_active"]),
        )

    def list_users(self) -> list[UserRecord]:
        rows = self.conn.execute("SELECT * FROM users_rbac WHERE is_active = TRUE ORDER BY full_name").fetchall()
        return [
            UserRecord(
                user_id=str(r["user_id"]),
                entra_oid=r["entra_oid"],
                slack_user_id=r["slack_user_id"],
                full_name=r["full_name"],
                email=r["email"],
                staff_role=StaffRole(r["staff_role"]),
                gphc_reg_number=r["gphc_reg_number"],
                is_active=bool(r["is_active"]),
            )
            for r in rows
        ]

    # -------------------------------------------------------------------------
    # Immutable Audit Event Writer (Database-Layer Hash Computation - ID-010)
    # -------------------------------------------------------------------------
    def append_audit_event(
        self,
        *,
        event_type: AuditEventType,
        task_id: Optional[int] = None,
        instance_id: Optional[str] = None,
        period_key: Optional[str] = None,
        actor: Optional[UserRecord] = None,
        actor_slack_id_override: Optional[str] = None,
        payload: Optional[dict[str, Any]] = None,
        occurred_at: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """
        ID-010: Inserts an audit event into PostgreSQL `task_events_audit` WITHOUT
        client-computed hashes. The PostgreSQL `BEFORE INSERT` trigger
        `fn_audit_compute_hash_chain()` computes `prev_hash` and `row_hash` inside
        the database engine using `fn_canonical_jsonb()` and `pg_advisory_xact_lock()`.
        """
        event_id = str(uuid.uuid4())
        ts = occurred_at or datetime.now(timezone.utc)
        occurred_at_iso = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        payload_dict = payload or {}

        actor_uid = actor.user_id if actor else None
        actor_slack = actor.slack_user_id if actor else actor_slack_id_override
        actor_entra = actor.entra_oid if actor else None
        actor_role = actor.staff_role.value if actor else None

        with self.conn.transaction():
            row = self.conn.execute(
                """
                INSERT INTO task_events_audit (
                    event_id, event_type, task_id, instance_id, period_key,
                    actor_user_id, actor_slack_id, actor_entra_oid, actor_role,
                    payload, occurred_at, prev_hash, row_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, '', '')
                RETURNING audit_seq, event_id, event_type, prev_hash, row_hash, occurred_at
                """,
                (
                    event_id,
                    event_type.value,
                    task_id,
                    instance_id,
                    period_key,
                    actor_uid,
                    actor_slack,
                    actor_entra,
                    actor_role,
                    canonical_json(payload_dict),
                    occurred_at_iso,
                ),
            ).fetchone()

            if row is None:
                raise RuntimeError("PostgreSQL INSERT RETURNING on task_events_audit returned no row.")
            return {
                "audit_seq": int(row["audit_seq"]),
                "event_id": str(row["event_id"]),
                "event_type": str(row["event_type"]),
                "prev_hash": str(row["prev_hash"]),
                "row_hash": str(row["row_hash"]),
                "occurred_at": format_canonical_utc_timestamp(row["occurred_at"]),
            }

    # -------------------------------------------------------------------------
    # Cycle Scheduling (Daily / Weekly / Monthly)
    # -------------------------------------------------------------------------
    def ensure_instances_for_date(self, target_date: date) -> list[TaskInstanceRecord]:
        master_rows = self.conn.execute(
            "SELECT * FROM tasks_master WHERE is_active = TRUE ORDER BY task_id"
        ).fetchall()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        for m in master_rows:
            freq = TaskFrequency(m["frequency"])
            bounds = compute_period_bounds(freq, target_date)

            existing = self.conn.execute(
                "SELECT instance_id FROM task_instances WHERE task_id = %s AND period_key = %s",
                (m["task_id"], bounds.period_key),
            ).fetchone()

            if not existing:
                instance_id = str(uuid.uuid4())
                with self.conn.transaction():
                    self.conn.execute(
                        """
                        INSERT INTO task_instances (
                            instance_id, task_id, period_key,
                            period_start_date, period_end_date,
                            status, created_at
                        ) VALUES (%s, %s, %s, %s, %s, 'Pending', %s)
                        """,
                        (
                            instance_id,
                            m["task_id"],
                            bounds.period_key,
                            bounds.start_date.isoformat(),
                            bounds.end_date.isoformat(),
                            now_iso,
                        ),
                    )
                self.append_audit_event(
                    event_type=AuditEventType.INSTANCE_SCHEDULED,
                    task_id=m["task_id"],
                    instance_id=instance_id,
                    period_key=bounds.period_key,
                    payload={
                        "task_name": m["task_name"],
                        "frequency": freq.value,
                        "daily_timing_window": m["daily_timing_window"],
                        "period_start": bounds.start_date.isoformat(),
                        "period_end": bounds.end_date.isoformat(),
                    },
                )

        return self.get_active_instances_for_date(target_date)

    def get_active_instances_for_date(self, target_date: date) -> list[TaskInstanceRecord]:
        daily_key = compute_period_bounds(TaskFrequency.DAILY, target_date).period_key
        weekly_key = compute_period_bounds(TaskFrequency.WEEKLY, target_date).period_key
        monthly_key = compute_period_bounds(TaskFrequency.MONTHLY, target_date).period_key

        rows = self.conn.execute(
            """
            SELECT
                ti.*,
                tm.task_name,
                tm.frequency,
                tm.daily_timing_window,
                tm.assigned_role,
                tm.requires_structured_input,
                u.full_name AS completed_by_name,
                u.staff_role AS completed_by_role
            FROM task_instances ti
            JOIN tasks_master tm ON tm.task_id = ti.task_id
            LEFT JOIN users_rbac u ON u.user_id = ti.completed_by_user_id
            WHERE ti.period_key IN (%s, %s, %s)
            ORDER BY tm.task_id ASC
            """,
            (daily_key, weekly_key, monthly_key),
        ).fetchall()

        return [self._row_to_instance(r) for r in rows]

    def get_instance_by_id(self, instance_id: str) -> Optional[TaskInstanceRecord]:
        row = self.conn.execute(
            """
            SELECT
                ti.*,
                tm.task_name,
                tm.frequency,
                tm.daily_timing_window,
                tm.assigned_role,
                tm.requires_structured_input,
                u.full_name AS completed_by_name,
                u.staff_role AS completed_by_role
            FROM task_instances ti
            JOIN tasks_master tm ON tm.task_id = ti.task_id
            LEFT JOIN users_rbac u ON u.user_id = ti.completed_by_user_id
            WHERE ti.instance_id = %s
            """,
            (instance_id,),
        ).fetchone()
        return self._row_to_instance(row) if row else None

    def _row_to_instance(self, r: dict[str, Any]) -> TaskInstanceRecord:
        p_start = r["period_start_date"]
        p_end = r["period_end_date"]
        comp_at = r["completed_at"]
        struct_data = r["structured_data"]
        if isinstance(struct_data, str):
            struct_data = json.loads(struct_data or "{}")
        elif struct_data is None:
            struct_data = {}

        if isinstance(comp_at, str):
            comp_at = datetime.fromisoformat(comp_at.replace("Z", "+00:00"))

        return TaskInstanceRecord(
            instance_id=str(r["instance_id"]),
            task_id=int(r["task_id"]),
            task_name=r["task_name"],
            frequency=TaskFrequency(r["frequency"]),
            daily_timing_window=DailyWindow(r["daily_timing_window"]) if r["daily_timing_window"] else None,
            assigned_role=RoleRequirement(r["assigned_role"]),
            requires_structured_input=bool(r["requires_structured_input"]),
            period_key=r["period_key"],
            period_start_date=p_start if isinstance(p_start, date) else date.fromisoformat(str(p_start)),
            period_end_date=p_end if isinstance(p_end, date) else date.fromisoformat(str(p_end)),
            status=InstanceStatus(r["status"]),
            completed_by_user_id=str(r["completed_by_user_id"]) if r["completed_by_user_id"] else None,
            completed_by_name=r["completed_by_name"],
            completed_by_role=r["completed_by_role"],
            completed_at=comp_at,
            structured_data=struct_data,
            notes=r["notes"],
            escalation_count=int(r["escalation_count"]),
        )

    # -------------------------------------------------------------------------
    # Task Completion & Fridge Temperature Logging (with Optimistic Locking - ID-009)
    # -------------------------------------------------------------------------
    def complete_task_instance(
        self,
        *,
        instance_id: str,
        actor_slack_id: str,
        notes: Optional[str] = None,
        fridge_readings: Optional[dict[str, float]] = None,
        completed_at: Optional[datetime] = None,
    ) -> tuple[bool, str, Optional[TaskInstanceRecord]]:
        instance = self.get_instance_by_id(instance_id)
        if not instance:
            return False, f"Task instance `{instance_id}` not found.", None

        actor = self.get_user_by_slack_id(actor_slack_id)
        if not actor:
            self.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                task_id=instance.task_id,
                instance_id=instance.instance_id,
                period_key=instance.period_key,
                actor_slack_id_override=actor_slack_id,
                payload={
                    "reason": "UNREGISTERED_SLACK_USER",
                    "task_name": instance.task_name,
                    "required_role": instance.assigned_role.value,
                },
                occurred_at=completed_at,
            )
            return (
                False,
                "Access Denied: Your Slack account is not linked to an active Microsoft Entra ID / Pharmacy RBAC profile.",
                instance,
            )

        if not is_role_authorized(actor.staff_role, instance.assigned_role):
            self.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                task_id=instance.task_id,
                instance_id=instance.instance_id,
                period_key=instance.period_key,
                actor=actor,
                payload={
                    "reason": "INSUFFICIENT_ROLE",
                    "task_name": instance.task_name,
                    "actor_role": actor.staff_role.value,
                    "required_role": instance.assigned_role.value,
                },
                occurred_at=completed_at,
            )
            return (
                False,
                (
                    f"Access Denied: *{instance.task_name}* requires role `{instance.assigned_role.value}`, "
                    f"but your profile role is `{actor.staff_role.value}`. This attempt has been logged."
                ),
                instance,
            )

        if instance.status == InstanceStatus.COMPLETED:
            return (
                True,
                f"*{instance.task_name}* was already completed for `{instance.period_key}` by {instance.completed_by_name}.",
                instance,
            )

        structured_payload: dict[str, Any] = {}
        if instance.requires_structured_input:
            if not fridge_readings:
                return (
                    False,
                    f"*{instance.task_name}* requires Min, Max, and Current (°C) temperature readings.",
                    instance,
                )
            validation: FridgeReadingValidation = validate_fridge_reading(
                min_temp_c=float(fridge_readings["min_temp_c"]),
                max_temp_c=float(fridge_readings["max_temp_c"]),
                current_temp_c=float(fridge_readings["current_temp_c"]),
                corrective_action_note=notes or "",
            )
            if not validation.is_valid_input:
                return False, validation.error_message or "Invalid fridge reading.", instance

            structured_payload = {
                "min_temp_c": validation.min_temp_c,
                "max_temp_c": validation.max_temp_c,
                "current_temp_c": validation.current_temp_c,
                "in_safe_range": validation.in_safe_range,
                "corrective_action_note": validation.corrective_action_note,
            }

            if not validation.in_safe_range:
                self.append_audit_event(
                    event_type=AuditEventType.FRIDGE_OUT_OF_RANGE_ALERT,
                    task_id=instance.task_id,
                    instance_id=instance.instance_id,
                    period_key=instance.period_key,
                    actor=actor,
                    payload=structured_payload,
                    occurred_at=completed_at,
                )

        ts = completed_at or datetime.now(timezone.utc)
        completed_iso = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # ID-009: Optimistic locking — enforce status != 'Completed' in the UPDATE predicate
        with self.conn.transaction():
            cur = self.conn.execute(
                """
                UPDATE task_instances
                SET status = 'Completed',
                    completed_by_user_id = %s,
                    completed_at = %s,
                    structured_data = %s::jsonb,
                    notes = %s
                WHERE instance_id = %s AND status <> 'Completed'
                """,
                (
                    actor.user_id,
                    completed_iso,
                    canonical_json(structured_payload),
                    notes,
                    instance.instance_id,
                ),
            )
            if cur.rowcount == 0:
                refreshed = self.get_instance_by_id(instance.instance_id)
                return (
                    False,
                    f"Conflict: *{instance.task_name}* was concurrently completed by another user.",
                    refreshed,
                )

        audit_type = (
            AuditEventType.FRIDGE_TEMP_LOGGED
            if instance.requires_structured_input
            else AuditEventType.TASK_COMPLETED
        )
        # ID-012: Minimize PII in audit payloads — do not duplicate GPhC registration numbers,
        # full names, or emails inside the JSON payload (actor_user_id and actor_entra_oid link to RBAC).
        self.append_audit_event(
            event_type=audit_type,
            task_id=instance.task_id,
            instance_id=instance.instance_id,
            period_key=instance.period_key,
            actor=actor,
            payload={
                "task_name": instance.task_name,
                "frequency": instance.frequency.value,
                "structured_data": structured_payload,
                "notes": notes or "",
            },
            occurred_at=ts,
        )

        updated = self.get_instance_by_id(instance.instance_id)
        return True, f"✅ *{instance.task_name}* marked complete by *{actor.full_name}* ({actor.staff_role.value}).", updated

    # -------------------------------------------------------------------------
    # Escalations
    # -------------------------------------------------------------------------
    def escalate_overdue_instances(
        self,
        instance_ids: list[str],
        reason: str,
        escalated_at: Optional[datetime] = None,
    ) -> list[TaskInstanceRecord]:
        escalated_records: list[TaskInstanceRecord] = []
        for iid in instance_ids:
            inst = self.get_instance_by_id(iid)
            if not inst or inst.status == InstanceStatus.COMPLETED:
                continue
            with self.conn.transaction():
                self.conn.execute(
                    """
                    UPDATE task_instances
                    SET status = 'Escalated',
                        escalation_count = escalation_count + 1
                    WHERE instance_id = %s AND status <> 'Completed'
                    """,
                    (iid,),
                )
            self.append_audit_event(
                event_type=AuditEventType.TASK_ESCALATED,
                task_id=inst.task_id,
                instance_id=inst.instance_id,
                period_key=inst.period_key,
                payload={
                    "task_name": inst.task_name,
                    "reason": reason,
                    "new_escalation_count": inst.escalation_count + 1,
                },
                occurred_at=escalated_at,
            )
            updated = self.get_instance_by_id(iid)
            if updated:
                escalated_records.append(updated)
        return escalated_records

    # -------------------------------------------------------------------------
    # Audit Verification & Inspection Queries
    # -------------------------------------------------------------------------
    def get_all_audit_events(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM task_events_audit ORDER BY audit_seq ASC"
        ).fetchall()
        normalized: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["audit_seq"] = int(item["audit_seq"])
            item["event_id"] = str(item["event_id"])
            item["event_type"] = str(item["event_type"])
            item["instance_id"] = str(item["instance_id"]) if item["instance_id"] else None
            item["actor_user_id"] = str(item["actor_user_id"]) if item["actor_user_id"] else None
            item["occurred_at"] = format_canonical_utc_timestamp(item["occurred_at"])
            item["prev_hash"] = str(item["prev_hash"]).strip()
            item["row_hash"] = str(item["row_hash"]).strip()
            normalized.append(item)
        return normalized

    def verify_ledger_integrity(self) -> LedgerVerificationResult:
        rows = self.get_all_audit_events()
        return verify_audit_chain(rows)

    def close(self) -> None:
        if not self.conn.closed:
            if self._drop_schema_on_close and self._ephemeral_schema:
                with self.conn.transaction():
                    self.conn.execute(f'DROP SCHEMA IF EXISTS "{self._ephemeral_schema}" CASCADE;')
            self.conn.close()
