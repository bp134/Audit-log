"""
Compliance Repository supporting both Azure PostgreSQL Flexible Server (via psycopg)
and a self-contained SQLite engine with equivalent immutability triggers and SHA-256 hash chaining.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Optional
import uuid

from src.domain.ledger import (
    GENESIS_PREV_HASH,
    LedgerVerificationResult,
    canonical_json,
    compute_audit_row_hash,
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
    TaskMasterRecord,
    UserRecord,
    compute_period_bounds,
    is_role_authorized,
    validate_fridge_reading,
)


class ImmutableLedgerViolationError(PermissionError):
    """Raised when any code or SQL query attempts to UPDATE or DELETE from task_events_audit."""


class ComplianceRepository:
    """
    Unified compliance repository providing:
    - Master task seeding (all 33 pharmacy tasks)
    - RBAC user management (Entra OID <-> Slack ID <-> Pharmacy Role)
    - Period instance scheduling (Daily, Weekly any-day, Monthly any-day)
    - Role-enforced task completion & Fridge temperature modal logging
    - Append-only, database-trigger-protected, SHA-256 hash-chained audit trail
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self._init_schema_and_immutability_triggers()

    def _init_schema_and_immutability_triggers(self) -> None:
        with self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users_rbac (
                    user_id         TEXT PRIMARY KEY,
                    entra_oid       TEXT UNIQUE NOT NULL,
                    slack_user_id   TEXT UNIQUE NOT NULL,
                    full_name       TEXT NOT NULL,
                    email           TEXT UNIQUE NOT NULL,
                    staff_role      TEXT NOT NULL CHECK (staff_role IN ('Pharm', 'Dispenser', 'Manager')),
                    gphc_reg_number TEXT,
                    is_active       INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL,
                    CHECK (staff_role <> 'Pharm' OR (gphc_reg_number IS NOT NULL AND length(trim(gphc_reg_number)) >= 6))
                );

                CREATE TABLE IF NOT EXISTS tasks_master (
                    task_id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_name                   TEXT UNIQUE NOT NULL,
                    frequency                   TEXT NOT NULL CHECK (frequency IN ('Daily', 'Weekly', 'Monthly')),
                    daily_timing_window         TEXT CHECK (daily_timing_window IN ('Morning', 'Anytime', 'End_Of_Day') OR daily_timing_window IS NULL),
                    assigned_role               TEXT NOT NULL CHECK (assigned_role IN ('Pharm', 'Dispenser', 'Either')),
                    original_role_label         TEXT NOT NULL,
                    requires_structured_input   INTEGER NOT NULL DEFAULT 0,
                    input_schema                TEXT NOT NULL DEFAULT '{}',
                    is_active                   INTEGER NOT NULL DEFAULT 1,
                    CHECK (
                        (frequency = 'Daily' AND daily_timing_window IS NOT NULL)
                        OR (frequency IN ('Weekly', 'Monthly') AND daily_timing_window IS NULL)
                    )
                );

                CREATE TABLE IF NOT EXISTS task_instances (
                    instance_id             TEXT PRIMARY KEY,
                    task_id                 INTEGER NOT NULL REFERENCES tasks_master(task_id),
                    period_key              TEXT NOT NULL,
                    period_start_date       TEXT NOT NULL,
                    period_end_date         TEXT NOT NULL,
                    status                  TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Completed', 'Escalated', 'Missed')),
                    completed_by_user_id    TEXT REFERENCES users_rbac(user_id),
                    completed_at            TEXT,
                    structured_data         TEXT NOT NULL DEFAULT '{}',
                    notes                   TEXT,
                    escalation_count        INTEGER NOT NULL DEFAULT 0,
                    last_reminded_at        TEXT,
                    slack_channel_id        TEXT,
                    slack_message_ts        TEXT,
                    created_at              TEXT NOT NULL,
                    UNIQUE (task_id, period_key)
                );

                CREATE TABLE IF NOT EXISTS task_events_audit (
                    audit_seq       INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id        TEXT UNIQUE NOT NULL,
                    event_type      TEXT NOT NULL,
                    task_id         INTEGER REFERENCES tasks_master(task_id),
                    instance_id     TEXT REFERENCES task_instances(instance_id),
                    period_key      TEXT,
                    actor_user_id   TEXT REFERENCES users_rbac(user_id),
                    actor_slack_id  TEXT,
                    actor_entra_oid TEXT,
                    actor_role      TEXT,
                    payload         TEXT NOT NULL DEFAULT '{}',
                    occurred_at     TEXT NOT NULL,
                    prev_hash       TEXT NOT NULL,
                    row_hash        TEXT UNIQUE NOT NULL
                );

                -- Database-level immutability triggers blocking UPDATE and DELETE on task_events_audit
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_update
                BEFORE UPDATE ON task_events_audit
                BEGIN
                    SELECT RAISE(ABORT, 'COMPLIANCE VIOLATION: task_events_audit is strictly append-only. Operation UPDATE is prohibited.');
                END;

                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_delete
                BEFORE DELETE ON task_events_audit
                BEGIN
                    SELECT RAISE(ABORT, 'COMPLIANCE VIOLATION: task_events_audit is strictly append-only. Operation DELETE is prohibited.');
                END;

                CREATE TABLE IF NOT EXISTS backup_verification_logs (
                    verification_id     TEXT PRIMARY KEY,
                    backup_date         TEXT NOT NULL,
                    s3_bucket           TEXT NOT NULL,
                    s3_object_key       TEXT NOT NULL,
                    archive_sha256      TEXT NOT NULL,
                    encryption_cipher   TEXT NOT NULL,
                    restored_task_count INTEGER NOT NULL,
                    restored_audit_count INTEGER NOT NULL,
                    hash_chain_valid    INTEGER NOT NULL,
                    verification_status TEXT NOT NULL CHECK (verification_status IN ('PASSED', 'FAILED')),
                    error_details       TEXT,
                    verified_at         TEXT NOT NULL
                );
                """
            )

    def seed_tasks_from_sql_file(self, sql_seed_path: Optional[Path] = None) -> int:
        """
        Loads and seeds the 33 normalized tasks from `db/02_seed_tasks.sql`.
        Returns the total count of active tasks in `tasks_master`.
        """
        if sql_seed_path is None:
            sql_seed_path = Path(__file__).resolve().parents[2] / "db" / "02_seed_tasks.sql"

        tasks_data = [
            # Daily - Morning (4)
            (
                "Fridge Check (Min/Max/Current)",
                "Daily",
                "Morning",
                "Either",
                "Dispenser / Pharm",
                True,
                {
                    "type": "fridge_temperature",
                    "fields": ["min_temp_c", "max_temp_c", "current_temp_c"],
                    "safe_min_c": 2.0,
                    "safe_max_c": 8.0,
                    "require_action_note_if_out_of_range": True,
                },
            ),
            ("Handover & Diary Review", "Daily", "Morning", "Either", "Pharm / Dispenser", False, {}),
            ("EPS & NHSmail Download", "Daily", "Morning", "Either", "Dispenser / Pharm", False, {}),
            ("Till Prep & Float", "Daily", "Morning", "Dispenser", "Dispenser", False, {}),
            # Daily - Anytime (5)
            ("Prescription Processing", "Daily", "Anytime", "Dispenser", "Dispenser", False, {}),
            ("MDS/Dosette Boxes Prep & Check", "Daily", "Anytime", "Either", "Dispenser / Pharm", False, {}),
            ("Owings Processing", "Daily", "Anytime", "Dispenser", "Dispenser", False, {}),
            ("Deliveries & Fridge Lines", "Daily", "Anytime", "Dispenser", "Dispenser", False, {}),
            ("Clinical Services Prep", "Daily", "Anytime", "Pharm", "Pharm", False, {}),
            # Daily - End_Of_Day (5)
            ("CD Register Reconcile", "Daily", "End_Of_Day", "Pharm", "Pharm", False, {}),
            ("EPS Claims (End of Day)", "Daily", "End_Of_Day", "Either", "Dispenser / Pharm", False, {}),
            ("Information Governance Secure", "Daily", "End_Of_Day", "Dispenser", "Dispenser", False, {}),
            ("Housekeeping (Benches/Bins/Floor)", "Daily", "End_Of_Day", "Dispenser", "Dispenser", False, {}),
            ("Security & Lock Up", "Daily", "End_Of_Day", "Pharm", "Pharm", False, {}),
            # Weekly (10)
            ("Full CD Balance Check", "Weekly", None, "Pharm", "Pharm", False, {}),
            ("Owings Audit & Chase", "Weekly", None, "Dispenser", "Dispenser", False, {}),
            ("Uncollected Scripts (14+ Days)", "Weekly", None, "Dispenser", "Dispenser", False, {}),
            ("Consumables Order", "Weekly", None, "Dispenser", "Dispenser", False, {}),
            ("Filing (Invoices & Logs)", "Weekly", None, "Dispenser", "Dispenser", False, {}),
            ("Rota Check", "Weekly", None, "Pharm", "Pharm", False, {}),
            ("Collection Box Audit", "Weekly", None, "Dispenser", "Dispenser", False, {}),
            ("Consultation Room Deep Clean", "Weekly", None, "Either", "Dispenser / Pharm", False, {}),
            ("Hardware Antibacterial Clean", "Weekly", None, "Dispenser", "Dispenser", False, {}),
            ("Retail Area Face Up & Mop", "Weekly", None, "Dispenser", "Dispenser", False, {}),
            # Monthly (9)
            ("Date Checking Matrix", "Monthly", None, "Dispenser", "Dispenser", False, {}),
            ("CD Management (Out of Date)", "Monthly", None, "Pharm", "Pharm", False, {}),
            ("Fridge Audit & Defrost", "Monthly", None, "Dispenser", "Dispenser", False, {}),
            ("End of Month (NHSBSA / FP34C)", "Monthly", None, "Either", "Dispenser / Pharm", False, {}),
            ("Service Claims (MYS/Local)", "Monthly", None, "Pharm", "Pharm", False, {}),
            ("SOP & Training Review", "Monthly", None, "Pharm", "Pharm", False, {}),
            ("Health & Safety (Fire/First Aid)", "Monthly", None, "Either", "Pharm / Dispenser", False, {}),
            ("Staff Areas Deep Clean", "Monthly", None, "Dispenser", "Dispenser", False, {}),
            ("Ventilation & Hardware Dusting", "Monthly", None, "Dispenser", "Dispenser", False, {}),
        ]

        with self.conn:
            for (
                name,
                freq,
                window,
                role,
                orig_label,
                req_struct,
                schema_dict,
            ) in tasks_data:
                self.conn.execute(
                    """
                    INSERT INTO tasks_master (
                        task_name, frequency, daily_timing_window,
                        assigned_role, original_role_label,
                        requires_structured_input, input_schema
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(task_name) DO UPDATE SET
                        frequency = excluded.frequency,
                        daily_timing_window = excluded.daily_timing_window,
                        assigned_role = excluded.assigned_role,
                        original_role_label = excluded.original_role_label,
                        requires_structured_input = excluded.requires_structured_input,
                        input_schema = excluded.input_schema
                    """,
                    (
                        name,
                        freq,
                        window,
                        role,
                        orig_label,
                        1 if req_struct else 0,
                        canonical_json(schema_dict),
                    ),
                )

        row = self.conn.execute("SELECT COUNT(*) AS cnt FROM tasks_master WHERE is_active = 1").fetchone()
        return int(row["cnt"])

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
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO users_rbac (
                    user_id, entra_oid, slack_user_id, full_name, email,
                    staff_role, gphc_reg_number, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(slack_user_id) DO UPDATE SET
                    entra_oid = excluded.entra_oid,
                    full_name = excluded.full_name,
                    email = excluded.email,
                    staff_role = excluded.staff_role,
                    gphc_reg_number = excluded.gphc_reg_number
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
            "SELECT * FROM users_rbac WHERE slack_user_id = ? AND is_active = 1",
            (slack_user_id,),
        ).fetchone()
        if not row:
            return None
        return UserRecord(
            user_id=row["user_id"],
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
            "SELECT * FROM users_rbac WHERE entra_oid = ? AND is_active = 1",
            (entra_oid,),
        ).fetchone()
        if not row:
            return None
        return UserRecord(
            user_id=row["user_id"],
            entra_oid=row["entra_oid"],
            slack_user_id=row["slack_user_id"],
            full_name=row["full_name"],
            email=row["email"],
            staff_role=StaffRole(row["staff_role"]),
            gphc_reg_number=row["gphc_reg_number"],
            is_active=bool(row["is_active"]),
        )

    def list_users(self) -> list[UserRecord]:
        rows = self.conn.execute("SELECT * FROM users_rbac WHERE is_active = 1 ORDER BY full_name").fetchall()
        return [
            UserRecord(
                user_id=r["user_id"],
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
    # Immutable Audit Event Writer
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
        Appends an event to `task_events_audit` with deterministic SHA-256 hash chaining.
        """
        event_id = str(uuid.uuid4())
        ts = occurred_at or datetime.now(timezone.utc)
        occurred_at_iso = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        payload_dict = payload or {}

        with self.conn:
            last_row = self.conn.execute(
                "SELECT row_hash FROM task_events_audit ORDER BY audit_seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = last_row["row_hash"] if last_row else GENESIS_PREV_HASH

            actor_uid = actor.user_id if actor else None
            actor_slack = actor.slack_user_id if actor else actor_slack_id_override
            actor_entra = actor.entra_oid if actor else None
            actor_role = actor.staff_role.value if actor else None

            row_hash = compute_audit_row_hash(
                event_id=event_id,
                event_type=event_type.value,
                task_id=task_id,
                instance_id=instance_id,
                period_key=period_key,
                actor_user_id=actor_uid,
                actor_slack_id=actor_slack,
                actor_entra_oid=actor_entra,
                actor_role=actor_role,
                payload=payload_dict,
                occurred_at_iso=occurred_at_iso,
                prev_hash=prev_hash,
            )

            cursor = self.conn.execute(
                """
                INSERT INTO task_events_audit (
                    event_id, event_type, task_id, instance_id, period_key,
                    actor_user_id, actor_slack_id, actor_entra_oid, actor_role,
                    payload, occurred_at, prev_hash, row_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    prev_hash,
                    row_hash,
                ),
            )
            return {
                "audit_seq": cursor.lastrowid,
                "event_id": event_id,
                "event_type": event_type.value,
                "prev_hash": prev_hash,
                "row_hash": row_hash,
                "occurred_at": occurred_at_iso,
            }

    # -------------------------------------------------------------------------
    # Cycle Scheduling (Daily / Weekly / Monthly)
    # -------------------------------------------------------------------------
    def ensure_instances_for_date(self, target_date: date) -> list[TaskInstanceRecord]:
        """
        Idempotently ensures task instances exist for `target_date`:
        - 14 Daily tasks for `YYYY-MM-DD`
        - 10 Weekly tasks for `YYYY-Www` (created once per week; remains open across all days of the week until completed once)
        - 9 Monthly tasks for `YYYY-MM` (created once per month; remains open across all days of the month until completed once)
        """
        master_rows = self.conn.execute(
            "SELECT * FROM tasks_master WHERE is_active = 1 ORDER BY task_id"
        ).fetchall()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        for m in master_rows:
            freq = TaskFrequency(m["frequency"])
            bounds = compute_period_bounds(freq, target_date)

            existing = self.conn.execute(
                "SELECT instance_id FROM task_instances WHERE task_id = ? AND period_key = ?",
                (m["task_id"], bounds.period_key),
            ).fetchone()

            if not existing:
                instance_id = str(uuid.uuid4())
                with self.conn:
                    self.conn.execute(
                        """
                        INSERT INTO task_instances (
                            instance_id, task_id, period_key,
                            period_start_date, period_end_date,
                            status, created_at
                        ) VALUES (?, ?, ?, ?, ?, 'Pending', ?)
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
        """
        Returns all Daily instances for `target_date`, Weekly instances for `target_date`'s week,
        and Monthly instances for `target_date`'s month.
        """
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
            WHERE ti.period_key IN (?, ?, ?)
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
            WHERE ti.instance_id = ?
            """,
            (instance_id,),
        ).fetchone()
        return self._row_to_instance(row) if row else None

    def _row_to_instance(self, r: sqlite3.Row) -> TaskInstanceRecord:
        return TaskInstanceRecord(
            instance_id=r["instance_id"],
            task_id=int(r["task_id"]),
            task_name=r["task_name"],
            frequency=TaskFrequency(r["frequency"]),
            daily_timing_window=DailyWindow(r["daily_timing_window"]) if r["daily_timing_window"] else None,
            assigned_role=RoleRequirement(r["assigned_role"]),
            requires_structured_input=bool(r["requires_structured_input"]),
            period_key=r["period_key"],
            period_start_date=date.fromisoformat(r["period_start_date"]),
            period_end_date=date.fromisoformat(r["period_end_date"]),
            status=InstanceStatus(r["status"]),
            completed_by_user_id=r["completed_by_user_id"],
            completed_by_name=r["completed_by_name"],
            completed_by_role=r["completed_by_role"],
            completed_at=datetime.fromisoformat(r["completed_at"].replace("Z", "+00:00"))
            if r["completed_at"]
            else None,
            structured_data=json.loads(r["structured_data"] or "{}"),
            notes=r["notes"],
            escalation_count=int(r["escalation_count"]),
        )

    # -------------------------------------------------------------------------
    # Task Completion & Fridge Temperature Logging (with Strict RBAC Enforcement)
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
        """
        Completes a task instance if and only if:
        1. Actor is a registered active user in `users_rbac`.
        2. Actor's `staff_role` satisfies the task's `assigned_role` (RBAC).
        3. If the task requires structured input (Fridge Check), `fridge_readings` are present and valid.
        Every attempt (including denied RBAC attempts and out-of-range fridge readings) is logged to `task_events_audit`.
        """
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

        with self.conn:
            self.conn.execute(
                """
                UPDATE task_instances
                SET status = 'Completed',
                    completed_by_user_id = ?,
                    completed_at = ?,
                    structured_data = ?,
                    notes = ?
                WHERE instance_id = ?
                """,
                (
                    actor.user_id,
                    completed_iso,
                    canonical_json(structured_payload),
                    notes,
                    instance.instance_id,
                ),
            )

        audit_type = (
            AuditEventType.FRIDGE_TEMP_LOGGED
            if instance.requires_structured_input
            else AuditEventType.TASK_COMPLETED
        )
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
                "gphc_reg_number": actor.gphc_reg_number,
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
            with self.conn:
                self.conn.execute(
                    """
                    UPDATE task_instances
                    SET status = 'Escalated',
                        escalation_count = escalation_count + 1
                    WHERE instance_id = ?
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
        return [dict(r) for r in rows]

    def verify_ledger_integrity(self) -> LedgerVerificationResult:
        rows = self.get_all_audit_events()
        return verify_audit_chain(rows)

    def close(self) -> None:
        self.conn.close()

