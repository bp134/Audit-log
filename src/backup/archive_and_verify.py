"""
Nightly Encrypted Cloud Archival & Automated "Break-Glass" Restore Verifier.
- Dumps full database state + daily compliance report
- Encrypts client-side using authenticated encryption (PBKDF2-HMAC-SHA256 + SHA-256 stream + HMAC-SHA256 tag)
- Transfers encrypted archive to Hetzner S3 Object Storage (or local S3 vault path)
- Immediately performs a "Break-Glass" restore into an ephemeral database instance,
  verifying row counts and the full SHA-256 cryptographic audit chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
import gzip
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Optional
import uuid

from src.dashboard.reporting import generate_daily_compliance_report_markdown
from src.domain.ledger import canonical_json, format_canonical_utc_timestamp
from src.domain.models import AuditEventType
from src.repository.db_repo import ComplianceRepository

CIPHER_IDENTIFIER = "PBKDF2-SHA256-CTR-HMAC-SHA256-v1"


class ArchiveIntegrityError(ValueError):
    """Raised when an encrypted backup archive fails authentication tag or SHA-256 integrity checks."""


def _keystream_xor(data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
    """Deterministic SHA-256 counter-mode keystream XOR."""
    out = bytearray(len(data))
    block_count = (len(data) + 31) // 32
    for counter in range(block_count):
        counter_bytes = counter.to_bytes(8, "big")
        block = hashlib.sha256(enc_key + nonce + counter_bytes).digest()
        start = counter * 32
        end = min(start + 32, len(data))
        for i in range(start, end):
            out[i] = data[i] ^ block[i - start]
    return bytes(out)


def encrypt_archive_bytes(plaintext: bytes, master_key_hex: str) -> bytes:
    """
    Compresses and encrypts `plaintext` with a random 16-byte salt and 16-byte nonce,
    appending a 32-byte Encrypt-then-MAC (HMAC-SHA256) authentication tag.
    """
    compressed = gzip.compress(plaintext, compresslevel=6)
    salt = os.urandom(16)
    nonce = os.urandom(16)
    key_material = hashlib.pbkdf2_hmac(
        "sha256", master_key_hex.encode("utf-8"), salt, iterations=100_000, dklen=64
    )
    enc_key = key_material[:32]
    mac_key = key_material[32:]

    ciphertext = _keystream_xor(compressed, enc_key, nonce)
    header = b"PHARMVAULT1" + salt + nonce
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def decrypt_archive_bytes(bundle: bytes, master_key_hex: str) -> bytes:
    """
    Verifies the Encrypt-then-MAC HMAC-SHA256 authentication tag in constant time
    before decrypting and decompressing the archive.
    Raises `ArchiveIntegrityError` if even 1 bit of ciphertext, header, or tag is corrupted.
    """
    min_len = len(b"PHARMVAULT1") + 16 + 16 + 32
    if len(bundle) < min_len or not bundle.startswith(b"PHARMVAULT1"):
        raise ArchiveIntegrityError("Invalid or truncated PHARMVAULT1 archive header.")

    prefix_len = len(b"PHARMVAULT1")
    salt = bundle[prefix_len : prefix_len + 16]
    nonce = bundle[prefix_len + 16 : prefix_len + 32]
    tag = bundle[-32:]
    ciphertext = bundle[prefix_len + 32 : -32]
    header = bundle[: prefix_len + 32]

    key_material = hashlib.pbkdf2_hmac(
        "sha256", master_key_hex.encode("utf-8"), salt, iterations=100_000, dklen=64
    )
    enc_key = key_material[:32]
    mac_key = key_material[32:]

    expected_tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ArchiveIntegrityError(
            "CRITICAL BACKUP CORRUPTION: HMAC-SHA256 authentication tag verification failed!"
        )

    compressed = _keystream_xor(ciphertext, enc_key, nonce)
    try:
        return gzip.decompress(compressed)
    except Exception as exc:
        raise ArchiveIntegrityError(f"Decompression failed after decryption: {exc}") from exc


@dataclass(frozen=True)
class BreakGlassVerificationReport:
    verification_id: str
    backup_date: date
    s3_bucket: str
    s3_object_key: str
    archive_sha256: str
    restored_task_count: int
    restored_instance_count: int
    restored_audit_count: int
    hash_chain_valid: bool
    status: str  # 'PASSED' or 'FAILED'
    error_details: Optional[str] = None


class HetznerS3BreakGlassManager:
    """
    Manages nightly encrypted backups to Hetzner S3 Object Storage
    and executes automated Break-Glass restore verification into an ephemeral database instance.
    """

    def __init__(
        self,
        repo: ComplianceRepository,
        s3_bucket: str,
        encryption_key: str,
        local_s3_staging_dir: Path,
    ) -> None:
        self.repo = repo
        self.s3_bucket = s3_bucket
        self.encryption_key = encryption_key
        self.local_s3_staging_dir = local_s3_staging_dir
        self.local_s3_staging_dir.mkdir(parents=True, exist_ok=True)

    def create_encrypted_backup(self, backup_date: date) -> tuple[str, Path, str]:
        """
        Exports all tables + the daily signed compliance report, encrypts client-side,
        and writes to the S3 object key `backups/YYYY/MM/pharmacy_backup_YYYY-MM-DD.vault`.
        """
        users = []
        for r in self.repo.conn.execute("SELECT * FROM users_rbac").fetchall():
            u = dict(r)
            u["user_id"] = str(u["user_id"])
            u["created_at"] = format_canonical_utc_timestamp(u["created_at"])
            u["updated_at"] = format_canonical_utc_timestamp(u["updated_at"])
            users.append(u)
        tasks = []
        for r in self.repo.conn.execute("SELECT * FROM tasks_master").fetchall():
            t = dict(r)
            t["created_at"] = format_canonical_utc_timestamp(t["created_at"])
            t["input_schema"] = canonical_json(t["input_schema"]) if isinstance(t["input_schema"], dict) else t["input_schema"]
            tasks.append(t)
        instances = []
        for r in self.repo.conn.execute("SELECT * FROM task_instances").fetchall():
            inst = dict(r)
            inst["instance_id"] = str(inst["instance_id"])
            inst["period_start_date"] = inst["period_start_date"].isoformat() if isinstance(inst["period_start_date"], date) else str(inst["period_start_date"])
            inst["period_end_date"] = inst["period_end_date"].isoformat() if isinstance(inst["period_end_date"], date) else str(inst["period_end_date"])
            inst["completed_by_user_id"] = str(inst["completed_by_user_id"]) if inst["completed_by_user_id"] else None
            inst["completed_at"] = format_canonical_utc_timestamp(inst["completed_at"]) if inst["completed_at"] else None
            inst["last_reminded_at"] = format_canonical_utc_timestamp(inst["last_reminded_at"]) if inst["last_reminded_at"] else None
            inst["created_at"] = format_canonical_utc_timestamp(inst["created_at"])
            inst["structured_data"] = canonical_json(inst["structured_data"]) if isinstance(inst["structured_data"], dict) else inst["structured_data"]
            instances.append(inst)
        audit_events = self.repo.get_all_audit_events()
        daily_report_md = generate_daily_compliance_report_markdown(self.repo, backup_date)

        payload_doc = {
            "schema_version": "1.0",
            "backup_date": backup_date.isoformat(),
            "exported_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "daily_compliance_report_markdown": daily_report_md,
            "tables": {
                "users_rbac": users,
                "tasks_master": tasks,
                "task_instances": instances,
                "task_events_audit": audit_events,
            },
        }
        plaintext_bytes = json.dumps(payload_doc, sort_keys=True).encode("utf-8")
        encrypted_bytes = encrypt_archive_bytes(plaintext_bytes, self.encryption_key)
        archive_sha256 = hashlib.sha256(encrypted_bytes).hexdigest()

        s3_key = f"backups/{backup_date.year:04d}/{backup_date.month:02d}/pharmacy_backup_{backup_date.isoformat()}.vault"
        target_path = self.local_s3_staging_dir / s3_key
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(encrypted_bytes)

        return s3_key, target_path, archive_sha256

    def execute_break_glass_restore_test(
        self,
        *,
        backup_date: date,
        s3_object_key: str,
    ) -> BreakGlassVerificationReport:
        """
        Reads the encrypted archive from S3 storage, decrypts it, spins up an isolated
        temporary database instance, restores all tables, and verifies:
        1. Ciphertext authenticity (HMAC-SHA256)
        2. Exact row count parity against source
        3. Full SHA-256 cryptographic hash chain integrity across all restored audit records
        """
        verification_id = str(uuid.uuid4())
        archive_path = self.local_s3_staging_dir / s3_object_key
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if not archive_path.exists():
            return self._record_verification_outcome(
                verification_id=verification_id,
                backup_date=backup_date,
                s3_object_key=s3_object_key,
                archive_sha256="MISSING",
                restored_task_count=0,
                restored_instance_count=0,
                restored_audit_count=0,
                hash_chain_valid=False,
                status="FAILED",
                error_details=f"Archive object not found at {s3_object_key}",
                verified_at_iso=now_iso,
            )

        raw_bytes = archive_path.read_bytes()
        archive_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        try:
            decrypted_bytes = decrypt_archive_bytes(raw_bytes, self.encryption_key)
            snapshot: dict[str, Any] = json.loads(decrypted_bytes.decode("utf-8"))
        except Exception as exc:
            return self._record_verification_outcome(
                verification_id=verification_id,
                backup_date=backup_date,
                s3_object_key=s3_object_key,
                archive_sha256=archive_sha256,
                restored_task_count=0,
                restored_instance_count=0,
                restored_audit_count=0,
                hash_chain_valid=False,
                status="FAILED",
                error_details=str(exc),
                verified_at_iso=now_iso,
            )

        # Spin up isolated ephemeral PostgreSQL schema for Break-Glass restore
        temp_repo = ComplianceRepository()
        try:
            tables = snapshot["tables"]
            with temp_repo.conn.transaction():
                for u in tables["users_rbac"]:
                    temp_repo.conn.execute(
                        """
                        INSERT INTO users_rbac (
                            user_id, entra_oid, slack_user_id, full_name, email,
                            staff_role, gphc_reg_number, is_active, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            u["user_id"],
                            u["entra_oid"],
                            u["slack_user_id"],
                            u["full_name"],
                            u["email"],
                            u["staff_role"],
                            u["gphc_reg_number"],
                            bool(u["is_active"]),
                            u["created_at"],
                        ),
                    )

                for t in tables["tasks_master"]:
                    temp_repo.conn.execute(
                        """
                        INSERT INTO tasks_master (
                            task_id, task_name, frequency, daily_timing_window,
                            assigned_role, original_role_label,
                            requires_structured_input, input_schema, is_active
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                        """,
                        (
                            t["task_id"],
                            t["task_name"],
                            t["frequency"],
                            t["daily_timing_window"],
                            t["assigned_role"],
                            t["original_role_label"],
                            bool(t["requires_structured_input"]),
                            t["input_schema"] if isinstance(t["input_schema"], str) else canonical_json(t["input_schema"]),
                            bool(t["is_active"]),
                        ),
                    )

                for inst in tables["task_instances"]:
                    temp_repo.conn.execute(
                        """
                        INSERT INTO task_instances (
                            instance_id, task_id, period_key,
                            period_start_date, period_end_date,
                            status, completed_by_user_id, completed_at,
                            structured_data, notes, escalation_count,
                            last_reminded_at, slack_channel_id, slack_message_ts, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            inst["instance_id"],
                            inst["task_id"],
                            inst["period_key"],
                            inst["period_start_date"],
                            inst["period_end_date"],
                            inst["status"],
                            inst["completed_by_user_id"],
                            inst["completed_at"],
                            inst["structured_data"] if isinstance(inst["structured_data"], str) else canonical_json(inst["structured_data"]),
                            inst["notes"],
                            inst["escalation_count"],
                            inst["last_reminded_at"],
                            inst["slack_channel_id"],
                            inst["slack_message_ts"],
                            inst["created_at"],
                        ),
                    )

                for ev in tables["task_events_audit"]:
                    temp_repo.conn.execute(
                        """
                        INSERT INTO task_events_audit (
                            audit_seq, event_id, event_type, task_id, instance_id,
                            period_key, actor_user_id, actor_slack_id, actor_entra_oid,
                            actor_role, payload, occurred_at, prev_hash, row_hash
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)
                        """,
                        (
                            ev["audit_seq"],
                            ev["event_id"],
                            ev["event_type"],
                            ev["task_id"],
                            ev["instance_id"],
                            ev["period_key"],
                            ev["actor_user_id"],
                            ev["actor_slack_id"],
                            ev["actor_entra_oid"],
                            ev["actor_role"],
                            ev["payload"] if isinstance(ev["payload"], str) else canonical_json(ev["payload"]),
                            ev["occurred_at"],
                            ev["prev_hash"],
                            ev["row_hash"],
                        ),
                    )

            restored_tasks = int(
                temp_repo.conn.execute("SELECT COUNT(*) AS cnt FROM tasks_master").fetchone()["cnt"]
            )
            restored_instances = int(
                temp_repo.conn.execute("SELECT COUNT(*) AS cnt FROM task_instances").fetchone()["cnt"]
            )
            restored_audits = int(
                temp_repo.conn.execute("SELECT COUNT(*) AS cnt FROM task_events_audit").fetchone()["cnt"]
            )
            chain_check = temp_repo.verify_ledger_integrity()

            passed = (
                restored_tasks == len(tables["tasks_master"])
                and restored_instances == len(tables["task_instances"])
                and restored_audits == len(tables["task_events_audit"])
                and chain_check.is_valid
            )
            return self._record_verification_outcome(
                verification_id=verification_id,
                backup_date=backup_date,
                s3_object_key=s3_object_key,
                archive_sha256=archive_sha256,
                restored_task_count=restored_tasks,
                restored_instance_count=restored_instances,
                restored_audit_count=restored_audits,
                hash_chain_valid=chain_check.is_valid,
                status="PASSED" if passed else "FAILED",
                error_details=chain_check.failure_reason if not passed else None,
                verified_at_iso=now_iso,
            )
        finally:
            temp_repo.close()

    def _record_verification_outcome(
        self,
        *,
        verification_id: str,
        backup_date: date,
        s3_object_key: str,
        archive_sha256: str,
        restored_task_count: int,
        restored_instance_count: int,
        restored_audit_count: int,
        hash_chain_valid: bool,
        status: str,
        error_details: Optional[str],
        verified_at_iso: str,
    ) -> BreakGlassVerificationReport:
        with self.repo.conn.transaction():
            self.repo.conn.execute(
                """
                INSERT INTO backup_verification_logs (
                    verification_id, backup_date, s3_bucket, s3_object_key,
                    archive_sha256, encryption_cipher, restored_task_count,
                    restored_audit_count, hash_chain_valid, verification_status,
                    error_details, verified_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    verification_id,
                    backup_date.isoformat(),
                    self.s3_bucket,
                    s3_object_key,
                    archive_sha256,
                    CIPHER_IDENTIFIER,
                    restored_task_count,
                    restored_audit_count,
                    bool(hash_chain_valid),
                    status,
                    error_details,
                    verified_at_iso,
                ),
            )

        self.repo.append_audit_event(
            event_type=AuditEventType.BREAK_GLASS_VERIFIED,
            period_key=backup_date.isoformat(),
            payload={
                "verification_id": verification_id,
                "s3_bucket": self.s3_bucket,
                "s3_object_key": s3_object_key,
                "archive_sha256": archive_sha256,
                "restored_task_count": restored_task_count,
                "restored_audit_count": restored_audit_count,
                "hash_chain_valid": hash_chain_valid,
                "status": status,
                "error_details": error_details,
            },
        )

        return BreakGlassVerificationReport(
            verification_id=verification_id,
            backup_date=backup_date,
            s3_bucket=self.s3_bucket,
            s3_object_key=s3_object_key,
            archive_sha256=archive_sha256,
            restored_task_count=restored_task_count,
            restored_instance_count=restored_instance_count,
            restored_audit_count=restored_audit_count,
            hash_chain_valid=hash_chain_valid,
            status=status,
            error_details=error_details,
        )
