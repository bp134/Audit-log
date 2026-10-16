"""
Nightly Encrypted Cloud Archival & Automated "Break-Glass" Restore Verifier (`src/backup/archive_and_verify.py`).
- ID-013: Uses standard AEAD encryption (`AES-256-GCM` via `cryptography` + `PBKDF2-HMAC-SHA256`)
  with key-versioned `PHARMVAULT1` header, replacing the legacy custom XOR stream cipher.
  Also verifies the `PGRSUS01` binary envelope + `.metadata` sidecars produced by the Databasus
  PostgreSQL backup container on Hetzner S3 (`db-backup-task-reminders`).
- ID-003: Transfers and retrieves encrypted archives + `.metadata` sidecars via `boto3` S3 client
  against Hetzner Object Storage (`https://hel1.your-objectstorage.com`).
- ID-023: Enforces a mandatory, non-bypassable SHA-256 hash-chain verification gate both BEFORE
  and AFTER restoring rows into an ephemeral PostgreSQL verification schema.
- ID-025: Executes native PostgreSQL `pg_dump --format=custom` when `pg_dump` is available.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import date, datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess  # nosec B404
from typing import Any, Optional
import uuid

import boto3
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.dashboard.reporting import generate_daily_compliance_report_markdown
from src.domain.ledger import canonical_json, format_canonical_utc_timestamp, verify_audit_chain
from src.domain.models import AuditEventType
from src.repository.db_repo import ComplianceRepository

CIPHER_IDENTIFIER = "AES-256-GCM-PBKDF2-SHA256-v2"
HEADER_PREFIX = b"PHARMVAULT1"
KEY_VERSION_CURRENT = 2
SALT_LEN = 16
NONCE_LEN = 12
GCM_TAG_LEN = 16

DATABASUS_MAGIC_HEADER = b"PGRSUS01"
DATABASUS_SALT_LEN = 32
DATABASUS_IV_LEN = 12


class ArchiveIntegrityError(ValueError):
    """Raised when an encrypted backup archive fails AES-256-GCM authentication or integrity checks."""


def _derive_aes256_key(master_key_hex: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(master_key_hex.encode("utf-8"))


def encrypt_archive_bytes(
    plaintext: bytes,
    master_key_hex: str,
    *,
    key_version: int = KEY_VERSION_CURRENT,
) -> bytes:
    """
    ID-013: Compresses `plaintext` with gzip and encrypts using standard `AES-256-GCM`
    with a 16-byte random salt, 12-byte random nonce, and 1-byte key version bound via AAD.
    Wire layout:
        b"PHARMVAULT1" (11B) | key_version (1B) | salt (16B) | nonce (12B) | ciphertext + 16B GCM tag
    """
    if not (1 <= key_version <= 255):
        raise ValueError("key_version must be between 1 and 255.")
    compressed = gzip.compress(plaintext, compresslevel=6)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_aes256_key(master_key_hex, salt)

    aad = HEADER_PREFIX + bytes([key_version])
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, compressed, aad)
    return aad + salt + nonce + ciphertext_and_tag


def decrypt_archive_bytes(bundle: bytes, master_key_hex: str) -> bytes:
    """
    ID-013: Verifies the `AES-256-GCM` authentication tag and AAD header (`PHARMVAULT1` + key_version)
    before decompressing the archive. Raises `ArchiveIntegrityError` if even 1 bit is corrupted.
    """
    min_len = len(HEADER_PREFIX) + 1 + SALT_LEN + NONCE_LEN + GCM_TAG_LEN
    if len(bundle) < min_len or not bundle.startswith(HEADER_PREFIX):
        raise ArchiveIntegrityError("Invalid or truncated PHARMVAULT1 archive header.")

    prefix_len = len(HEADER_PREFIX)
    key_version = bundle[prefix_len]
    if key_version != KEY_VERSION_CURRENT:
        raise ArchiveIntegrityError(f"Unsupported PHARMVAULT1 key version: {key_version}")

    salt_start = prefix_len + 1
    nonce_start = salt_start + SALT_LEN
    ct_start = nonce_start + NONCE_LEN

    salt = bundle[salt_start:nonce_start]
    nonce = bundle[nonce_start:ct_start]
    ciphertext_and_tag = bundle[ct_start:]
    aad = bundle[:salt_start]

    key = _derive_aes256_key(master_key_hex, salt)
    try:
        compressed = AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise ArchiveIntegrityError(
            "CRITICAL BACKUP CORRUPTION: AES-256-GCM authentication tag verification failed!"
        ) from exc

    try:
        return gzip.decompress(compressed)
    except Exception as exc:
        raise ArchiveIntegrityError(f"Decompression failed after AES-256-GCM decryption: {exc}") from exc


def verify_databasus_pgrsus01_envelope(blob: bytes, metadata: dict[str, Any]) -> bool:
    """
    Verifies the binary envelope produced by the Databasus PostgreSQL backup service
    in Hetzner S3 (`db-backup-task-reminders`):
      - Bytes [0:8]   == b"PGRSUS01"
      - Bytes [8:40]  == Base64-decoded `metadata["encryptionSalt"]` (32 bytes)
      - Bytes [40:52] == Base64-decoded `metadata["encryptionIV"]` (12 bytes)
      - `metadata["encryption"] == "ENCRYPTED"`
      - Remaining payload length > 16 bytes (AES-GCM tag + compressed pg_dump stream)
    """
    header_len = len(DATABASUS_MAGIC_HEADER) + DATABASUS_SALT_LEN + DATABASUS_IV_LEN
    if len(blob) <= header_len + GCM_TAG_LEN:
        return False
    if blob[:8] != DATABASUS_MAGIC_HEADER:
        return False
    if metadata.get("encryption") != "ENCRYPTED":
        return False

    try:
        expected_salt = base64.b64decode(str(metadata.get("encryptionSalt") or ""), validate=True)
        expected_iv = base64.b64decode(str(metadata.get("encryptionIV") or ""), validate=True)
    except Exception:
        return False

    if len(expected_salt) != DATABASUS_SALT_LEN or len(expected_iv) != DATABASUS_IV_LEN:
        return False

    return blob[8:40] == expected_salt and blob[40:52] == expected_iv


def run_pg_dump_snapshot(database_url: str, pg_dump_bin: Optional[str] = None) -> Optional[bytes]:
    """
    ID-025: Executes PostgreSQL-native `pg_dump --format=custom --no-owner --no-privileges`
    when `pg_dump` is installed (as in the production Dockerfile or local PostgreSQL 18 install).
    """
    resolved_bin = pg_dump_bin or shutil.which("pg_dump")
    if not resolved_bin:
        win_pg18 = Path("C:/Program Files/PostgreSQL/18/bin/pg_dump.exe")
        if win_pg18.exists():
            resolved_bin = str(win_pg18)
    if not resolved_bin:
        return None

    res = subprocess.run(  # nosec B603
        [resolved_bin, "--dbname", database_url, "--format=custom", "--no-owner", "--no-privileges"],
        capture_output=True,
        check=False,
        timeout=60,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"pg_dump failed (exit {res.returncode}): {res.stderr.decode('utf-8', errors='replace')}"
        )
    return res.stdout


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
    Manages nightly AES-256-GCM encrypted backups to Hetzner S3 Object Storage (`boto3`)
    and executes automated Break-Glass restore verification into an isolated ephemeral
    PostgreSQL schema with non-bypassable pre- and post-restore hash-chain gates.
    """

    def __init__(
        self,
        repo: ComplianceRepository,
        s3_bucket: str,
        encryption_key: str,
        local_s3_staging_dir: Path,
        *,
        s3_endpoint: Optional[str] = None,
        s3_access_key: Optional[str] = None,
        s3_secret_key: Optional[str] = None,
        s3_client: Optional[Any] = None,
        enable_pg_dump: bool = False,
    ) -> None:
        self.repo = repo
        self.s3_bucket = s3_bucket
        self.encryption_key = encryption_key
        self.local_s3_staging_dir = local_s3_staging_dir
        self.local_s3_staging_dir.mkdir(parents=True, exist_ok=True)
        self.enable_pg_dump = enable_pg_dump

        if s3_client is not None:
            self._s3 = s3_client
        elif s3_endpoint and s3_access_key and s3_secret_key:
            self._s3 = boto3.client(
                "s3",
                endpoint_url=s3_endpoint,
                aws_access_key_id=s3_access_key,
                aws_secret_access_key=s3_secret_key,
            )
        else:
            self._s3 = None

    def create_encrypted_backup(self, backup_date: date) -> tuple[str, Path, str]:
        """
        Exports all PostgreSQL tables + daily compliance report (+ optional native `pg_dump`),
        encrypts client-side with `AES-256-GCM`, writes to local staging, and uploads
        both the `.vault` archive and `.metadata` JSON sidecar to Hetzner S3 via `boto3` when configured.
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
            t["input_schema"] = (
                canonical_json(t["input_schema"])
                if isinstance(t["input_schema"], dict)
                else t["input_schema"]
            )
            tasks.append(t)
        instances = []
        for r in self.repo.conn.execute("SELECT * FROM task_instances").fetchall():
            inst = dict(r)
            inst["instance_id"] = str(inst["instance_id"])
            inst["period_start_date"] = (
                inst["period_start_date"].isoformat()
                if isinstance(inst["period_start_date"], date)
                else str(inst["period_start_date"])
            )
            inst["period_end_date"] = (
                inst["period_end_date"].isoformat()
                if isinstance(inst["period_end_date"], date)
                else str(inst["period_end_date"])
            )
            inst["completed_by_user_id"] = (
                str(inst["completed_by_user_id"]) if inst["completed_by_user_id"] else None
            )
            inst["completed_at"] = (
                format_canonical_utc_timestamp(inst["completed_at"]) if inst["completed_at"] else None
            )
            inst["last_reminded_at"] = (
                format_canonical_utc_timestamp(inst["last_reminded_at"])
                if inst["last_reminded_at"]
                else None
            )
            inst["created_at"] = format_canonical_utc_timestamp(inst["created_at"])
            inst["structured_data"] = (
                canonical_json(inst["structured_data"])
                if isinstance(inst["structured_data"], dict)
                else inst["structured_data"]
            )
            instances.append(inst)

        audit_events = self.repo.get_all_audit_events()
        daily_report_md = generate_daily_compliance_report_markdown(self.repo, backup_date)

        pg_dump_b64: Optional[str] = None
        if self.enable_pg_dump:
            raw_dump = run_pg_dump_snapshot(self.repo.database_url)
            if raw_dump is not None:
                pg_dump_b64 = base64.b64encode(raw_dump).decode("ascii")

        payload_doc: dict[str, Any] = {
            "schema_version": "2.0",
            "cipher": CIPHER_IDENTIFIER,
            "backup_date": backup_date.isoformat(),
            "exported_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "daily_compliance_report_markdown": daily_report_md,
            "pg_dump_custom_b64": pg_dump_b64,
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

        if self._s3 is not None:
            metadata_doc = {
                "backupDate": backup_date.isoformat(),
                "cipher": CIPHER_IDENTIFIER,
                "keyVersion": KEY_VERSION_CURRENT,
                "archiveSha256": archive_sha256,
                "encryption": "ENCRYPTED",
            }
            self._s3.put_object(Bucket=self.s3_bucket, Key=s3_key, Body=encrypted_bytes)
            self._s3.put_object(
                Bucket=self.s3_bucket,
                Key=f"{s3_key}.metadata",
                Body=json.dumps(metadata_doc, sort_keys=True).encode("utf-8"),
            )

        return s3_key, target_path, archive_sha256

    def execute_break_glass_restore_test(
        self,
        *,
        backup_date: date,
        s3_object_key: str,
    ) -> BreakGlassVerificationReport:
        """
        ID-023: Reads the encrypted archive from local staging or Hetzner S3 (`boto3`),
        decrypts with `AES-256-GCM`, enforces a mandatory PRE-RESTORE SHA-256 hash-chain
        verification gate on `task_events_audit`, restores into an isolated ephemeral
        PostgreSQL schema, and enforces a mandatory POST-RESTORE database hash-chain check.
        """
        verification_id = str(uuid.uuid4())
        archive_path = self.local_s3_staging_dir / s3_object_key
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        raw_bytes: Optional[bytes] = None
        if archive_path.exists():
            raw_bytes = archive_path.read_bytes()
        elif self._s3 is not None:
            try:
                resp = self._s3.get_object(Bucket=self.s3_bucket, Key=s3_object_key)
                raw_bytes = resp["Body"].read()
                meta_resp = self._s3.get_object(Bucket=self.s3_bucket, Key=f"{s3_object_key}.metadata")
                meta_doc = json.loads(meta_resp["Body"].read().decode("utf-8"))
                expected_sha = str(meta_doc.get("archiveSha256") or "")
                actual_sha = hashlib.sha256(raw_bytes).hexdigest()
                if expected_sha and expected_sha != actual_sha:
                    raise ArchiveIntegrityError(
                        f"S3 metadata archiveSha256 mismatch: expected {expected_sha}, got {actual_sha}"
                    )
                archive_path.parent.mkdir(parents=True, exist_ok=True)
                archive_path.write_bytes(raw_bytes)
            except Exception as exc:
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
                    error_details=f"S3 download failed for {s3_object_key}: {exc}",
                    verified_at_iso=now_iso,
                )

        if raw_bytes is None:
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

        tables = snapshot.get("tables") or {}
        audit_rows = tables.get("task_events_audit") or []

        # ID-023 MANDATORY GATE 1: Pre-restore cryptographic hash-chain validation BEFORE any DB insert
        pre_chain_check = verify_audit_chain(audit_rows)
        if not pre_chain_check.is_valid:
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
                error_details=f"PRE-RESTORE CHAIN GATE REJECTED ARCHIVE: {pre_chain_check.failure_reason}",
                verified_at_iso=now_iso,
            )

        temp_repo = ComplianceRepository()
        try:
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
                            t["input_schema"]
                            if isinstance(t["input_schema"], str)
                            else canonical_json(t["input_schema"]),
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
                            inst["structured_data"]
                            if isinstance(inst["structured_data"], str)
                            else canonical_json(inst["structured_data"]),
                            inst["notes"],
                            inst["escalation_count"],
                            inst["last_reminded_at"],
                            inst["slack_channel_id"],
                            inst["slack_message_ts"],
                            inst["created_at"],
                        ),
                    )

                for ev in audit_rows:
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
                (temp_repo.conn.execute("SELECT COUNT(*) AS cnt FROM tasks_master").fetchone() or {"cnt": 0})["cnt"]
            )
            restored_instances = int(
                (temp_repo.conn.execute("SELECT COUNT(*) AS cnt FROM task_instances").fetchone() or {"cnt": 0})["cnt"]
            )
            restored_audits = int(
                (temp_repo.conn.execute("SELECT COUNT(*) AS cnt FROM task_events_audit").fetchone() or {"cnt": 0})["cnt"]
            )
            # ID-023 MANDATORY GATE 2: Post-restore database-level ledger integrity check
            chain_check = temp_repo.verify_ledger_integrity()

            passed = (
                restored_tasks == len(tables["tasks_master"])
                and restored_instances == len(tables["task_instances"])
                and restored_audits == len(audit_rows)
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
                error_details=f"Database restore trigger rejected tampered audit row: {exc}",
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
