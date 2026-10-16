"""
Deterministic PostgreSQL Acceptance Tests for WP-5
(Audit IDs: ID-003 [S3], ID-013, ID-014, ID-023, ID-025).
"""

from __future__ import annotations

import base64
from datetime import date
import gzip
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import unittest

from src.backup.archive_and_verify import (
    CIPHER_IDENTIFIER,
    KEY_VERSION_CURRENT,
    ArchiveIntegrityError,
    HetznerS3BreakGlassManager,
    decrypt_archive_bytes,
    encrypt_archive_bytes,
    run_pg_dump_snapshot,
    verify_databasus_pgrsus01_envelope,
)
from src.backup.service import build_backup_scheduler, has_backup_verified_for_date
from src.config import AppConfig
from src.domain.models import StaffRole
from src.repository.db_repo import ComplianceRepository


class FakeHetznerS3Client:
    """In-memory boto3-compatible S3 stub for deterministic S3 upload/download verification."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **_kwargs: Any) -> dict[str, Any]:
        self.objects[(Bucket, Key)] = bytes(Body)
        return {"ETag": '"fake-etag"'}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        if (Bucket, Key) not in self.objects:
            raise KeyError(f"NoSuchKey: {Bucket}/{Key}")

        class _BodyStream:
            def __init__(self, raw: bytes) -> None:
                self._raw = raw

            def read(self) -> bytes:
                return self._raw

        return {"Body": _BodyStream(self.objects[(Bucket, Key)])}


class TestWP5AesGcmS3AndDatabasusBreakGlass(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = ComplianceRepository()
        self.repo.seed_tasks_from_sql_file()
        self.pharm = self.repo.upsert_user(
            entra_oid="oid-pharm-wp5",
            slack_user_id="U_PHARM_WP5",
            full_name="Anjum Superintendent RP",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2054321",
        )
        self.fake_s3 = FakeHetznerS3Client()
        self.key_hex = "a" * 64
        self.manager = HetznerS3BreakGlassManager(
            repo=self.repo,
            s3_bucket="db-backup-task-reminders",
            encryption_key=self.key_hex,
            local_s3_staging_dir=Path(self.temp_dir.name),
            s3_client=self.fake_s3,
        )

    def tearDown(self) -> None:
        self.repo.close()
        self.temp_dir.cleanup()

    def test_id013_aes256_gcm_aead_encryption_and_databasus_pgrsus01_envelope_verifier(self) -> None:
        self.assertEqual(CIPHER_IDENTIFIER, "AES-256-GCM-PBKDF2-SHA256-v2")
        plaintext = b'{"compliance":"GPhC_AES_GCM_verified"}'
        bundle = encrypt_archive_bytes(plaintext, self.key_hex)
        self.assertTrue(bundle.startswith(b"PHARMVAULT1"))
        self.assertEqual(bundle[11], KEY_VERSION_CURRENT)
        self.assertEqual(decrypt_archive_bytes(bundle, self.key_hex), plaintext)

        # Tampering with the key_version AAD byte must fail AES-GCM tag authentication
        tampered_aad = bytearray(bundle)
        tampered_aad[11] = 99
        with self.assertRaises(ArchiveIntegrityError):
            decrypt_archive_bytes(bytes(tampered_aad), self.key_hex)

        # Verify Databasus PGRSUS01 binary envelope + .metadata sidecar format
        salt_32 = os.urandom(32)
        iv_12 = os.urandom(12)
        meta = {
            "backupId": "3d2273e2-afaa-4066-a1c1-fedb9fdeb1fa",
            "encryptionSalt": base64.b64encode(salt_32).decode("ascii"),
            "encryptionIV": base64.b64encode(iv_12).decode("ascii"),
            "encryption": "ENCRYPTED",
        }
        valid_pgrsus_blob = b"PGRSUS01" + salt_32 + iv_12 + os.urandom(128)
        self.assertTrue(verify_databasus_pgrsus01_envelope(valid_pgrsus_blob, meta))
        self.assertFalse(verify_databasus_pgrsus01_envelope(b"WRONGHDR" + salt_32 + iv_12 + os.urandom(128), meta))

    def test_id003_s3_upload_and_remote_download_restore_succeeds(self) -> None:
        op_date = date(2026, 10, 16)
        self.repo.ensure_instances_for_date(op_date)
        s3_key, local_path, _ = self.manager.create_encrypted_backup(op_date)

        # Verify both .vault and .metadata were uploaded to S3 bucket
        self.assertIn(("db-backup-task-reminders", s3_key), self.fake_s3.objects)
        self.assertIn(("db-backup-task-reminders", f"{s3_key}.metadata"), self.fake_s3.objects)

        # Delete local file to force execute_break_glass_restore_test to download from S3 via get_object
        local_path.unlink()
        self.assertFalse(local_path.exists())

        report = self.manager.execute_break_glass_restore_test(
            backup_date=op_date,
            s3_object_key=s3_key,
        )
        self.assertEqual(report.status, "PASSED")
        self.assertTrue(report.hash_chain_valid)
        self.assertTrue(local_path.exists())

    def test_id023_non_bypassable_pre_restore_chain_gate_rejects_tampered_audit_chain(self) -> None:
        op_date = date(2026, 10, 16)
        self.repo.ensure_instances_for_date(op_date)
        s3_key, local_path, _ = self.manager.create_encrypted_backup(op_date)

        # Decrypt, tamper with an audit row's row_hash inside the JSON payload, and re-encrypt with valid AES-GCM key
        decrypted = json.loads(decrypt_archive_bytes(local_path.read_bytes(), self.key_hex).decode("utf-8"))
        decrypted["tables"]["task_events_audit"][0]["row_hash"] = "f" * 64
        reencrypted = encrypt_archive_bytes(json.dumps(decrypted, sort_keys=True).encode("utf-8"), self.key_hex)
        local_path.write_bytes(reencrypted)

        report = self.manager.execute_break_glass_restore_test(
            backup_date=op_date,
            s3_object_key=s3_key,
        )
        self.assertEqual(report.status, "FAILED")
        self.assertFalse(report.hash_chain_valid)
        self.assertIn("PRE-RESTORE CHAIN GATE REJECTED ARCHIVE", report.error_details or "")

    def test_id014_id025_idempotency_guard_scheduler_and_pg_dump(self) -> None:
        op_date = date(2026, 10, 16)
        self.assertFalse(has_backup_verified_for_date(self.repo, op_date))

        self.repo.ensure_instances_for_date(op_date)
        s3_key, _, _ = self.manager.create_encrypted_backup(op_date)
        report = self.manager.execute_break_glass_restore_test(backup_date=op_date, s3_object_key=s3_key)
        self.assertEqual(report.status, "PASSED")
        self.assertTrue(has_backup_verified_for_date(self.repo, op_date))

        sched = build_backup_scheduler(AppConfig())
        job_ids = {j.id for j in sched.get_jobs()}
        self.assertIn("nightly_s3_backup_and_break_glass", job_ids)

        # Verify native pg_dump executes against local PostgreSQL 18
        dump_bytes = run_pg_dump_snapshot(self.repo.database_url)
        self.assertIsNotNone(dump_bytes)
        self.assertTrue((dump_bytes or b"").startswith(b"PGDMP"))


if __name__ == "__main__":
    unittest.main()
