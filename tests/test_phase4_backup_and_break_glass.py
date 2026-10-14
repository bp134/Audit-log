"""
Phase 4 Critic Verification Gate:
Tests Nightly Encrypted Cloud Archival, Automated Break-Glass Restore into an
ephemeral database instance, and detection of silent bit-rot / archive corruption.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
import tempfile
import unittest

from src.backup.archive_and_verify import HetznerS3BreakGlassManager
from src.domain.models import StaffRole
from src.repository.db_repo import ComplianceRepository


class Phase4CriticTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = ComplianceRepository(":memory:")
        self.repo.seed_tasks_from_sql_file()
        self.pharm = self.repo.upsert_user(
            entra_oid="entra-pharm-001",
            slack_user_id="U_PHARM_ANJUM",
            full_name="Anjum Superintendent RP",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2054321",
        )
        self.manager = HetznerS3BreakGlassManager(
            repo=self.repo,
            s3_bucket="pharmacy-compliance-vault",
            encryption_key="a" * 64,
            local_s3_staging_dir=Path(self.temp_dir.name),
        )

    def tearDown(self) -> None:
        self.repo.close()
        self.temp_dir.cleanup()

    def test_encrypted_backup_and_automated_break_glass_restore_succeeds(self) -> None:
        op_date = date(2026, 10, 13)
        instances = self.repo.ensure_instances_for_date(op_date)
        cd_task = next(i for i in instances if i.task_name == "CD Register Reconcile")
        self.repo.complete_task_instance(
            instance_id=cd_task.instance_id,
            actor_slack_id=self.pharm.slack_user_id,
        )

        s3_key, archive_path, sha256_hex = self.manager.create_encrypted_backup(op_date)
        self.assertTrue(archive_path.exists())
        self.assertEqual(len(sha256_hex), 64)

        # Ensure ciphertext does not leak plaintext strings
        raw_ciphertext = archive_path.read_bytes()
        self.assertNotIn(b"CD Register Reconcile", raw_ciphertext)
        self.assertTrue(raw_ciphertext.startswith(b"PHARMVAULT1"))

        # Run Break-Glass restore into ephemeral DB and verify 100% parity & hash chain
        report = self.manager.execute_break_glass_restore_test(
            backup_date=op_date,
            s3_object_key=s3_key,
        )
        self.assertEqual(report.status, "PASSED")
        self.assertEqual(report.restored_task_count, 33)
        self.assertEqual(report.restored_instance_count, 33)
        self.assertTrue(report.hash_chain_valid)

    def test_break_glass_restore_catches_silent_bit_rot_corruption(self) -> None:
        op_date = date(2026, 10, 13)
        self.repo.ensure_instances_for_date(op_date)
        s3_key, archive_path, _ = self.manager.create_encrypted_backup(op_date)

        # Critic Attack: Flip 1 byte in the middle of the encrypted S3 archive (simulating silent storage corruption)
        corrupted = bytearray(archive_path.read_bytes())
        corrupted[len(corrupted) // 2] ^= 0xFF
        archive_path.write_bytes(bytes(corrupted))

        report = self.manager.execute_break_glass_restore_test(
            backup_date=op_date,
            s3_object_key=s3_key,
        )
        self.assertEqual(report.status, "FAILED")
        self.assertFalse(report.hash_chain_valid)
        self.assertIn("CRITICAL BACKUP CORRUPTION", report.error_details or "")


if __name__ == "__main__":
    unittest.main()
