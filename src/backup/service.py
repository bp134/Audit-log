"""Nightly backup and Break-Glass restore verification runner for Docker Compose."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path

from src.backup.archive_and_verify import HetznerS3BreakGlassManager
from src.config import AppConfig
from src.repository.db_repo import ComplianceRepository

logger = logging.getLogger("pharmacy_compliance.backup_service")


def run_nightly_backup_and_verify(
    config: AppConfig | None = None,
    staging_dir: Path | None = None,
) -> None:
    cfg = config or AppConfig()
    repo = ComplianceRepository(cfg.database_url)
    repo.seed_tasks_from_sql_file()

    vault_dir = staging_dir or Path("/app/s3_vault")
    manager = HetznerS3BreakGlassManager(
        repo=repo,
        s3_bucket=cfg.hetzner_s3_bucket,
        encryption_key=cfg.backup_encryption_key,
        local_s3_staging_dir=vault_dir,
    )

    today = datetime.now(timezone.utc).date()
    s3_key, _, sha256_hex = manager.create_encrypted_backup(today)
    report = manager.execute_break_glass_restore_test(backup_date=today, s3_object_key=s3_key)
    logger.info(
        "Nightly Backup & Break-Glass Verification status=%s key=%s sha256=%s",
        report.status,
        s3_key,
        sha256_hex,
    )
    repo.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    run_nightly_backup_and_verify()
