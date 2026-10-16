"""
Nightly Backup & Break-Glass Restore Verification Service (`src/backup/service.py`).
- ID-014: Replaces the uncontrolled container restart loop with a timezone-aware
  `APScheduler` nightly schedule (`22:15` Europe/London) and an idempotency guard
  (`has_backup_verified_for_date`) so each operating date is backed up and verified
  once on schedule without tight-looping.
- ID-003: Routes backups to Hetzner S3 Object Storage (`boto3`) when credentials are configured.
"""

from __future__ import annotations

from datetime import date, datetime
import logging
from pathlib import Path
import signal
import time
from typing import Any, Optional
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from src.backup.archive_and_verify import BreakGlassVerificationReport, HetznerS3BreakGlassManager
from src.config import AppConfig
from src.repository.db_repo import ComplianceRepository

logger = logging.getLogger("pharmacy_compliance.backup_service")


def has_backup_verified_for_date(repo: ComplianceRepository, backup_date: date) -> bool:
    """
    ID-014: Idempotency guard checking whether a `PASSED` Break-Glass backup verification
    has already been recorded for `backup_date`.
    """
    row = repo.conn.execute(
        """
        SELECT 1 AS ok
        FROM backup_verification_logs
        WHERE backup_date = %s AND verification_status = 'PASSED'
        LIMIT 1
        """,
        (backup_date.isoformat(),),
    ).fetchone()
    return row is not None


def run_nightly_backup_and_verify(
    config: Optional[AppConfig] = None,
    staging_dir: Optional[Path] = None,
    target_date: Optional[date] = None,
    force: bool = False,
) -> Optional[BreakGlassVerificationReport]:
    cfg = config or AppConfig()
    repo = ComplianceRepository(cfg.database_url)
    try:
        repo.seed_tasks_from_sql_file()
        op_date = target_date or datetime.now(ZoneInfo(cfg.timezone)).date()

        if not force and has_backup_verified_for_date(repo, op_date):
            logger.info("Nightly backup for %s already verified (PASSED); skipping duplicate run.", op_date.isoformat())
            return None

        vault_dir = staging_dir or Path("/app/s3_vault")
        manager = HetznerS3BreakGlassManager(
            repo=repo,
            s3_bucket=cfg.hetzner_s3_bucket,
            encryption_key=cfg.backup_encryption_key,
            local_s3_staging_dir=vault_dir,
            s3_endpoint=cfg.hetzner_s3_endpoint if cfg.hetzner_s3_access_key else None,
            s3_access_key=cfg.hetzner_s3_access_key or None,
            s3_secret_key=cfg.hetzner_s3_secret_key or None,
            enable_pg_dump=True,
        )

        s3_key, _, sha256_hex = manager.create_encrypted_backup(op_date)
        report = manager.execute_break_glass_restore_test(backup_date=op_date, s3_object_key=s3_key)
        logger.info(
            "Nightly Backup & Break-Glass Verification status=%s key=%s sha256=%s",
            report.status,
            s3_key,
            sha256_hex,
        )
        return report
    finally:
        repo.close()


def build_backup_scheduler(
    config: Optional[AppConfig] = None,
    staging_dir: Optional[Path] = None,
) -> BackgroundScheduler:
    """
    ID-014: Builds a controlled nightly `BackgroundScheduler` running at `22:15` in the
    configured pharmacy timezone (`Europe/London`).
    """
    cfg = config or AppConfig()
    scheduler = BackgroundScheduler(timezone=cfg.timezone)
    scheduler.add_job(
        run_nightly_backup_and_verify,
        CronTrigger(hour=22, minute=15, timezone=cfg.timezone),
        kwargs={"config": cfg, "staging_dir": staging_dir},
        id="nightly_s3_backup_and_break_glass",
        replace_existing=True,
    )
    return scheduler


def main() -> None:
    """
    ID-014: Starts the controlled nightly backup scheduler daemon (`22:15` Europe/London)
    and waits for SIGTERM/SIGINT so the Docker container never exits and tight-loops.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    cfg = AppConfig()
    run_nightly_backup_and_verify(cfg)
    scheduler = build_backup_scheduler(cfg)
    scheduler.start()
    logger.info("Nightly Backup & Break-Glass Scheduler started (22:15 %s).", cfg.timezone)

    stop_requested = False

    def _on_signal(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    try:
        while not stop_requested:
            time.sleep(1.0)
    finally:
        scheduler.shutdown(wait=False)


if __name__ == "__main__":
    main()
