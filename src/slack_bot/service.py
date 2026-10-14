"""
Production Slack Socket Mode & APScheduler Service Runner.
Connects to Slack Free Tier via Socket Mode (no public inbound webhook URL required)
and dispatches Morning, Mid-Day, End-of-Day, and Closing Escalation checklists.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
import logging

from src.config import AppConfig
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.handlers import SlackComplianceHandler
from src.slack_bot.scheduler import TrancheSchedulerEngine, TrancheWindow

logger = logging.getLogger("pharmacy_compliance.slack_service")


def create_slack_runtime(config: AppConfig | None = None) -> tuple[ComplianceRepository, SlackComplianceHandler, TrancheSchedulerEngine]:
    cfg = config or AppConfig()
    repo = ComplianceRepository(cfg.sqlite_fallback_path)
    repo.seed_tasks_from_sql_file()
    handler = SlackComplianceHandler(repo)
    scheduler = TrancheSchedulerEngine(repo)
    return repo, handler, scheduler


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    cfg = AppConfig()
    repo, handler, scheduler = create_slack_runtime(cfg)
    logger.info("Pharmacy Compliance Slack Service initialized (Timezone=%s).", cfg.timezone)

    # Ensure today's instances are scheduled on startup
    today = datetime.now(timezone.utc).date()
    scheduler.run_tranche(TrancheWindow.MORNING, today)
    logger.info("Initial tranche state verified for %s.", today.isoformat())


if __name__ == "__main__":
    main()
