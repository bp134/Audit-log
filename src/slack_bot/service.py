"""
Production Slack Bolt Socket Mode & APScheduler Service Runner (`src/slack_bot/service.py`).
- ID-003 & ID-024: Wires `slack_bolt.App` (with signing-secret verification), `SocketModeHandler`,
  and `APScheduler` (`BackgroundScheduler` with timezone-aware `CronTrigger` jobs for Morning,
  Mid-Day, End-of-Day, Closing Audit, and Nightly Period-Close `Missed` transitions).
"""

from __future__ import annotations

from datetime import date, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import os
import re
import signal
from socketserver import ThreadingMixIn
import threading
from typing import Any
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from src.config import AppConfig
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.handlers import SlackComplianceHandler
from src.slack_bot.scheduler import TrancheSchedulerEngine, TrancheWindow

logger = logging.getLogger("pharmacy_compliance.slack_service")


def _parse_hhmm(time_str: str) -> tuple[int, int]:
    parts = time_str.strip().split(":")
    return int(parts[0]), int(parts[1])


def _current_pharmacy_date(tz_name: str) -> date:
    return datetime.now(ZoneInfo(tz_name)).date()


def check_database_readiness(repo: ComplianceRepository) -> tuple[bool, str]:
    """
    ID-015: Verifies PostgreSQL connectivity and `tasks_master` readiness.
    """
    try:
        if repo.conn.closed:
            return False, "Database connection is closed."
        row = repo.conn.execute("SELECT COUNT(*) AS cnt FROM tasks_master").fetchone()
        cnt = int((row or {"cnt": 0})["cnt"])
        return True, f"Ready (tasks_master={cnt})"
    except Exception as exc:
        return False, f"Database not ready: {exc}"


class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class HealthProbeServer:
    """
    ID-015: Lightweight HTTP `/health` and `/ready` probe server for container orchestration.
    """

    def __init__(
        self,
        repo: ComplianceRepository,
        *,
        service_name: str = "slack-compliance-bot",
        host: str = "127.0.0.1",
        port: int = 8080,
    ) -> None:
        self.repo = repo
        self.service_name = service_name
        self.host = host
        self.port = port
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/health":
                    body = json.dumps({"status": "alive", "service": parent.service_name}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/ready":
                    ready_ok, detail = check_database_readiness(parent.repo)
                    code = 200 if ready_ok else 503
                    body = json.dumps(
                        {
                            "status": "ready" if ready_ok else "not_ready",
                            "service": parent.service_name,
                            "detail": detail,
                        }
                    ).encode("utf-8")
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        self._httpd = _ThreadedHTTPServer((self.host, self.port), _Handler)
        self.actual_port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def install_graceful_shutdown_handlers(
    repo: ComplianceRepository,
    scheduler: BackgroundScheduler,
    probe_server: HealthProbeServer | None = None,
) -> dict[str, bool]:
    """
    ID-015: Installs `SIGTERM` and `SIGINT` handlers that cleanly shut down the APScheduler,
    stop the health probe server, and close the PostgreSQL connection.
    """
    state = {"stopped": False}

    def _handle_signal(_signum: int, _frame: Any) -> None:
        if state["stopped"]:
            return
        state["stopped"] = True
        if getattr(scheduler, "running", False):
            scheduler.shutdown(wait=False)
        if probe_server is not None:
            probe_server.stop()
        repo.close()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    return state


def create_slack_runtime(
    config: AppConfig | None = None,
) -> tuple[ComplianceRepository, SlackComplianceHandler, TrancheSchedulerEngine]:
    cfg = config or AppConfig()
    repo = ComplianceRepository(cfg.database_url)
    repo.seed_tasks_from_sql_file()
    handler = SlackComplianceHandler(
        repo,
        signing_secret=cfg.slack_signing_secret,
        require_signature=(cfg.environment == "production"),
    )
    scheduler = TrancheSchedulerEngine(repo)
    return repo, handler, scheduler


def build_bolt_app(cfg: AppConfig, handler: SlackComplianceHandler) -> App:
    """
    ID-003 & ID-024: Builds a Slack Bolt `App` with signing-secret middleware and wires
    interactive Block Kit button clicks and Fridge Temperature modal submissions.
    """
    app = App(
        token=cfg.slack_bot_token,
        signing_secret=cfg.slack_signing_secret,
        request_verification_enabled=True,
        token_verification_enabled=False,
    )

    @app.action(re.compile(r"^(complete_task|open_fridge_modal):.+"))
    def _on_task_button_click(ack: Any, body: dict[str, Any], client: Any, context: dict[str, Any]) -> None:
        ack()
        actions = body.get("actions") or [{}]
        action_id = str(actions[0].get("action_id") or "")
        actor_slack_id = str((body.get("user") or {}).get("id") or "")
        headers = context.get("headers") or {}
        resp = handler.handle_button_click(
            action_id=action_id,
            actor_slack_id=actor_slack_id,
            signature=headers.get("X-Slack-Signature") or headers.get("x-slack-signature"),
            timestamp=headers.get("X-Slack-Request-Timestamp") or headers.get("x-slack-request-timestamp"),
            raw_body=context.get("raw_body"),
        )
        if resp.modal_view and body.get("trigger_id"):
            client.views_open(trigger_id=body["trigger_id"], view=resp.modal_view)
        elif body.get("channel", {}).get("id") and actor_slack_id:
            client.chat_postEphemeral(
                channel=body["channel"]["id"],
                user=actor_slack_id,
                text=resp.ephemeral_message,
            )

    @app.view(re.compile(r"^submit_fridge_modal:.+"))
    def _on_fridge_modal_submit(
        ack: Any, body: dict[str, Any], view: dict[str, Any], client: Any, context: dict[str, Any]
    ) -> None:
        ack()
        callback_id = str(view.get("callback_id") or "")
        instance_id = str(view.get("private_metadata") or "")
        if not instance_id and ":" in callback_id:
            instance_id = callback_id.split(":", 1)[1]
        actor_slack_id = str((body.get("user") or {}).get("id") or "")
        values = (view.get("state") or {}).get("values") or {}
        min_raw = str(((values.get("min_temp_block") or {}).get("min_temp_input") or {}).get("value") or "")
        max_raw = str(((values.get("max_temp_block") or {}).get("max_temp_input") or {}).get("value") or "")
        cur_raw = str(((values.get("current_temp_block") or {}).get("current_temp_input") or {}).get("value") or "")
        note_raw = str(((values.get("action_note_block") or {}).get("action_note_input") or {}).get("value") or "")
        headers = context.get("headers") or {}
        resp = handler.handle_fridge_modal_submission(
            instance_id=instance_id,
            actor_slack_id=actor_slack_id,
            min_temp_raw=min_raw,
            max_temp_raw=max_raw,
            current_temp_raw=cur_raw,
            action_note=note_raw,
            signature=headers.get("X-Slack-Signature") or headers.get("x-slack-signature"),
            timestamp=headers.get("X-Slack-Request-Timestamp") or headers.get("x-slack-request-timestamp"),
            raw_body=context.get("raw_body"),
        )
        if actor_slack_id:
            client.chat_postMessage(channel=actor_slack_id, text=resp.ephemeral_message)

    return app


def build_tranche_scheduler(
    cfg: AppConfig,
    scheduler_engine: TrancheSchedulerEngine,
    bolt_app: App | None = None,
) -> BackgroundScheduler:
    """
    ID-003 & ID-019: Configures the APScheduler `BackgroundScheduler` with timezone-aware
    cron triggers for the 4 daily compliance tranches plus the nightly `close_expired_periods` job.
    """
    bg_scheduler = BackgroundScheduler(timezone=cfg.timezone)

    def _dispatch_tranche(window: TrancheWindow) -> None:
        today = _current_pharmacy_date(cfg.timezone)
        res = scheduler_engine.run_tranche(window, today)
        if bolt_app is not None and cfg.slack_channel_id and cfg.environment == "production":
            bolt_app.client.chat_postMessage(
                channel=cfg.slack_channel_id,
                text=f"Pharmacy Compliance Checklist ({window.value})",
                blocks=res.slack_blocks,
            )

    m_hr, m_min = _parse_hhmm(cfg.tranche_morning_time)
    md_hr, md_min = _parse_hhmm(cfg.tranche_midday_time)
    eod_hr, eod_min = _parse_hhmm(cfg.tranche_eod_time)
    cl_hr, cl_min = _parse_hhmm(cfg.tranche_closing_escalation_time)

    bg_scheduler.add_job(
        _dispatch_tranche,
        CronTrigger(hour=m_hr, minute=m_min, timezone=cfg.timezone),
        args=[TrancheWindow.MORNING],
        id="tranche_morning",
        replace_existing=True,
    )
    bg_scheduler.add_job(
        _dispatch_tranche,
        CronTrigger(hour=md_hr, minute=md_min, timezone=cfg.timezone),
        args=[TrancheWindow.MID_DAY],
        id="tranche_midday",
        replace_existing=True,
    )
    bg_scheduler.add_job(
        _dispatch_tranche,
        CronTrigger(hour=eod_hr, minute=eod_min, timezone=cfg.timezone),
        args=[TrancheWindow.END_OF_DAY],
        id="tranche_eod",
        replace_existing=True,
    )
    bg_scheduler.add_job(
        _dispatch_tranche,
        CronTrigger(hour=cl_hr, minute=cl_min, timezone=cfg.timezone),
        args=[TrancheWindow.CLOSING_AUDIT],
        id="tranche_closing_audit",
        replace_existing=True,
    )
    bg_scheduler.add_job(
        lambda: scheduler_engine.close_expired_periods(_current_pharmacy_date(cfg.timezone)),
        CronTrigger(hour=0, minute=5, timezone=cfg.timezone),
        id="close_expired_periods",
        replace_existing=True,
    )
    return bg_scheduler


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    cfg = AppConfig()
    repo, handler, scheduler_engine = create_slack_runtime(cfg)
    bolt_app = build_bolt_app(cfg, handler)
    bg_scheduler = build_tranche_scheduler(cfg, scheduler_engine, bolt_app=bolt_app)

    probe_port = int(os.getenv("SLACK_HEALTH_PORT", "8080"))
    probe_server = HealthProbeServer(repo, service_name="slack-compliance-bot", port=probe_port)
    probe_server.start()
    install_graceful_shutdown_handlers(repo, bg_scheduler, probe_server)

    today = _current_pharmacy_date(cfg.timezone)
    scheduler_engine.run_tranche(TrancheWindow.MORNING, today)
    bg_scheduler.start()
    logger.info("Pharmacy Compliance Slack Bolt + APScheduler started (Timezone=%s).", cfg.timezone)

    if cfg.environment == "production":
        SocketModeHandler(bolt_app, cfg.slack_app_token).start()


if __name__ == "__main__":
    main()
