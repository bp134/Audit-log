"""
Deterministic PostgreSQL Acceptance Tests for WP-6
(Audit IDs: ID-015, ID-026, ID-027 — completing all 28 audit findings).
"""

from __future__ import annotations

import json
from pathlib import Path
import signal
import unittest
import urllib.error
import urllib.request

import yaml

from src.config import AppConfig
from src.repository.db_repo import ComplianceRepository
from src.slack_bot.scheduler import TrancheSchedulerEngine
from src.slack_bot.service import (
    HealthProbeServer,
    build_tranche_scheduler,
    check_database_readiness,
    install_graceful_shutdown_handlers,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestWP6HealthCicdAndDocs(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = ComplianceRepository()
        self.repo.seed_tasks_from_sql_file()

    def tearDown(self) -> None:
        self.repo.close()

    def test_id015_health_and_readiness_http_probes_and_graceful_shutdown(self) -> None:
        ready_ok, detail = check_database_readiness(self.repo)
        self.assertTrue(ready_ok)
        self.assertIn("tasks_master=33", detail)

        probe = HealthProbeServer(self.repo, service_name="test-compliance-svc", host="127.0.0.1", port=0)
        probe.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{probe.actual_port}/health", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["status"], "alive")

            with urllib.request.urlopen(f"http://127.0.0.1:{probe.actual_port}/ready", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["status"], "ready")
        finally:
            probe.stop()

        # Verify graceful shutdown handler closes DB and stops scheduler, restoring original signal handlers
        orig_sigterm = signal.getsignal(signal.SIGTERM)
        orig_sigint = signal.getsignal(signal.SIGINT)
        try:
            sched = build_tranche_scheduler(AppConfig(), TrancheSchedulerEngine(self.repo))
            state = install_graceful_shutdown_handlers(self.repo, sched)
            self.assertFalse(state["stopped"])
            handler_fn = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler_fn))
            handler_fn(signal.SIGTERM, None)  # type: ignore[misc]
            self.assertTrue(state["stopped"])
            self.assertTrue(self.repo.conn.closed)
        finally:
            signal.signal(signal.SIGTERM, orig_sigterm)
            signal.signal(signal.SIGINT, orig_sigint)

    def test_id015_docker_compose_healthchecks_and_stop_grace_period(self) -> None:
        compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        services = compose["services"]
        for svc_name in ("slack-compliance-bot", "compliance-dashboard", "backup-break-glass-verifier"):
            self.assertIn(svc_name, services)
            self.assertIn("healthcheck", services[svc_name])
            self.assertEqual(services[svc_name].get("stop_grace_period"), "30s")

    def test_id027_github_actions_ci_workflow_valid_and_complete(self) -> None:
        ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
        self.assertTrue(ci_path.exists())
        ci_doc = yaml.safe_load(ci_path.read_text(encoding="utf-8"))
        job = ci_doc["jobs"]["compliance-verification"]
        self.assertEqual(job["services"]["postgres"]["image"], "postgres:18")

        steps_text = json.dumps(job["steps"])
        for required_gate in ("ruff", "bandit", "pip_audit", "gitleaks", "pytest"):
            self.assertIn(required_gate, steps_text)

    def test_id026_readme_documents_all_28_audit_ids_and_accurate_architecture(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("AES-256-GCM-PBKDF2-SHA256-v2", readme)
        self.assertIn("PGRSUS01", readme)
        self.assertNotIn("Encrypt-then-MAC", readme)
        for num in range(1, 29):
            audit_id = f"ID-{num:03d}"
            self.assertIn(audit_id, readme, f"Missing {audit_id} in README verification matrix")


if __name__ == "__main__":
    unittest.main()
