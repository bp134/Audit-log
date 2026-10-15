"""Deterministic acceptance tests for WP-1 (Audit IDs: ID-005, ID-006, ID-020, ID-021)."""

import ast
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from src.config import AppConfig

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestWP1SecretsAndHygiene(unittest.TestCase):
    def test_id005_production_fails_fast_on_default_secrets(self) -> None:
        with patch.dict(os.environ, {"ENV": "production"}, clear=False):
            with self.assertRaises(RuntimeError):
                AppConfig()

    def test_id005_production_succeeds_with_strong_secrets(self) -> None:
        env = {
            "ENV": "production",
            "DATABASE_URL": "postgresql://prod_user:S3cureP@ssw0rd99@db.internal:5432/compliance",
            "SLACK_BOT_TOKEN": "xoxb-real-token-998877",
            "SLACK_APP_TOKEN": "xapp-real-token-112233",
            "BACKUP_ENCRYPTION_KEY": "a" * 64,
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = AppConfig()
            self.assertEqual(cfg.environment, "production")

    def test_id006_gitignore_blocks_sensitive_paths(self) -> None:
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for required_pattern in (".env", "*.db", "s3_vault/", "__pycache__/"):
            self.assertIn(required_pattern, gitignore)

    def test_id020_requirements_strictly_pinned_all_six_deps(self) -> None:
        reqs = [
            line.strip()
            for line in (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertEqual(len(reqs), 6, f"Expected all 6 dependencies in requirements.txt, got {len(reqs)}: {reqs}")
        for req in reqs:
            self.assertIn("==", req, f"Dependency not strictly pinned: {req}")

    def test_id021_demo_staff_seeding_gated_by_development_env(self) -> None:
        app_source = (REPO_ROOT / "src" / "dashboard" / "app.py").read_text(encoding="utf-8")
        self.assertIn('cfg.environment == "development"', app_source)
        ast.parse(app_source)


if __name__ == "__main__":
    unittest.main()
