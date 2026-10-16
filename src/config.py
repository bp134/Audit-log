"""Centralized configuration for Pharmacy Workflow & Compliance Automation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

FORBIDDEN_PLACEHOLDERS = frozenset(
    {
        "changeme",
        "xoxb-placeholder",
        "xapp-placeholder",
        "slack-signing-placeholder",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    }
)


@dataclass(frozen=True)
class AppConfig:
    # Execution environment ("development" vs "production")
    environment: str = field(default_factory=lambda: os.getenv("ENV", "development").lower())

    # Database (Azure PostgreSQL Flexible Server in production; PostgreSQL test DB in local dev/test)
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL",
            os.getenv(
                "TEST_DATABASE_URL",
                "postgresql://postgres:postgres@localhost:5432/pharmacy_compliance_test",
            ),
        )
    )

    # Slack (Socket Mode - Free Tier compatible)
    slack_bot_token: str = field(default_factory=lambda: os.getenv("SLACK_BOT_TOKEN", "xoxb-placeholder"))
    slack_app_token: str = field(default_factory=lambda: os.getenv("SLACK_APP_TOKEN", "xapp-placeholder"))
    slack_signing_secret: str = field(
        default_factory=lambda: os.getenv("SLACK_SIGNING_SECRET", "slack-signing-placeholder")
    )
    slack_channel_id: str = field(default_factory=lambda: os.getenv("SLACK_CHANNEL_ID", "C01PHARMACY"))

    # Tranche Times (24h HH:MM format, Europe/London)
    timezone: str = field(default_factory=lambda: os.getenv("PHARMACY_TIMEZONE", "Europe/London"))
    tranche_morning_time: str = field(default_factory=lambda: os.getenv("TRANCHE_MORNING_TIME", "09:00"))
    tranche_midday_time: str = field(default_factory=lambda: os.getenv("TRANCHE_MIDDAY_TIME", "13:00"))
    tranche_eod_time: str = field(default_factory=lambda: os.getenv("TRANCHE_EOD_TIME", "17:30"))
    tranche_closing_escalation_time: str = field(
        default_factory=lambda: os.getenv("TRANCHE_CLOSING_ESCALATION_TIME", "18:15")
    )

    # Microsoft Entra ID (OIDC Authentication for Dashboard)
    entra_tenant_id: str = field(default_factory=lambda: os.getenv("ENTRA_TENANT_ID", ""))
    entra_client_id: str = field(default_factory=lambda: os.getenv("ENTRA_CLIENT_ID", ""))
    entra_client_secret: str = field(default_factory=lambda: os.getenv("ENTRA_CLIENT_SECRET", ""))
    entra_redirect_uri: str = field(
        default_factory=lambda: os.getenv("ENTRA_REDIRECT_URI", "http://localhost:8501")
    )

    # Hetzner S3 Object Storage & Backup Encryption
    hetzner_s3_endpoint: str = field(
        default_factory=lambda: os.getenv("HETZNER_S3_ENDPOINT", "https://fsn1.your-objectstorage.com")
    )
    hetzner_s3_bucket: str = field(
        default_factory=lambda: os.getenv("HETZNER_S3_BUCKET", "pharmacy-compliance-vault")
    )
    hetzner_s3_access_key: str = field(default_factory=lambda: os.getenv("HETZNER_S3_ACCESS_KEY", ""))
    hetzner_s3_secret_key: str = field(default_factory=lambda: os.getenv("HETZNER_S3_SECRET_KEY", ""))
    backup_encryption_key: str = field(
        default_factory=lambda: os.getenv(
            "BACKUP_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
    )

    def __post_init__(self) -> None:
        if self.environment != "development":
            self.validate_production_secrets()

    def validate_production_secrets(self) -> None:
        """ID-005: Fail fast if required secrets are missing or use known placeholders."""
        if (
            not self.database_url
            or "changeme" in self.database_url
            or "postgres:postgres@localhost" in self.database_url
        ):
            raise RuntimeError("ID-005 Violation: DATABASE_URL is missing or contains default password.")
        if not self.slack_bot_token or self.slack_bot_token in FORBIDDEN_PLACEHOLDERS:
            raise RuntimeError("ID-005 Violation: SLACK_BOT_TOKEN is missing or placeholder.")
        if not self.slack_app_token or self.slack_app_token in FORBIDDEN_PLACEHOLDERS:
            raise RuntimeError("ID-005 Violation: SLACK_APP_TOKEN is missing or placeholder.")
        if not self.slack_signing_secret or self.slack_signing_secret in FORBIDDEN_PLACEHOLDERS:
            raise RuntimeError("ID-024 Violation: SLACK_SIGNING_SECRET is missing or placeholder.")
        if (
            not self.backup_encryption_key
            or self.backup_encryption_key in FORBIDDEN_PLACEHOLDERS
            or len(self.backup_encryption_key) < 64
        ):
            raise RuntimeError("ID-005 Violation: BACKUP_ENCRYPTION_KEY is missing, weak, or default hex.")
