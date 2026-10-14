"""Microsoft Entra ID (OIDC) authentication and RBAC session verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from src.domain.models import AuditEventType, UserRecord
from src.repository.db_repo import ComplianceRepository


@dataclass(frozen=True)
class EntraAuthResult:
    authenticated: bool
    user: Optional[UserRecord]
    error_message: Optional[str] = None


class EntraIDAuthenticator:
    """
    Verifies Microsoft Entra ID OIDC token claims (`oid`, `tid`, `preferred_username`)
    against the configured tenant and the pharmacy's `users_rbac` table.
    """

    def __init__(self, repo: ComplianceRepository, expected_tenant_id: str) -> None:
        self.repo = repo
        self.expected_tenant_id = expected_tenant_id

    def verify_oidc_claims(self, claims: dict[str, Any]) -> EntraAuthResult:
        if not claims:
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Missing Microsoft Entra ID OIDC claims.",
            )

        token_tid = str(claims.get("tid", "")).strip()
        if self.expected_tenant_id and token_tid != self.expected_tenant_id:
            self.repo.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                payload={
                    "surface": "DASHBOARD_OIDC",
                    "reason": "TENANT_MISMATCH",
                    "token_tid": token_tid,
                },
            )
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Access Denied: Microsoft Entra tenant ID does not match authorized pharmacy tenant.",
            )

        entra_oid = str(claims.get("oid", "")).strip()
        if not entra_oid:
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Access Denied: Entra ID token is missing the mandatory `oid` (Object ID) claim.",
            )

        user = self.repo.get_user_by_entra_oid(entra_oid)
        if not user or not user.is_active:
            self.repo.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                payload={
                    "surface": "DASHBOARD_OIDC",
                    "reason": "UNMAPPED_ENTRA_OID",
                    "entra_oid": entra_oid,
                },
            )
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Access Denied: Your Entra ID account is not assigned an active pharmacy RBAC role.",
            )

        return EntraAuthResult(authenticated=True, user=user, error_message=None)
