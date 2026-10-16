"""
Microsoft Entra ID (OIDC) Cryptographic Authentication and RBAC Session Verification (`src/dashboard/auth.py`).
- ID-004: Cryptographically verifies Microsoft Entra ID JWTs (`RS256` signature against JWKS public keys,
  `exp`, `iss`, `aud`, and `nonce`) using `PyJWT` and `msal`.
- Maps verified `oid` (Entra Object ID) and `tid` (Tenant ID) to active GPhC staff roles in PostgreSQL.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Optional
import urllib.request

import jwt
from jwt.algorithms import RSAAlgorithm
import msal

from src.domain.models import AuditEventType, UserRecord
from src.repository.db_repo import ComplianceRepository


@dataclass(frozen=True)
class EntraAuthResult:
    authenticated: bool
    user: Optional[UserRecord]
    error_message: Optional[str] = None


class EntraIDAuthenticator:
    """
    Verifies Microsoft Entra ID OIDC ID tokens (`RS256` JWT signature, `exp`, `iss`, `aud`, `nonce`)
    and maps the verified claims (`oid`, `tid`) to the pharmacy's `users_rbac` table.
    """

    def __init__(
        self,
        repo: ComplianceRepository,
        expected_tenant_id: str,
        expected_client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> None:
        self.repo = repo
        self.expected_tenant_id = expected_tenant_id
        self.expected_client_id = expected_client_id or ""
        self.client_secret = client_secret or ""

    @property
    def expected_issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.expected_tenant_id}/v2.0"

    def build_msal_authorization_url(self, nonce: str, redirect_uri: str) -> str:
        """Builds the Microsoft Entra ID OAuth2/OIDC authorization URL via MSAL."""
        if not self.expected_tenant_id or not self.expected_client_id:
            return ""
        authority = f"https://login.microsoftonline.com/{self.expected_tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id=self.expected_client_id,
            client_credential=self.client_secret or None,
            authority=authority,
        )
        return str(
            app.get_authorization_request_url(
                scopes=["User.Read"],
                redirect_uri=redirect_uri,
                nonce=nonce,
            )
        )

    def fetch_tenant_jwks(self) -> dict[str, Any]:
        """Fetches the Microsoft Entra ID tenant JWKS public keys over HTTPS."""
        jwks_url = f"https://login.microsoftonline.com/{self.expected_tenant_id}/discovery/v2.0/keys"
        if not jwks_url.startswith("https://login.microsoftonline.com/"):
            raise ValueError("Invalid Microsoft Entra JWKS discovery URL.")
        req = urllib.request.Request(jwks_url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            return dict(json.loads(resp.read().decode("utf-8")))

    def exchange_authorization_code(
        self,
        auth_code: str,
        *,
        redirect_uri: str,
        expected_nonce: Optional[str] = None,
        jwks_document: Optional[dict[str, Any]] = None,
    ) -> tuple[EntraAuthResult, Optional[dict[str, Any]]]:
        """
        ID-001 & ID-004: Exchanges an OAuth2 authorization `code` with Microsoft Entra ID via MSAL,
        extracts the raw `id_token`, and cryptographically verifies its RS256 signature against
        the tenant JWKS before establishing an authenticated session.
        """
        if not auth_code or not self.expected_tenant_id or not self.expected_client_id:
            return (
                EntraAuthResult(
                    authenticated=False,
                    user=None,
                    error_message="Access Denied: Missing Entra ID authorization code or tenant configuration.",
                ),
                None,
            )

        authority = f"https://login.microsoftonline.com/{self.expected_tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id=self.expected_client_id,
            client_credential=self.client_secret or None,
            authority=authority,
        )
        token_resp = app.acquire_token_by_authorization_code(
            code=auth_code,
            scopes=["User.Read"],
            redirect_uri=redirect_uri,
        )
        raw_id_token = str(token_resp.get("id_token") or "").strip()
        if not raw_id_token:
            err_desc = str(token_resp.get("error_description") or token_resp.get("error") or "No id_token returned.")
            self.repo.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                payload={"surface": "DASHBOARD_OIDC_EXCHANGE", "reason": "MSAL_CODE_EXCHANGE_FAILED"},
            )
            return (
                EntraAuthResult(
                    authenticated=False,
                    user=None,
                    error_message=f"Access Denied: Microsoft Entra code exchange failed ({err_desc}).",
                ),
                None,
            )

        jwks_doc = jwks_document if jwks_document is not None else self.fetch_tenant_jwks()
        auth_res = self.verify_id_token(
            raw_id_token,
            jwks_document=jwks_doc,
            expected_nonce=expected_nonce,
        )
        verified_claims = token_resp.get("id_token_claims") if auth_res.authenticated else None
        return auth_res, verified_claims

    def verify_id_token(
        self,
        id_token: str,
        *,
        jwks_document: dict[str, Any],
        expected_nonce: Optional[str] = None,
    ) -> EntraAuthResult:
        """
        ID-004: Cryptographically validates a raw Microsoft Entra ID JWT (`id_token`)
        against the tenant's JWKS RSA public keys, enforcing `RS256` signature,
        `exp`, `iss`, `aud`, and `nonce` before delegating to RBAC lookup.
        """
        if not id_token or not id_token.strip():
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Access Denied: Missing Microsoft Entra ID bearer token.",
            )

        try:
            unverified_header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message=f"Access Denied: Malformed JWT header ({exc}).",
            )

        alg = unverified_header.get("alg")
        if alg != "RS256":
            self.repo.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                payload={"surface": "DASHBOARD_OIDC_JWT", "reason": "INVALID_JWT_ALG", "alg": str(alg)},
            )
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Access Denied: Only RS256 signed Microsoft Entra ID tokens are permitted.",
            )

        kid = unverified_header.get("kid")
        keys = jwks_document.get("keys", [])
        matching_jwk = next((k for k in keys if k.get("kid") == kid), None)
        if not matching_jwk:
            self.repo.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                payload={"surface": "DASHBOARD_OIDC_JWT", "reason": "UNKNOWN_JWKS_KID", "kid": str(kid)},
            )
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Access Denied: Token signing key (kid) not found in Microsoft Entra JWKS.",
            )

        try:
            public_key = RSAAlgorithm.from_jwk(json.dumps(matching_jwk))
            decode_options = {
                "require": ["exp", "iss", "aud", "tid", "oid"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": bool(self.expected_tenant_id),
                "verify_aud": bool(self.expected_client_id),
            }
            verified_claims: dict[str, Any] = jwt.decode(
                id_token,
                key=public_key,  # type: ignore[arg-type]
                algorithms=["RS256"],
                audience=self.expected_client_id if self.expected_client_id else None,
                issuer=self.expected_issuer if self.expected_tenant_id else None,
                options=decode_options,
            )
        except jwt.ExpiredSignatureError:
            self.repo.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                payload={"surface": "DASHBOARD_OIDC_JWT", "reason": "TOKEN_EXPIRED"},
            )
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Access Denied: Microsoft Entra ID token has expired.",
            )
        except (jwt.PyJWTError, ValueError, KeyError) as exc:
            self.repo.append_audit_event(
                event_type=AuditEventType.RBAC_ACCESS_DENIED,
                payload={"surface": "DASHBOARD_OIDC_JWT", "reason": "JWT_VERIFICATION_FAILED"},
            )
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message=f"Access Denied: Cryptographic JWT validation failed ({exc}).",
            )

        return self.verify_oidc_claims(
            verified_claims,
            expected_nonce=expected_nonce,
            verify_temporal_claims=True,
        )

    def verify_oidc_claims(
        self,
        claims: dict[str, Any],
        *,
        expected_nonce: Optional[str] = None,
        verify_temporal_claims: bool = False,
    ) -> EntraAuthResult:
        if not claims:
            return EntraAuthResult(
                authenticated=False,
                user=None,
                error_message="Missing Microsoft Entra ID OIDC claims.",
            )

        if verify_temporal_claims or "exp" in claims:
            exp_val = claims.get("exp")
            if exp_val is None or float(exp_val) <= time.time():
                self.repo.append_audit_event(
                    event_type=AuditEventType.RBAC_ACCESS_DENIED,
                    payload={"surface": "DASHBOARD_OIDC", "reason": "TOKEN_EXPIRED"},
                )
                return EntraAuthResult(
                    authenticated=False,
                    user=None,
                    error_message="Access Denied: Microsoft Entra ID session token has expired.",
                )

        if self.expected_client_id and "aud" in claims:
            if str(claims.get("aud", "")).strip() != self.expected_client_id:
                self.repo.append_audit_event(
                    event_type=AuditEventType.RBAC_ACCESS_DENIED,
                    payload={"surface": "DASHBOARD_OIDC", "reason": "AUDIENCE_MISMATCH"},
                )
                return EntraAuthResult(
                    authenticated=False,
                    user=None,
                    error_message="Access Denied: Token audience (`aud`) does not match application client ID.",
                )

        if expected_nonce is not None:
            token_nonce = str(claims.get("nonce", "")).strip()
            if token_nonce != expected_nonce:
                self.repo.append_audit_event(
                    event_type=AuditEventType.RBAC_ACCESS_DENIED,
                    payload={"surface": "DASHBOARD_OIDC", "reason": "NONCE_MISMATCH"},
                )
                return EntraAuthResult(
                    authenticated=False,
                    user=None,
                    error_message="Access Denied: OIDC replay protection `nonce` mismatch.",
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
