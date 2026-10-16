"""
Deterministic PostgreSQL Acceptance Tests for WP-3
(Audit IDs: ID-001, ID-004, ID-007, ID-011, ID-012, ID-028).
"""

from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jwt.algorithms import RSAAlgorithm

from src.dashboard.app import redact_audit_event_for_ui
from src.dashboard.auth import EntraIDAuthenticator
from src.domain.models import (
    RoleRequirement,
    StaffRole,
    can_complete_clinical_tasks,
    can_view_audit_and_rota_oversight,
    is_role_authorized,
)
from src.repository.db_repo import ComplianceRepository

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestWP3EntraAuthAndRBACHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = ComplianceRepository()
        self.repo.seed_tasks_from_sql_file()
        self.tenant_id = "11111111-2222-3333-4444-555555555555"
        self.client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        self.auth = EntraIDAuthenticator(
            self.repo,
            expected_tenant_id=self.tenant_id,
            expected_client_id=self.client_id,
        )
        self.pharm = self.repo.upsert_user(
            entra_oid="oid-anjum-rp-001",
            slack_user_id="U_PHARM_ANJUM",
            full_name="Anjum Superintendent RP",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2054321",
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_id001_dashboard_removes_staff_impersonation_selectbox(self) -> None:
        app_src = (REPO_ROOT / "src" / "dashboard" / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("st.selectbox", app_src)
        self.assertIn("_resolve_authenticated_entra_user", app_src)

    def test_id004_cryptographic_jwt_rs256_signature_exp_aud_iss_nonce_validation(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
        public_jwk["kid"] = "entra-key-2026"
        public_jwk["alg"] = "RS256"
        jwks_doc = {"keys": [public_jwk]}

        now = int(time.time())
        valid_claims = {
            "iss": f"https://login.microsoftonline.com/{self.tenant_id}/v2.0",
            "aud": self.client_id,
            "tid": self.tenant_id,
            "oid": self.pharm.entra_oid,
            "nonce": "nonce-998877",
            "iat": now - 10,
            "exp": now + 600,
        }
        valid_token = jwt.encode(
            valid_claims,
            private_key,
            algorithm="RS256",
            headers={"kid": "entra-key-2026"},
        )

        # 1. Valid signed RS256 token succeeds
        ok_res = self.auth.verify_id_token(
            valid_token,
            jwks_document=jwks_doc,
            expected_nonce="nonce-998877",
        )
        self.assertTrue(ok_res.authenticated)
        self.assertIsNotNone(ok_res.user)
        self.assertEqual(ok_res.user.entra_oid, self.pharm.entra_oid)  # type: ignore[union-attr]

        # 2. Expired token is rejected
        expired_claims = {**valid_claims, "exp": now - 120}
        expired_token = jwt.encode(
            expired_claims,
            private_key,
            algorithm="RS256",
            headers={"kid": "entra-key-2026"},
        )
        exp_res = self.auth.verify_id_token(
            expired_token,
            jwks_document=jwks_doc,
            expected_nonce="nonce-998877",
        )
        self.assertFalse(exp_res.authenticated)
        self.assertIn("expired", (exp_res.error_message or "").lower())

        # 3. Wrong audience (`aud`) is rejected
        wrong_aud_claims = {**valid_claims, "aud": "wrong-client-id"}
        wrong_aud_token = jwt.encode(
            wrong_aud_claims,
            private_key,
            algorithm="RS256",
            headers={"kid": "entra-key-2026"},
        )
        aud_res = self.auth.verify_id_token(
            wrong_aud_token,
            jwks_document=jwks_doc,
            expected_nonce="nonce-998877",
        )
        self.assertFalse(aud_res.authenticated)

        # 4. Wrong nonce is rejected
        nonce_res = self.auth.verify_id_token(
            valid_token,
            jwks_document=jwks_doc,
            expected_nonce="wrong-nonce",
        )
        self.assertFalse(nonce_res.authenticated)
        self.assertIn("nonce", (nonce_res.error_message or "").lower())

        # 5. Token signed by attacker RSA key is rejected
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged_token = jwt.encode(
            valid_claims,
            attacker_key,
            algorithm="RS256",
            headers={"kid": "entra-key-2026"},
        )
        forged_res = self.auth.verify_id_token(
            forged_token,
            jwks_document=jwks_doc,
            expected_nonce="nonce-998877",
        )
        self.assertFalse(forged_res.authenticated)

    def test_id007_docker_compose_binds_dashboard_to_localhost_only(self) -> None:
        compose_src = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("127.0.0.1:8501:8501", compose_src)
        self.assertNotIn('- "8501:8501"', compose_src)

    def test_id011_gphc_roles_and_manager_readonly_policy_enforced_in_postgres(self) -> None:
        pt_user = self.repo.upsert_user(
            entra_oid="oid-pt-01",
            slack_user_id="U_PT_01",
            full_name="Lead Pharmacy Technician",
            email="pt@pharmacy.co.uk",
            staff_role=StaffRole.PHARM_TECH,
        )
        mca_user = self.repo.upsert_user(
            entra_oid="oid-mca-01",
            slack_user_id="U_MCA_01",
            full_name="Medicines Counter Assistant",
            email="mca@pharmacy.co.uk",
            staff_role=StaffRole.MCA,
        )
        mgr_user = self.repo.upsert_user(
            entra_oid="oid-mgr-01",
            slack_user_id="U_MGR_01",
            full_name="Non-Clinical Manager",
            email="mgr@pharmacy.co.uk",
            staff_role=StaffRole.MANAGER,
        )
        self.assertEqual(pt_user.staff_role, StaffRole.PHARM_TECH)
        self.assertEqual(mca_user.staff_role, StaffRole.MCA)
        self.assertEqual(mgr_user.staff_role, StaffRole.MANAGER)

        # Non-qualified Manager cannot complete ANY clinical/pharmacy task
        for req in (RoleRequirement.PHARM, RoleRequirement.DISPENSER, RoleRequirement.EITHER):
            self.assertFalse(is_role_authorized(StaffRole.MANAGER, req))
        self.assertFalse(can_complete_clinical_tasks(StaffRole.MANAGER))
        self.assertTrue(can_view_audit_and_rota_oversight(StaffRole.MANAGER))

        # PT can complete Dispenser and Either tasks, but not Pharm-only
        self.assertFalse(is_role_authorized(StaffRole.PHARM_TECH, RoleRequirement.PHARM))
        self.assertTrue(is_role_authorized(StaffRole.PHARM_TECH, RoleRequirement.DISPENSER))
        self.assertTrue(is_role_authorized(StaffRole.PHARM_TECH, RoleRequirement.EITHER))

        # MCA can complete Either tasks, but not Dispenser-only or Pharm-only
        self.assertFalse(is_role_authorized(StaffRole.MCA, RoleRequirement.PHARM))
        self.assertFalse(is_role_authorized(StaffRole.MCA, RoleRequirement.DISPENSER))
        self.assertTrue(is_role_authorized(StaffRole.MCA, RoleRequirement.EITHER))

        # Drive Manager, PT, and MCA through repo.complete_task_instance against PostgreSQL
        instances = self.repo.ensure_instances_for_date(date(2026, 10, 16))
        either_task = next(i for i in instances if i.assigned_role == RoleRequirement.EITHER and not i.requires_structured_input)
        disp_task = next(i for i in instances if i.assigned_role == RoleRequirement.DISPENSER)
        pharm_task = next(i for i in instances if i.assigned_role == RoleRequirement.PHARM)

        # Manager denied on Either task at repository layer
        mgr_ok, mgr_msg, _ = self.repo.complete_task_instance(
            instance_id=either_task.instance_id,
            actor_slack_id=mgr_user.slack_user_id,
        )
        self.assertFalse(mgr_ok)
        self.assertIn("Access Denied", mgr_msg)

        # MCA denied on Dispenser task, allowed on Either task
        mca_disp_ok, _, _ = self.repo.complete_task_instance(
            instance_id=disp_task.instance_id,
            actor_slack_id=mca_user.slack_user_id,
        )
        self.assertFalse(mca_disp_ok)
        mca_either_ok, _, _ = self.repo.complete_task_instance(
            instance_id=either_task.instance_id,
            actor_slack_id=mca_user.slack_user_id,
        )
        self.assertTrue(mca_either_ok)

        # PT denied on Pharm task, allowed on Dispenser task
        pt_pharm_ok, _, _ = self.repo.complete_task_instance(
            instance_id=pharm_task.instance_id,
            actor_slack_id=pt_user.slack_user_id,
        )
        self.assertFalse(pt_pharm_ok)
        pt_disp_ok, _, _ = self.repo.complete_task_instance(
            instance_id=disp_task.instance_id,
            actor_slack_id=pt_user.slack_user_id,
        )
        self.assertTrue(pt_disp_ok)

    def test_id012_id028_pii_minimized_in_audit_payload_and_redacted_in_ui(self) -> None:
        instances = self.repo.ensure_instances_for_date(date(2026, 10, 16))
        cd_task = next(i for i in instances if i.task_name == "CD Register Reconcile")
        ok, _, _ = self.repo.complete_task_instance(
            instance_id=cd_task.instance_id,
            actor_slack_id=self.pharm.slack_user_id,
            notes="Verified balance.",
        )
        self.assertTrue(ok)

        events = self.repo.get_all_audit_events()
        completed_ev = next(e for e in events if e["event_type"] == "TASK_COMPLETED")
        self.assertNotIn("gphc_reg_number", completed_ev["payload"])

        # UI redaction for Manager masks raw actor identifiers
        redacted_for_mgr = redact_audit_event_for_ui(completed_ev, StaffRole.MANAGER)
        self.assertTrue(str(redacted_for_mgr["actor_slack_id"]).endswith("***"))
        self.assertTrue(str(redacted_for_mgr["actor_entra_oid"]).endswith("***"))


if __name__ == "__main__":
    unittest.main()
