"""
Streamlit Compliance & GPhC Inspection Dashboard (`src/dashboard/app.py`).
- ID-001: Enforces verified Microsoft Entra ID OIDC session before rendering; staff impersonation picker removed.
- ID-011: Enforces GPhC clinical role permissions (`Pharm`, `PT`, `Dispenser`, `MCA`) vs read-only `Manager` oversight.
- ID-012 & ID-028: Restricts forensic audit tab to authorized roles (`Pharm`, `Manager`) and redacts sensitive identifiers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any
import uuid

# Ensure project root is on sys.path when launched via `streamlit run`
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import AppConfig
from src.dashboard.auth import EntraIDAuthenticator
from src.dashboard.reporting import (
    build_dashboard_summary,
    export_inspection_csv,
    generate_daily_compliance_report_markdown,
)
from src.domain.models import (
    DailyWindow,
    InstanceStatus,
    StaffRole,
    TaskFrequency,
    UserRecord,
    can_complete_clinical_tasks,
    can_view_audit_and_rota_oversight,
    is_role_authorized,
)
from src.repository.db_repo import ComplianceRepository


def redact_audit_event_for_ui(event: dict[str, Any], viewer_role: StaffRole) -> dict[str, Any]:
    """
    ID-012 & ID-028: Redacts sensitive identifiers and raw credentials from audit rows
    displayed in the UI based on the viewer's role.
    """
    redacted = dict(event)
    payload = dict(redacted.get("payload") or {})
    payload.pop("gphc_reg_number", None)
    payload.pop("email", None)
    redacted["payload"] = payload

    if viewer_role != StaffRole.PHARM:
        slack_id = str(redacted.get("actor_slack_id") or "")
        if slack_id:
            redacted["actor_slack_id"] = f"{slack_id[:4]}***"
        entra_oid = str(redacted.get("actor_entra_oid") or "")
        if entra_oid:
            redacted["actor_entra_oid"] = f"{entra_oid[:8]}***"
    return redacted


def _resolve_authenticated_entra_user(
    st_mod: Any, cfg: AppConfig, repo: ComplianceRepository
) -> UserRecord | None:
    """
    ID-001: Resolves the signed-in user strictly from a verified Microsoft Entra ID OIDC session.
    Never offers a staff profile picker dropdown.
    """
    authenticator = EntraIDAuthenticator(
        repo=repo,
        expected_tenant_id=cfg.entra_tenant_id,
        expected_client_id=cfg.entra_client_id,
        client_secret=cfg.entra_client_secret,
    )

    session_claims = st_mod.session_state.get("entra_oidc_claims")
    expected_nonce = st_mod.session_state.get("entra_oidc_nonce")
    if isinstance(session_claims, dict):
        auth_res = authenticator.verify_oidc_claims(
            session_claims,
            expected_nonce=expected_nonce,
            verify_temporal_claims=True,
        )
        if auth_res.authenticated and auth_res.user:
            return auth_res.user
        st_mod.error(auth_res.error_message or "Entra ID session verification failed.")
        return None

    # Handle Microsoft Entra ID OAuth2/OIDC callback (`?code=...`) or bearer token (`?id_token=...`)
    query_params = getattr(st_mod, "query_params", {})
    auth_code = query_params.get("code") if hasattr(query_params, "get") else None
    raw_id_token = query_params.get("id_token") if hasattr(query_params, "get") else None

    if auth_code:
        auth_res, verified_claims = authenticator.exchange_authorization_code(
            str(auth_code),
            redirect_uri=cfg.entra_redirect_uri,
            expected_nonce=expected_nonce,
        )
        if auth_res.authenticated and auth_res.user and verified_claims:
            st_mod.session_state["entra_oidc_claims"] = verified_claims
            if hasattr(query_params, "clear"):
                query_params.clear()
            return auth_res.user
        st_mod.error(auth_res.error_message or "Microsoft Entra ID code exchange failed.")
        st_mod.stop()
        return None

    if raw_id_token:
        jwks_doc = authenticator.fetch_tenant_jwks()
        auth_res = authenticator.verify_id_token(
            str(raw_id_token),
            jwks_document=jwks_doc,
            expected_nonce=expected_nonce,
        )
        if auth_res.authenticated and auth_res.user:
            return auth_res.user
        st_mod.error(auth_res.error_message or "Microsoft Entra ID token verification failed.")
        st_mod.stop()
        return None

    # Render Microsoft Entra ID SSO sign-in gate and halt page execution
    st_mod.title("🔐 Pharmacy Compliance & GPhC Audit Dashboard")
    st_mod.warning("Authentication Required: Please sign in with your Microsoft Entra ID corporate account.")
    if "entra_oidc_nonce" not in st_mod.session_state:
        st_mod.session_state["entra_oidc_nonce"] = str(uuid.uuid4())
    auth_url = authenticator.build_msal_authorization_url(
        nonce=st_mod.session_state["entra_oidc_nonce"],
        redirect_uri=cfg.entra_redirect_uri,
    )
    if auth_url:
        st_mod.link_button("🔑 Sign in with Microsoft Entra ID (SSO)", auth_url)
    st_mod.stop()
    return None


def render_streamlit_dashboard() -> None:
    import streamlit as st

    st.set_page_config(
        page_title="Pharmacy Compliance & Audit Dashboard",
        page_icon="⚕️",
        layout="wide",
    )

    cfg = AppConfig()
    repo = ComplianceRepository(cfg.database_url)
    repo.seed_tasks_from_sql_file()

    # ID-021: Gate demo staff seeding strictly behind ENV=development
    if cfg.environment == "development" and not repo.list_users():
        repo.upsert_user(
            entra_oid="entra-pharm-anjum",
            slack_user_id="U_PHARM_ANJUM",
            full_name="Anjum (Superintendent / RP)",
            email="anjum@pharmacy.co.uk",
            staff_role=StaffRole.PHARM,
            gphc_reg_number="2054321",
        )
        repo.upsert_user(
            entra_oid="entra-disp-01",
            slack_user_id="U_DISP_01",
            full_name="Lead Dispenser",
            email="dispenser@pharmacy.co.uk",
            staff_role=StaffRole.DISPENSER,
        )

    active_user = _resolve_authenticated_entra_user(st, cfg, repo)
    if active_user is None:
        return

    st.title("⚕️ Pharmacy Operations & GPhC Compliance Dashboard")
    st.caption(
        "Immutable SHA-256 Audit Ledger • Entra ID RBAC Enforced • Zero-Query Inspection View"
    )

    with st.sidebar:
        st.header("🔐 Verified Entra ID Session")
        st.markdown(f"**Signed-in User:** {active_user.full_name}")
        st.markdown(f"**GPhC / Staff Role:** `{active_user.staff_role.value}`")
        st.markdown(f"**Entra Object ID:** `{active_user.entra_oid[:12]}...`")

        selected_date = st.date_input(
            "Operating Date",
            value=datetime.now(timezone.utc).date(),
        )
        if isinstance(selected_date, tuple):
            selected_date = selected_date[0]

        st.divider()
        st.markdown("**Quick Inspection Exports**")
        csv_data = export_inspection_csv(repo, selected_date)
        md_report = generate_daily_compliance_report_markdown(repo, selected_date)
        st.download_button(
            "📥 Download Inspection CSV",
            data=csv_data,
            file_name=f"pharmacy_compliance_{selected_date.isoformat()}.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.download_button(
            "📄 Download Signed Audit Report (.md)",
            data=md_report,
            file_name=f"pharmacy_audit_report_{selected_date.isoformat()}.md",
            mime="text/markdown",
            use_container_width=True,
        )

    summary = build_dashboard_summary(repo, selected_date)

    # Top Traffic-Light KPI Row
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric(
        "Daily Tasks Today",
        f"{summary.daily_completed} / {summary.daily_total}",
        delta=f"Morning {summary.morning_completed}/{summary.morning_total} • EOD {summary.eod_completed}/{summary.eod_total}",
    )
    col2.metric(
        "Weekly Tasks (Any Day)",
        f"{summary.weekly_completed} / {summary.weekly_total}",
        delta="Current ISO Week",
    )
    col3.metric(
        "Monthly Tasks (Any Day)",
        f"{summary.monthly_completed} / {summary.monthly_total}",
        delta="Current Month",
    )
    fridge_status_str = (
        f"{summary.fridge_readings.get('current_temp_c')}°C (Safe)"
        if summary.fridge_completed_today and summary.fridge_in_safe_range
        else ("Excursion Logged" if summary.fridge_completed_today else "Pending Today")
    )
    col4.metric("Fridge Cold-Chain (2–8°C)", fridge_status_str)
    col5.metric(
        "Audit Ledger Integrity",
        "VERIFIED ✅" if summary.ledger_verification.is_valid else "TAMPER ALERT 🚨",
        delta=f"{summary.ledger_verification.total_rows_checked} chained events",
    )

    st.divider()

    tab_daily, tab_weekly_monthly, tab_audit = st.tabs(
        [
            "🗓️ Today's Daily Tasks (Morning / Anytime / End of Day)",
            "📅 Weekly & Monthly Tasks (Complete Any Day)",
            "🔒 Immutable Audit Trail & Cryptographic Ledger",
        ]
    )

    instances = repo.ensure_instances_for_date(selected_date)
    user_can_act = can_complete_clinical_tasks(active_user.staff_role)

    with tab_daily:
        for window, title in [
            (DailyWindow.MORNING, "🌅 Early Morning Tasks (Start of Day)"),
            (DailyWindow.ANYTIME, "☀️ Anytime Daily Tasks (During the Day)"),
            (DailyWindow.END_OF_DAY, "🌙 End of Day Tasks (Closing & Lock-Up)"),
        ]:
            st.subheader(title)
            window_tasks = [
                i
                for i in instances
                if i.frequency == TaskFrequency.DAILY and i.daily_timing_window == window
            ]
            for inst in window_tasks:
                cols = st.columns([4, 2, 2, 2])
                status_icon = "✅" if inst.status == InstanceStatus.COMPLETED else (
                    "🚨" if inst.status == InstanceStatus.ESCALATED else "⬜"
                )
                cols[0].markdown(f"{status_icon} **{inst.task_name}**")
                cols[1].markdown(f"Role: `{inst.assigned_role.value}`")
                cols[2].markdown(
                    f"Status: **{inst.status.value}**"
                    + (f" ({inst.completed_by_name})" if inst.completed_by_name else "")
                )
                if (
                    inst.status != InstanceStatus.COMPLETED
                    and user_can_act
                    and is_role_authorized(active_user.staff_role, inst.assigned_role)
                ):
                    if inst.requires_structured_input:
                        with cols[3].popover("🌡️ Log Temps"):
                            min_t = st.number_input("Min (°C)", value=3.2, step=0.1, key=f"min_{inst.instance_id}")
                            max_t = st.number_input("Max (°C)", value=6.4, step=0.1, key=f"max_{inst.instance_id}")
                            cur_t = st.number_input("Current (°C)", value=4.5, step=0.1, key=f"cur_{inst.instance_id}")
                            note = st.text_input("Corrective Note (if <2°C or >8°C)", key=f"note_{inst.instance_id}")
                            if st.button("Save Readings", key=f"save_fridge_{inst.instance_id}"):
                                ok, msg, _ = repo.complete_task_instance(
                                    instance_id=inst.instance_id,
                                    actor_slack_id=active_user.slack_user_id,
                                    notes=note,
                                    fridge_readings={
                                        "min_temp_c": min_t,
                                        "max_temp_c": max_t,
                                        "current_temp_c": cur_t,
                                    },
                                )
                                if ok:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
                    else:
                        if cols[3].button("✓ Complete", key=f"btn_{inst.instance_id}"):
                            ok, msg, _ = repo.complete_task_instance(
                                instance_id=inst.instance_id,
                                actor_slack_id=active_user.slack_user_id,
                            )
                            if ok:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)

    with tab_weekly_monthly:
        col_w, col_m = st.columns(2)
        with col_w:
            st.subheader("📅 Weekly Tasks (Once on Any Day of the Week)")
            for inst in [i for i in instances if i.frequency == TaskFrequency.WEEKLY]:
                icon = "✅" if inst.status == InstanceStatus.COMPLETED else "⬜"
                c1, c2 = st.columns([3, 1])
                c1.markdown(
                    f"{icon} **{inst.task_name}** (`{inst.assigned_role.value}`)"
                    + (f" — _Done by {inst.completed_by_name}_" if inst.completed_by_name else "")
                )
                if (
                    inst.status != InstanceStatus.COMPLETED
                    and user_can_act
                    and is_role_authorized(active_user.staff_role, inst.assigned_role)
                ):
                    if c2.button("✓ Complete", key=f"w_{inst.instance_id}"):
                        ok, msg, _ = repo.complete_task_instance(
                            instance_id=inst.instance_id,
                            actor_slack_id=active_user.slack_user_id,
                        )
                        if ok:
                            st.rerun()
                        else:
                            st.error(msg)

        with col_m:
            st.subheader("📆 Monthly Tasks (Once on Any Day of the Month)")
            for inst in [i for i in instances if i.frequency == TaskFrequency.MONTHLY]:
                icon = "✅" if inst.status == InstanceStatus.COMPLETED else "⬜"
                c1, c2 = st.columns([3, 1])
                c1.markdown(
                    f"{icon} **{inst.task_name}** (`{inst.assigned_role.value}`)"
                    + (f" — _Done by {inst.completed_by_name}_" if inst.completed_by_name else "")
                )
                if (
                    inst.status != InstanceStatus.COMPLETED
                    and user_can_act
                    and is_role_authorized(active_user.staff_role, inst.assigned_role)
                ):
                    if c2.button("✓ Complete", key=f"m_{inst.instance_id}"):
                        ok, msg, _ = repo.complete_task_instance(
                            instance_id=inst.instance_id,
                            actor_slack_id=active_user.slack_user_id,
                        )
                        if ok:
                            st.rerun()
                        else:
                            st.error(msg)

    with tab_audit:
        st.subheader("🔒 Append-Only Cryptographic Audit Trail")
        if can_view_audit_and_rota_oversight(active_user.staff_role):
            events = [
                redact_audit_event_for_ui(e, active_user.staff_role)
                for e in repo.get_all_audit_events()
            ]
            st.dataframe(events, use_container_width=True)
        else:
            st.info(
                "Restricted View: Raw forensic audit trail is restricted to Responsible Pharmacist and Manager oversight roles."
            )


if __name__ == "__main__":
    render_streamlit_dashboard()
