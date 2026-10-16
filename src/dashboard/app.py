"""
Streamlit Compliance & GPhC Inspection Dashboard (`src/dashboard/app.py`).
Designed for maximum ease of use with zero manual SQL queries required.
Run with: `streamlit run src/dashboard/app.py`
"""

from __future__ import annotations

from datetime import date, datetime, timezone
import sys
from pathlib import Path

# Ensure project root is on sys.path when launched via `streamlit run`
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import AppConfig
from src.dashboard.reporting import (
    build_dashboard_summary,
    export_inspection_csv,
    generate_daily_compliance_report_markdown,
)
from src.domain.models import DailyWindow, InstanceStatus, StaffRole, TaskFrequency
from src.repository.db_repo import ComplianceRepository


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

    st.title("⚕️ Pharmacy Operations & GPhC Compliance Dashboard")
    st.caption(
        "Immutable SHA-256 Audit Ledger • Entra ID RBAC Enforced • Zero-Query Inspection View"
    )

    with st.sidebar:
        st.header("🔐 Entra ID Session & Controls")
        users = repo.list_users()
        user_labels = {f"{u.full_name} [{u.staff_role.value}]": u for u in users}
        selected_label = st.selectbox("Signed-in Staff Profile (Entra SSO)", list(user_labels.keys()))
        active_user = user_labels[selected_label]

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
                if inst.status != InstanceStatus.COMPLETED:
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
                if inst.status != InstanceStatus.COMPLETED:
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
                if inst.status != InstanceStatus.COMPLETED:
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
        events = repo.get_all_audit_events()
        st.dataframe(events, use_container_width=True)


if __name__ == "__main__":
    render_streamlit_dashboard()
