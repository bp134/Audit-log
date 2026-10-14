# Pharmacy Workflow & Compliance Automation

A zero-additional-licensing-cost compliance, task scheduling, and immutable audit ledger system tailored for UK Community Pharmacy operations (GPhC / NHSBSA / Controlled Drugs / Cold-Chain governance).

---

## 1. Architecture Overview

1. **PostgreSQL Immutable Audit Ledger (`db/01_schema.sql`, `db/02_seed_tasks.sql`):**
   - Stores all **33 core pharmacy tasks**:
     - **14 Daily Tasks** split into **Early Morning** (4 tasks), **Anytime** (5 tasks), and **End of Day** (5 tasks).
     - **10 Weekly Tasks** (completed once on *any* day of the week).
     - **9 Monthly Tasks** (completed once on *any* day of the month).
   - Normalizes role permissions (`Dispenser / Pharm` and `Pharm / Dispenser` $\rightarrow$ `Either`; `Pharm` $\rightarrow$ strictly Pharmacist-only with mandatory GPhC registration number).
   - Protects `task_events_audit` with **PostgreSQL database triggers** blocking `UPDATE`, `DELETE`, and `TRUNCATE`, plus a **SHA-256 cryptographic hash chain** (`prev_hash` $\rightarrow$ `row_hash`) across every event.

2. **Slack Block Kit & Tranche Scheduler (`src/slack_bot/`):**
   - Runs over **Slack Socket Mode** (100% compatible with Slack Free Tier; no public webhook exposure required).
   - Posts interactive checklists at **Morning (09:00)**, **Mid-Day (13:00)**, and **End-of-Day (17:30)**.
   - Includes a dedicated **Fridge Temperature Modal** (`Min °C`, `Max °C`, `Current °C`) that validates the $2.0^\circ\text{C}\text{–}8.0^\circ\text{C}$ cold-chain range and mandates a corrective action note if an excursion occurs.
   - Automatically escalates overdue tasks and blocks unauthorized role clicks in real time.

3. **Entra ID Governance & Compliance Dashboard (`src/dashboard/`):**
   - Validates **Microsoft Entra ID** OIDC tokens (`tid` and `oid` claims) against `users_rbac`.
   - Provides a clean, zero-query **Streamlit Web Dashboard** (`src/dashboard/app.py`) with traffic-light KPIs, live checklists, Fridge temperature logs, cryptographic ledger verification, and **One-Click GPhC Inspection CSV / Report Export**.

4. **Encrypted Hetzner S3 Archival & "Break-Glass" Restore Verifier (`src/backup/`):**
   - Compresses and encrypts nightly database dumps + daily compliance reports client-side (`PBKDF2-HMAC-SHA256` + `HMAC-SHA256` Encrypt-then-MAC authentication tag) before uploading to **Hetzner S3 Object Storage**.
   - Immediately executes an automated **"Break-Glass" restore** into an isolated temporary database instance, verifying row counts and the full SHA-256 hash chain to detect silent corruption early.

---

## 2. Quick Start

### Apply PostgreSQL Schema & Task Seed (Azure PostgreSQL Flexible Server)
```bash
psql "$DATABASE_URL" -f db/01_schema.sql
psql "$DATABASE_URL" -f db/02_seed_tasks.sql
```

### Run the Full Stack with Docker Compose
```bash
cp .env.example .env
docker compose up --build -d
```

### Launch the Compliance Dashboard Locally
```bash
streamlit run src/dashboard/app.py
```

### Run the Critic Verification Test Suite (All 5 Phases)
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
