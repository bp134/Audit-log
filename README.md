# Pharmacy Workflow & Compliance Automation

A zero-additional-licensing-cost compliance, task scheduling, and immutable audit ledger system tailored for UK Community Pharmacy operations (GPhC / NHSBSA / Controlled Drugs / Cold-Chain governance).

---

## 1. Architecture Overview (PostgreSQL-Exclusive Runtime)

1. **PostgreSQL Immutable Audit Ledger (`db/01_schema.sql`, `db/02_seed_tasks.sql`, `src/repository/db_repo.py`):**
   - Runs **exclusively on PostgreSQL** (`psycopg` + `DATABASE_URL`; zero SQLite dependencies anywhere in the codebase).
   - Seeds all **33 core pharmacy tasks** from a single canonical SQL source (`db/02_seed_tasks.sql`):
     - **14 Daily Tasks** split into **Early Morning** (4 tasks), **Anytime** (5 tasks), and **End of Day** (5 tasks).
     - **10 Weekly Tasks** (completed once on *any* day of the week).
     - **9 Monthly Tasks** (completed once on *any* day of the month).
   - Enforces **GPhC clinical role permissions** (`Pharm`, `PT`, `Dispenser`, `MCA`, plus read-only `Manager` oversight with zero clinical task completion authority).
   - Protects `task_events_audit` with **PostgreSQL database triggers** (`fn_audit_compute_hash_chain`, `fn_canonical_jsonb` with `COLLATE "C"`, `pg_advisory_xact_lock`, and `fn_prevent_audit_mutation`) blocking `UPDATE`, `DELETE`, `TRUNCATE`, and forged hashes.

2. **Slack Bolt Socket Mode, Request Signature Verification & APScheduler (`src/slack_bot/`):**
   - Wires `slack_bolt.App` with **HMAC-SHA256 signing-secret verification** (`v0=<hex>` + 300s replay protection) and `SocketModeHandler`.
   - Uses `APScheduler` (`BackgroundScheduler`) with `Europe/London` timezone-aware `CronTrigger` jobs for **Morning (09:00)**, **Mid-Day (13:00)**, **End-of-Day (17:30)**, **Closing Audit (18:15, scoped strictly to `End_Of_Day` tasks)**, and **Nightly Period-Close `Missed` transitions (00:05)**.
   - Exposes `/health` and `/ready` HTTP probes on `127.0.0.1:8080` with graceful `SIGTERM`/`SIGINT` shutdown.

3. **Microsoft Entra ID Cryptographic OIDC Auth & Hardened Dashboard (`src/dashboard/`):**
   - Cryptographically verifies **Microsoft Entra ID** `RS256` JWT signatures against tenant JWKS public keys (`exp`, `iss`, `aud`, `nonce`, `tid`, `oid`) via `PyJWT` and `msal`.
   - Removes staff profile impersonation pickers, restricts the forensic audit tab to `Pharm`/`Manager` roles with PII minimization and identifier redaction, and binds host port publishing strictly to `127.0.0.1:8501:8501`.

4. **AES-256-GCM Encrypted Hetzner S3 Archival, Databasus `PGRSUS01` Verification & Break-Glass Restore (`src/backup/`):**
   - Compresses and encrypts nightly PostgreSQL snapshots + `pg_dump --format=custom` dumps client-side using standard AEAD **`AES-256-GCM-PBKDF2-SHA256-v2`** with key versioning before uploading `.vault` and `.metadata` sidecars to **Hetzner S3 Object Storage** (`boto3`).
   - Validates **Databasus `PGRSUS01`** encrypted PostgreSQL backup envelopes (`8B header + 32B salt + 12B IV + AES-GCM payload`).
   - Enforces **non-bypassable pre-restore and post-restore SHA-256 hash-chain gates** when restoring into an isolated PostgreSQL verification schema, scheduled nightly at `22:15 Europe/London` with an idempotency guard (`has_backup_verified_for_date`).

---

## 2. Implementation & Verification Status Matrix (All 28 Audit Findings)

| Audit ID | Severity | Remediation Summary | Module(s) | Verification Test Suite | Work Package | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ID-001** | Critical | Removed staff impersonation `st.selectbox`; enforced verified Entra ID OIDC session | `src/dashboard/app.py` | `tests/test_wp3_entra_auth_and_rbac_hardening.py` | WP-3 | **VERIFIED** |
| **ID-002** | Critical | PostgreSQL-only `ComplianceRepository` via `psycopg` and `DATABASE_URL` | `src/repository/db_repo.py` | `tests/test_wp2_hash_chain_and_db_integrity.py` | WP-2 | **VERIFIED** |
| **ID-003** | Critical | Wired Slack Bolt Socket Mode, APScheduler cron jobs, and `boto3` Hetzner S3 upload/download | `src/slack_bot/service.py`, `src/backup/archive_and_verify.py` | `tests/test_wp4_slack_scheduler_and_missed_transitions.py`, `tests/test_wp5_aes_gcm_s3_and_databasus_break_glass.py` | WP-4 / WP-5 | **VERIFIED** |
| **ID-004** | High | Cryptographic RS256 JWT validation against Microsoft JWKS (`exp`, `iss`, `aud`, `nonce`) | `src/dashboard/auth.py` | `tests/test_wp3_entra_auth_and_rbac_hardening.py` | WP-3 | **VERIFIED** |
| **ID-005** | High | Fail-fast startup validation rejecting missing or placeholder secrets in production | `src/config.py` | `tests/test_wp1_secrets_and_hygiene.py` | WP-1 | **VERIFIED** |
| **ID-006** | High | Added `.gitignore` excluding `.env`, `*.db`, `s3_vault/`, `worktrees/`, `evidence/`, `__pycache__/` | `.gitignore` | `tests/test_wp1_secrets_and_hygiene.py` | WP-1 | **VERIFIED** |
| **ID-007** | High | Restricted dashboard host port binding to `127.0.0.1:8501:8501` | `docker-compose.yml` | `tests/test_wp3_entra_auth_and_rbac_hardening.py` | WP-3 | **VERIFIED** |
| **ID-008** | High | Unified canonical JSONB (`fn_canonical_jsonb` with `COLLATE "C"`) and UTC timestamp hashing | `db/01_schema.sql`, `src/domain/ledger.py` | `tests/test_wp2_hash_chain_and_db_integrity.py` | WP-2 | **VERIFIED** |
| **ID-009** | High | Optimistic locking (`WHERE instance_id = %s AND status <> 'Completed'`) on task completion | `src/repository/db_repo.py` | `tests/test_wp2_hash_chain_and_db_integrity.py` | WP-2 | **VERIFIED** |
| **ID-010** | High | Database-layer `BEFORE INSERT` hash computation & forged-hash rejection in PostgreSQL | `db/01_schema.sql`, `src/repository/db_repo.py` | `tests/test_wp2_hash_chain_and_db_integrity.py` | WP-2 | **VERIFIED** |
| **ID-011** | High | GPhC role hierarchy (`Pharm`, `PT`, `Dispenser`, `MCA`) + read-only `Manager` policy | `src/domain/models.py`, `db/01_schema.sql` | `tests/test_wp3_entra_auth_and_rbac_hardening.py` | WP-3 | **VERIFIED** |
| **ID-012** | High | Removed `gphc_reg_number` PII from raw audit JSON payloads and redacted UI views | `src/repository/db_repo.py`, `src/dashboard/app.py` | `tests/test_wp3_entra_auth_and_rbac_hardening.py` | WP-3 | **VERIFIED** |
| **ID-013** | Medium | Standard `AES-256-GCM-PBKDF2-SHA256-v2` AEAD encryption + Databasus `PGRSUS01` verifier | `src/backup/archive_and_verify.py` | `tests/test_wp5_aes_gcm_s3_and_databasus_break_glass.py` | WP-5 | **VERIFIED** |
| **ID-014** | Medium | Controlled nightly APScheduler job (`22:15`) + `has_backup_verified_for_date` idempotency guard | `src/backup/service.py` | `tests/test_wp5_aes_gcm_s3_and_databasus_break_glass.py` | WP-5 | **VERIFIED** |
| **ID-015** | Medium | HTTP `/health` & `/ready` probes, `SIGTERM`/`SIGINT` graceful shutdown, and Docker `healthcheck` | `src/slack_bot/service.py`, `src/backup/service.py`, `docker-compose.yml` | `tests/test_wp6_health_cicd_and_docs.py` | WP-6 | **VERIFIED** |
| **ID-016** | Medium | Retired SQLite (`check_same_thread=False`) completely in favor of PostgreSQL `psycopg` | `src/repository/db_repo.py` | `tests/test_wp2_hash_chain_and_db_integrity.py` | WP-2 | **VERIFIED** |
| **ID-017** | Medium | Single canonical SQL seed source (`db/02_seed_tasks.sql`) executed at runtime | `src/repository/db_repo.py`, `db/02_seed_tasks.sql` | `tests/test_wp2_hash_chain_and_db_integrity.py` | WP-2 | **VERIFIED** |
| **ID-018** | Medium | Scoped `CLOSING_AUDIT` escalation strictly to `End_Of_Day` window tasks | `src/slack_bot/scheduler.py` | `tests/test_wp4_slack_scheduler_and_missed_transitions.py` | WP-4 | **VERIFIED** |
| **ID-019** | Medium | Automatic transition of uncompleted expired-period tasks to `Missed` (`TASK_MISSED`) | `src/repository/db_repo.py`, `src/slack_bot/scheduler.py` | `tests/test_wp4_slack_scheduler_and_missed_transitions.py` | WP-4 | **VERIFIED** |
| **ID-020** | Medium | Strictly pinned all dependencies with `==` in `requirements.txt` and verified via `pip-audit` | `requirements.txt` | `tests/test_wp1_secrets_and_hygiene.py` | WP-1 | **VERIFIED** |
| **ID-021** | Medium | Gated demo staff seeding strictly behind `ENV=development` | `src/dashboard/app.py` | `tests/test_wp1_secrets_and_hygiene.py` | WP-1 | **VERIFIED** |
| **ID-022** | Medium | Replaced `LOCK TABLE IN EXCLUSIVE MODE` with `pg_advisory_xact_lock(20261015, 1)` | `db/01_schema.sql` | `tests/test_wp2_hash_chain_and_db_integrity.py` | WP-2 | **VERIFIED** |
| **ID-023** | Low | Mandatory non-bypassable pre- and post-restore SHA-256 chain gates in Break-Glass restore | `src/backup/archive_and_verify.py` | `tests/test_wp5_aes_gcm_s3_and_databasus_break_glass.py` | WP-5 | **VERIFIED** |
| **ID-024** | Low | Enforced Slack `v0` HMAC-SHA256 signing-secret and 300s replay verification at boundary | `src/slack_bot/handlers.py`, `src/slack_bot/service.py` | `tests/test_wp4_slack_scheduler_and_missed_transitions.py` | WP-4 | **VERIFIED** |
| **ID-025** | Low | Wired native PostgreSQL `pg_dump --format=custom` snapshot into encrypted backup flow | `src/backup/archive_and_verify.py`, `src/backup/service.py` | `tests/test_wp5_aes_gcm_s3_and_databasus_break_glass.py` | WP-5 | **VERIFIED** |
| **ID-026** | Low | Updated `README.md` with accurate architecture and 28-finding verification matrix | `README.md` | `tests/test_wp6_health_cicd_and_docs.py` | WP-6 | **VERIFIED** |
| **ID-027** | Low | Added GitHub Actions CI/CD workflow running PostgreSQL 18, `pytest`, `ruff`, `bandit`, `pip-audit`, `gitleaks` | `.github/workflows/ci.yml` | `tests/test_wp6_health_cicd_and_docs.py` | WP-6 | **VERIFIED** |
| **ID-028** | Low | Restricted dashboard audit tab to `Pharm`/`Manager` and redacted sensitive identifiers | `src/dashboard/app.py`, `src/domain/models.py` | `tests/test_wp3_entra_auth_and_rbac_hardening.py` | WP-3 | **VERIFIED** |

---

## 3. Quick Start

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

### Run the PostgreSQL Verification Test Suite
```bash
python -B -m pytest -q
```
