-- =============================================================================
-- PHARMACY WORKFLOW & COMPLIANCE AUTOMATION
-- Phase 1: PostgreSQL Schema, RBAC, and Immutable Hash-Chained Audit Ledger
-- Target: Azure Database for PostgreSQL - Flexible Server (PostgreSQL 14+)
-- =============================================================================

BEGIN;

-- Required extension for SHA-256 cryptographic hashing inside PostgreSQL triggers
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- -----------------------------------------------------------------------------
-- 1. ENUMERATED TYPES
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typname = 'task_frequency' AND n.nspname = current_schema()) THEN
        CREATE TYPE task_frequency AS ENUM ('Daily', 'Weekly', 'Monthly');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typname = 'daily_window' AND n.nspname = current_schema()) THEN
        CREATE TYPE daily_window AS ENUM ('Morning', 'Anytime', 'End_Of_Day');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typname = 'staff_role' AND n.nspname = current_schema()) THEN
        CREATE TYPE staff_role AS ENUM ('Pharm', 'Dispenser', 'Manager');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typname = 'role_requirement' AND n.nspname = current_schema()) THEN
        -- Normalized from 'Pharm', 'Dispenser', 'Dispenser / Pharm', 'Pharm / Dispenser'
        CREATE TYPE role_requirement AS ENUM ('Pharm', 'Dispenser', 'Either');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typname = 'instance_status' AND n.nspname = current_schema()) THEN
        CREATE TYPE instance_status AS ENUM ('Pending', 'Completed', 'Escalated', 'Missed');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typname = 'audit_event_type' AND n.nspname = current_schema()) THEN
        CREATE TYPE audit_event_type AS ENUM (
            'INSTANCE_SCHEDULED',
            'REMINDER_DISPATCHED',
            'TASK_COMPLETED',
            'FRIDGE_TEMP_LOGGED',
            'FRIDGE_OUT_OF_RANGE_ALERT',
            'RBAC_ACCESS_DENIED',
            'TASK_ESCALATED',
            'BREAK_GLASS_VERIFIED'
        );
    END IF;
END$$;

-- -----------------------------------------------------------------------------
-- 2. USERS & RBAC MAPPING (Entra ID <-> Slack User ID <-> Pharmacy Role)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users_rbac (
    user_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entra_oid           VARCHAR(128) UNIQUE NOT NULL,  -- Microsoft Entra ID Object ID
    slack_user_id       VARCHAR(64) UNIQUE NOT NULL,   -- Slack Member ID (e.g. U012ABCDEF)
    full_name           VARCHAR(150) NOT NULL,
    email               VARCHAR(255) UNIQUE NOT NULL,
    staff_role          staff_role NOT NULL,
    gphc_reg_number     VARCHAR(32),                   -- Mandatory for Pharmacists
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_pharmacist_gphc CHECK (
        staff_role <> 'Pharm' OR (gphc_reg_number IS NOT NULL AND length(trim(gphc_reg_number)) >= 6)
    )
);

CREATE INDEX IF NOT EXISTS idx_users_rbac_slack_id ON users_rbac(slack_user_id) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_users_rbac_entra_oid ON users_rbac(entra_oid) WHERE is_active = TRUE;

-- -----------------------------------------------------------------------------
-- 3. TASKS MASTER CATALOG (The 33 Core Pharmacy Tasks)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tasks_master (
    task_id                     SERIAL PRIMARY KEY,
    task_name                   VARCHAR(200) UNIQUE NOT NULL,
    frequency                   task_frequency NOT NULL,
    daily_timing_window         daily_window,          -- Populated for Daily tasks; NULL for Weekly/Monthly
    assigned_role               role_requirement NOT NULL,
    original_role_label         VARCHAR(64) NOT NULL,  -- Preserves original SQL label for traceability
    requires_structured_input   BOOLEAN NOT NULL DEFAULT FALSE,
    input_schema                JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active                   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_daily_window_consistency CHECK (
        (frequency = 'Daily' AND daily_timing_window IS NOT NULL)
        OR (frequency IN ('Weekly', 'Monthly') AND daily_timing_window IS NULL)
    )
);

-- -----------------------------------------------------------------------------
-- 4. TASK INSTANCES (Active Cycle State per Day / Week / Month)
--    - Daily period_key format:   'YYYY-MM-DD' (e.g. '2026-10-13')
--    - Weekly period_key format:  'IYYY-W"IW"' (e.g. '2026-W42') -> Completed once on ANY day of the week
--    - Monthly period_key format: 'YYYY-MM'    (e.g. '2026-10')  -> Completed once on ANY day of the month
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task_instances (
    instance_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id                 INTEGER NOT NULL REFERENCES tasks_master(task_id),
    period_key              VARCHAR(32) NOT NULL,
    period_start_date       DATE NOT NULL,
    period_end_date         DATE NOT NULL,
    status                  instance_status NOT NULL DEFAULT 'Pending',
    completed_by_user_id    UUID REFERENCES users_rbac(user_id),
    completed_at            TIMESTAMPTZ,
    structured_data         JSONB NOT NULL DEFAULT '{}'::jsonb, -- e.g. Fridge Min/Max/Current °C
    notes                   TEXT,
    escalation_count        INTEGER NOT NULL DEFAULT 0,
    last_reminded_at        TIMESTAMPTZ,
    slack_channel_id        VARCHAR(64),
    slack_message_ts        VARCHAR(64),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_task_period UNIQUE (task_id, period_key),
    CONSTRAINT chk_completion_fields CHECK (
        (status = 'Completed' AND completed_by_user_id IS NOT NULL AND completed_at IS NOT NULL)
        OR (status <> 'Completed')
    )
);

CREATE INDEX IF NOT EXISTS idx_task_instances_period ON task_instances(period_key, status);
CREATE INDEX IF NOT EXISTS idx_task_instances_dates ON task_instances(period_start_date, period_end_date, status);

-- -----------------------------------------------------------------------------
-- 5. IMMUTABLE AUDIT LEDGER (Append-Only + SHA-256 Cryptographic Hash Chain)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task_events_audit (
    audit_seq               BIGSERIAL PRIMARY KEY,
    event_id                UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    event_type              audit_event_type NOT NULL,
    task_id                 INTEGER REFERENCES tasks_master(task_id),
    instance_id             UUID REFERENCES task_instances(instance_id),
    period_key              VARCHAR(32),
    actor_user_id           UUID REFERENCES users_rbac(user_id),
    actor_slack_id          VARCHAR(64),
    actor_entra_oid         VARCHAR(128),
    actor_role               VARCHAR(32),
    payload                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    prev_hash               CHAR(64) NOT NULL,
    row_hash                CHAR(64) UNIQUE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON task_events_audit(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_task_instance ON task_events_audit(task_id, instance_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON task_events_audit(event_type);

-- Helper Function: Canonical compact JSONB serialization (ID-008: sorted keys, no spaces after ':' or ',')
-- Matches Python `json.dumps(payload, sort_keys=True, separators=(',', ':'))` byte-for-byte.
CREATE OR REPLACE FUNCTION fn_canonical_jsonb(p_data JSONB)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_type TEXT;
    v_result TEXT;
BEGIN
    IF p_data IS NULL THEN
        RETURN '{}';
    END IF;
    v_type := jsonb_typeof(p_data);
    IF v_type = 'object' THEN
        SELECT '{' || COALESCE(string_agg(to_json(k)::text || ':' || fn_canonical_jsonb(v), ',' ORDER BY k COLLATE "C"), '') || '}'
          INTO v_result
          FROM jsonb_each(p_data) AS t(k, v);
        RETURN v_result;
    ELSIF v_type = 'array' THEN
        SELECT '[' || COALESCE(string_agg(fn_canonical_jsonb(v), ','), '') || ']'
          INTO v_result
          FROM jsonb_array_elements(p_data) AS t(v);
        RETURN v_result;
    ELSE
        RETURN p_data::text;
    END IF;
END;
$$;

-- Trigger Function 1: Compute deterministic SHA-256 hash chain on INSERT
CREATE OR REPLACE FUNCTION fn_audit_compute_hash_chain()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_last_hash CHAR(64);
    v_canonical_string TEXT;
    v_computed_hash CHAR(64);
BEGIN
    -- ID-022: Use transaction-scoped advisory lock so concurrent SELECTs
    -- and compliance reports are never blocked by audit inserts.
    PERFORM pg_advisory_xact_lock(20261015, 1);

    SELECT row_hash
      INTO v_last_hash
      FROM task_events_audit
     ORDER BY audit_seq DESC
     LIMIT 1;

    IF v_last_hash IS NULL THEN
        v_last_hash := repeat('0', 64); -- Genesis block prev_hash
    END IF;

    -- ID-010: Reject forged prev_hash if caller supplied one that does not match the chain head
    IF NEW.prev_hash IS NOT NULL AND btrim(NEW.prev_hash) <> '' AND NEW.prev_hash <> v_last_hash THEN
        RAISE EXCEPTION 'COMPLIANCE VIOLATION: Invalid prev_hash in task_events_audit INSERT.'
            USING ERRCODE = '23514';
    END IF;

    NEW.prev_hash := v_last_hash;

    -- Canonical pipe-delimited string over all immutable compliance fields (ID-008 parity)
    v_canonical_string := concat_ws(
        '|',
        COALESCE(NEW.event_id::text, ''),
        COALESCE(NEW.event_type::text, ''),
        COALESCE(NEW.task_id::text, ''),
        COALESCE(NEW.instance_id::text, ''),
        COALESCE(NEW.period_key, ''),
        COALESCE(NEW.actor_user_id::text, ''),
        COALESCE(NEW.actor_slack_id, ''),
        COALESCE(NEW.actor_entra_oid, ''),
        COALESCE(NEW.actor_role, ''),
        fn_canonical_jsonb(COALESCE(NEW.payload, '{}'::jsonb)),
        to_char(NEW.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        NEW.prev_hash
    );

    v_computed_hash := encode(public.digest(convert_to(v_canonical_string, 'UTF8'), 'sha256'), 'hex');

    -- ID-010: Reject forged row_hash if caller supplied one that does not match the DB-computed SHA-256
    IF NEW.row_hash IS NOT NULL AND btrim(NEW.row_hash) <> '' AND NEW.row_hash <> v_computed_hash THEN
        RAISE EXCEPTION 'COMPLIANCE VIOLATION: Forged or mismatched row_hash in task_events_audit INSERT.'
            USING ERRCODE = '23514';
    END IF;

    NEW.row_hash := v_computed_hash;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_compute_hash_chain ON task_events_audit;
CREATE TRIGGER trg_audit_compute_hash_chain
BEFORE INSERT ON task_events_audit
FOR EACH ROW
EXECUTE FUNCTION fn_audit_compute_hash_chain();

-- Trigger Function 2: Block UPDATE, DELETE, and TRUNCATE on task_events_audit
CREATE OR REPLACE FUNCTION fn_prevent_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'COMPLIANCE VIOLATION: task_events_audit is strictly append-only. Operation % is prohibited.', TG_OP
        USING ERRCODE = '42501';
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_audit_row_mutation ON task_events_audit;
CREATE TRIGGER trg_prevent_audit_row_mutation
BEFORE UPDATE OR DELETE ON task_events_audit
FOR EACH ROW
EXECUTE FUNCTION fn_prevent_audit_mutation();

DROP TRIGGER IF EXISTS trg_prevent_audit_truncate ON task_events_audit;
CREATE TRIGGER trg_prevent_audit_truncate
BEFORE TRUNCATE ON task_events_audit
FOR EACH STATEMENT
EXECUTE FUNCTION fn_prevent_audit_mutation();

-- -----------------------------------------------------------------------------
-- 6. BACKUP & "BREAK-GLASS" VERIFICATION LOG
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS backup_verification_logs (
    verification_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_date             DATE NOT NULL,
    s3_bucket               VARCHAR(128) NOT NULL,
    s3_object_key           VARCHAR(512) NOT NULL,
    archive_sha256          CHAR(64) NOT NULL,
    encryption_cipher       VARCHAR(64) NOT NULL,
    restored_task_count     INTEGER NOT NULL,
    restored_audit_count    BIGINT NOT NULL,
    hash_chain_valid        BOOLEAN NOT NULL,
    verification_status     VARCHAR(32) NOT NULL CHECK (verification_status IN ('PASSED', 'FAILED')),
    error_details           TEXT,
    verified_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 7. LEAST-PRIVILEGE APPLICATION DATABASE ROLE
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_compliance_writer') THEN
        CREATE ROLE app_compliance_writer NOLOGIN;
    END IF;
END$$;

GRANT USAGE ON SCHEMA public TO app_compliance_writer;
GRANT SELECT, INSERT, UPDATE ON users_rbac, tasks_master, task_instances TO app_compliance_writer;
GRANT SELECT, INSERT ON task_events_audit, backup_verification_logs TO app_compliance_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_compliance_writer;
-- Explicitly ensure NO UPDATE, DELETE, or TRUNCATE privileges on task_events_audit
REVOKE UPDATE, DELETE, TRUNCATE ON task_events_audit FROM app_compliance_writer;

COMMIT;
