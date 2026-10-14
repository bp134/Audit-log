-- =============================================================================
-- PHARMACY WORKFLOW & COMPLIANCE AUTOMATION
-- Phase 1: Normalized Task Seed (All 33 Tasks from User Specification)
--
-- Role Normalization Rule (agreed with user):
--   - 'Dispenser / Pharm' and 'Pharm / Dispenser' -> 'Either'
--   - 'Pharm'                                     -> 'Pharm' (Pharmacist only)
--   - 'Dispenser'                                 -> 'Dispenser'
--
-- Daily Timing Window Rule (agreed with user):
--   - 'Morning'    : Must be completed early morning at start of day
--   - 'Anytime'    : Can be completed at any point during the day
--   - 'End_Of_Day' : Must be completed at end of day / closing
--   - NULL         : Weekly and Monthly tasks (completed on any one day in the week/month)
-- =============================================================================

BEGIN;

INSERT INTO tasks_master (
    task_name,
    frequency,
    daily_timing_window,
    assigned_role,
    original_role_label,
    requires_structured_input,
    input_schema
) VALUES
    -- =========================================================================
    -- DAILY TASKS (14 Tasks)
    -- =========================================================================

    -- Early Morning Window (4 Tasks)
    (
        'Fridge Check (Min/Max/Current)',
        'Daily',
        'Morning',
        'Either',
        'Dispenser / Pharm',
        TRUE,
        '{
            "type": "fridge_temperature",
            "fields": ["min_temp_c", "max_temp_c", "current_temp_c"],
            "safe_min_c": 2.0,
            "safe_max_c": 8.0,
            "require_action_note_if_out_of_range": true
        }'::jsonb
    ),
    (
        'Handover & Diary Review',
        'Daily',
        'Morning',
        'Either',
        'Pharm / Dispenser',
        FALSE,
        '{}'::jsonb
    ),
    (
        'EPS & NHSmail Download',
        'Daily',
        'Morning',
        'Either',
        'Dispenser / Pharm',
        FALSE,
        '{}'::jsonb
    ),
    (
        'Till Prep & Float',
        'Daily',
        'Morning',
        'Dispenser',
        'Dispenser',
        FALSE,
        '{}'::jsonb
    ),

    -- Anytime During the Day Window (5 Tasks)
    (
        'Prescription Processing',
        'Daily',
        'Anytime',
        'Dispenser',
        'Dispenser',
        FALSE,
        '{}'::jsonb
    ),
    (
        'MDS/Dosette Boxes Prep & Check',
        'Daily',
        'Anytime',
        'Either',
        'Dispenser / Pharm',
        FALSE,
        '{}'::jsonb
    ),
    (
        'Owings Processing',
        'Daily',
        'Anytime',
        'Dispenser',
        'Dispenser',
        FALSE,
        '{}'::jsonb
    ),
    (
        'Deliveries & Fridge Lines',
        'Daily',
        'Anytime',
        'Dispenser',
        'Dispenser',
        FALSE,
        '{}'::jsonb
    ),
    (
        'Clinical Services Prep',
        'Daily',
        'Anytime',
        'Pharm',
        'Pharm',
        FALSE,
        '{}'::jsonb
    ),

    -- End of Day Window (5 Tasks)
    (
        'CD Register Reconcile',
        'Daily',
        'End_Of_Day',
        'Pharm',
        'Pharm',
        FALSE,
        '{}'::jsonb
    ),
    (
        'EPS Claims (End of Day)',
        'Daily',
        'End_Of_Day',
        'Either',
        'Dispenser / Pharm',
        FALSE,
        '{}'::jsonb
    ),
    (
        'Information Governance Secure',
        'Daily',
        'End_Of_Day',
        'Dispenser',
        'Dispenser',
        FALSE,
        '{}'::jsonb
    ),
    (
        'Housekeeping (Benches/Bins/Floor)',
        'Daily',
        'End_Of_Day',
        'Dispenser',
        'Dispenser',
        FALSE,
        '{}'::jsonb
    ),
    (
        'Security & Lock Up',
        'Daily',
        'End_Of_Day',
        'Pharm',
        'Pharm',
        FALSE,
        '{}'::jsonb
    ),

    -- =========================================================================
    -- WEEKLY TASKS (10 Tasks - Completed on any one day of the week)
    -- =========================================================================
    ('Full CD Balance Check',           'Weekly', NULL, 'Pharm',     'Pharm',             FALSE, '{}'::jsonb),
    ('Owings Audit & Chase',            'Weekly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('Uncollected Scripts (14+ Days)',  'Weekly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('Consumables Order',               'Weekly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('Filing (Invoices & Logs)',        'Weekly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('Rota Check',                      'Weekly', NULL, 'Pharm',     'Pharm',             FALSE, '{}'::jsonb),
    ('Collection Box Audit',            'Weekly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('Consultation Room Deep Clean',    'Weekly', NULL, 'Either',    'Dispenser / Pharm', FALSE, '{}'::jsonb),
    ('Hardware Antibacterial Clean',    'Weekly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('Retail Area Face Up & Mop',       'Weekly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),

    -- =========================================================================
    -- MONTHLY TASKS (9 Tasks - Completed on any one day in the month)
    -- =========================================================================
    ('Date Checking Matrix',            'Monthly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('CD Management (Out of Date)',     'Monthly', NULL, 'Pharm',     'Pharm',             FALSE, '{}'::jsonb),
    ('Fridge Audit & Defrost',          'Monthly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('End of Month (NHSBSA / FP34C)',   'Monthly', NULL, 'Either',    'Dispenser / Pharm', FALSE, '{}'::jsonb),
    ('Service Claims (MYS/Local)',      'Monthly', NULL, 'Pharm',     'Pharm',             FALSE, '{}'::jsonb),
    ('SOP & Training Review',           'Monthly', NULL, 'Pharm',     'Pharm',             FALSE, '{}'::jsonb),
    ('Health & Safety (Fire/First Aid)','Monthly', NULL, 'Either',    'Pharm / Dispenser', FALSE, '{}'::jsonb),
    ('Staff Areas Deep Clean',          'Monthly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb),
    ('Ventilation & Hardware Dusting',  'Monthly', NULL, 'Dispenser', 'Dispenser',         FALSE, '{}'::jsonb)
ON CONFLICT (task_name) DO UPDATE
SET
    frequency                 = EXCLUDED.frequency,
    daily_timing_window       = EXCLUDED.daily_timing_window,
    assigned_role             = EXCLUDED.assigned_role,
    original_role_label       = EXCLUDED.original_role_label,
    requires_structured_input = EXCLUDED.requires_structured_input,
    input_schema              = EXCLUDED.input_schema;

COMMIT;
