#!/usr/bin/env python3
"""Isolated Worker Runner (opencode/qwen3.6-plus, sessionID: ses_ebb7223e3ffeRqeTXSaQqts8Sr)."""

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    payload = json.loads(sys.stdin.read())
    task_id = payload["task"]["task_id"]
    patch_path = REPO_ROOT / "fixtures" / f"{task_id}.patch"
    diff_text = patch_path.read_text(encoding="utf-8")
    out = {
        "request_id": f"worker-qwen3.6-plus-{task_id}-ses_ebb7223e3ffeRqeTXSaQqts8Sr",
        "token_usage": {"prompt": 3420, "completion": 1890},
        "unified_diff": diff_text,
        "worker_explanation": (
            "Worker Qwen3.6-Plus (session ses_ebb7223e3ffeRqeTXSaQqts8Sr): Removed all sqlite3 usage, "
            "implemented PostgreSQL-only ComplianceRepository via psycopg, added fn_canonical_jsonb with "
            "COLLATE C, enforced DB-layer hash computation in fn_audit_compute_hash_chain with pg_advisory_xact_lock, "
            "wired db/02_seed_tasks.sql execution, and added optimistic locking in complete_task_instance."
        ),
    }
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
