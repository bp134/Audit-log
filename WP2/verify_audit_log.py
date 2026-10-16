#!/usr/bin/env python3
"""
Standalone Offline Verifier for pipeline_audit_trail.jsonl and .audit_head_sha256.
Run independently in CI or by human before any sign-off:
    python verify_audit_log.py
"""

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent
AUDIT_LOG_PATH = REPO_ROOT / "pipeline_audit_trail.jsonl"
AUDIT_HEAD_SEAL_PATH = REPO_ROOT / ".audit_head_sha256"
GENESIS_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_hex(content: str | bytes) -> str:
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def verify_audit_trail(log_path: Path = AUDIT_LOG_PATH, seal_path: Path = AUDIT_HEAD_SEAL_PATH) -> tuple[bool, str, int]:
    if not log_path.exists():
        if seal_path.exists():
            return False, "FAIL: Audit log file is missing while .audit_head_sha256 exists (deletion detected).", 0
        return True, "OK: No audit log created yet (clean state).", 0

    prev_hash = GENESIS_HASH
    count = 0

    with log_path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            count += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                return False, f"FAIL: Invalid JSON at line {line_no}: {exc}", count

            recorded_entry_hash = record.get("entry_hash")
            if record.get("prev_hash") != prev_hash:
                return (
                    False,
                    f"FAIL: Chain link broken at line {line_no}: expected prev_hash={prev_hash}, got {record.get('prev_hash')}",
                    count,
                )

            body = {k: v for k, v in record.items() if k != "entry_hash"}
            computed = sha256_hex(prev_hash + canonical_json(body))
            if computed != recorded_entry_hash:
                return (
                    False,
                    f"FAIL: Entry hash mismatch at line {line_no}: computed={computed}, recorded={recorded_entry_hash}",
                    count,
                )
            prev_hash = recorded_entry_hash

    if seal_path.exists():
        sealed_head = seal_path.read_text(encoding="utf-8").strip()
        if sealed_head != prev_hash:
            return (
                False,
                f"FAIL: Truncation/seal mismatch: last log entry={prev_hash}, .audit_head_sha256={sealed_head}",
                count,
            )

    return True, f"OK: Verified {count} chained event(s). Head SHA-256 = {prev_hash}", count


if __name__ == "__main__":
    ok, message, _ = verify_audit_trail()
    print(message)
    sys.exit(0 if ok else 1)
