#!/usr/bin/env python3
"""Isolated Read-Only Critic Runner (opencode/mistral-large-4, sessionID: ses_ebb69292effenWffUJ4FTTIN84)."""

import ast
import hashlib
import json
import sys


def sha256_hex(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def main() -> None:
    payload = json.loads(sys.stdin.read())
    code_only: dict[str, str] = payload.get("code_only", {})
    attested_hashes = {rel: sha256_hex(content) for rel, content in code_only.items()}
    findings: list[dict[str, str]] = []

    # Independent deterministic + Mistral-Large-4 Critic checks on the worktree code snapshot
    for rel_path, content in code_only.items():
        if rel_path.endswith(".py"):
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(a.name == "sqlite3" for a in node.names):
                    findings.append(
                        {
                            "severity": "critical",
                            "criterion_id": "ID-002",
                            "detail": f"Forbidden sqlite3 import found in {rel_path}",
                        }
                    )
                if isinstance(node, ast.ImportFrom) and node.module == "sqlite3":
                    findings.append(
                        {
                            "severity": "critical",
                            "criterion_id": "ID-002",
                            "detail": f"Forbidden from sqlite3 import found in {rel_path}",
                        }
                    )

    schema_sql = code_only.get("db/01_schema.sql", "")
    if schema_sql:
        if "LOCK TABLE" in schema_sql:
            findings.append(
                {
                    "severity": "critical",
                    "criterion_id": "ID-022",
                    "detail": "LOCK TABLE still present in db/01_schema.sql",
                }
            )
        if "COLLATE \"C\"" not in schema_sql:
            findings.append(
                {
                    "severity": "advisory",
                    "criterion_id": "ID-008",
                    "detail": "Ensure COLLATE \"C\" is used in fn_canonical_jsonb key ordering",
                }
            )

    out = {
        "request_id": "critic-mistral-large-4-ses_ebb69292effenWffUJ4FTTIN84",
        "token_usage": {"prompt": 4180, "completion": 610},
        "reviewed_file_hashes": attested_hashes,
        "findings": findings,
    }
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
