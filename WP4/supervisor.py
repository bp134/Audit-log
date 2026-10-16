#!/usr/bin/env python3
"""
Hardened Multi-Agent Supervisor Pipeline (v3)
Fixes:
- Fixed `expected_prefix` syntax error in final_verification_gate()
- Added `final_task_accounting()` verifying every planned task & audit ID is completed or explicitly waived
- Added true `git write-tree` and `porcelain_sha256` working-tree binding
- Added `git add -A -- <touched_files>` so file deletions stage cleanly on promote
- Added `TRIAL_STOP_AT_EVIDENCE=1` mode so Phase-0 trials stop at HITL after generating evidence packets
  without touching or committing to the main branch.
- Added atomic write via temp file rename for `.audit_head_sha256`.
"""

from dataclasses import dataclass
import datetime
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from verify_audit_log import (
    AUDIT_HEAD_SEAL_PATH,
    AUDIT_LOG_PATH,
    GENESIS_HASH,
    canonical_json,
    sha256_hex,
    verify_audit_trail,
)

REPO_ROOT = Path(__file__).resolve().parent
PLAN_PATH = REPO_ROOT / "remediation_plan.json"
GATES_CONFIG_PATH = REPO_ROOT / "gates.json"
WORKTREES_DIR = REPO_ROOT / "worktrees"
EVIDENCE_DIR = REPO_ROOT / "evidence"
NARRATIVE_LOG_PATH = REPO_ROOT / "narrative_log.jsonl"

MAX_RETRIES = 3

ROLE_MODELS = {
    "orchestrator": "opencode/gemini-4-argon",
    "worker": "opencode/qwen3.6-plus",
    "critic": "opencode/mistral-large-4",
}

ROLE_RUNNERS = {
    "orchestrator": [sys.executable, "runners/orchestrator_runner.py"],
    "worker": [sys.executable, "runners/worker_runner.py"],
    "critic": [sys.executable, "runners/critic_runner.py"],
}


def matches_glob(rel_posix_path: str, pattern: str) -> bool:
    norm_path = PurePosixPath(rel_posix_path).as_posix()
    norm_pat = PurePosixPath(pattern).as_posix()

    regex_parts = ["^"]
    i = 0
    n = len(norm_pat)
    while i < n:
        if norm_pat[i : i + 3] == "**/":
            regex_parts.append("(?:.+/)?")
            i += 3
        elif norm_pat[i : i + 2] == "**":
            regex_parts.append(".*")
            i += 2
        elif norm_pat[i] == "*":
            regex_parts.append("[^/]*")
            i += 1
        elif norm_pat[i] == "?":
            regex_parts.append("[^/]")
            i += 1
        else:
            regex_parts.append(re.escape(norm_pat[i]))
            i += 1
    regex_parts.append("$")
    return bool(re.match("".join(regex_parts), norm_path))


def append_audit_event(
    event_type: str,
    role: str,
    model: str,
    payload: dict[str, Any],
    plan_hash: str,
    channel: str = "audit",
) -> str:
    if channel == "audit":
        ok, msg, _ = verify_audit_trail(AUDIT_LOG_PATH, AUDIT_HEAD_SEAL_PATH)
        if not ok:
            raise RuntimeError(msg)
        prev_hash = (
            AUDIT_HEAD_SEAL_PATH.read_text(encoding="utf-8").strip()
            if AUDIT_HEAD_SEAL_PATH.exists() and AUDIT_LOG_PATH.exists()
            else GENESIS_HASH
        )
        target_path = AUDIT_LOG_PATH
    else:
        target_path = NARRATIVE_LOG_PATH
        prev_hash = GENESIS_HASH
        if target_path.exists():
            lines = [ln.strip() for ln in target_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                prev_hash = json.loads(lines[-1])["entry_hash"]

    body = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "plan_hash": plan_hash,
        "event_type": event_type,
        "role": role,
        "model": model,
        "prev_hash": prev_hash,
        "payload": payload,
    }
    entry_hash = sha256_hex(prev_hash + canonical_json(body))
    record = {**body, "entry_hash": entry_hash}

    with target_path.open("a", encoding="utf-8") as f:
        f.write(canonical_json(record) + "\n")
        f.flush()
        os.fsync(f.fileno())

    if channel == "audit":
        tmp_seal = AUDIT_HEAD_SEAL_PATH.with_suffix(".tmp")
        tmp_seal.write_text(entry_hash + "\n", encoding="utf-8")
        tmp_seal.replace(AUDIT_HEAD_SEAL_PATH)

    return entry_hash


def invoke_isolated_role(
    role: str,
    stdin_payload: dict[str, Any],
    plan_hash: str,
    read_only_worktree: Path | None = None,
) -> dict[str, Any]:
    """
    NOTE ON ISOLATION: Subprocess runs in a temporary directory with stripped env vars.
    True filesystem containment requires running each role inside a Docker container
    with read-only mounts. Until container runners are enabled, subprocesses are
    process-separated only.
    """
    model = ROLE_MODELS[role]
    input_bytes = canonical_json(stdin_payload).encode("utf-8")
    input_checksum = sha256_hex(input_bytes)

    runner_script = REPO_ROOT / ROLE_RUNNERS[role][1]
    if not runner_script.exists():
        if os.environ.get("PLACEHOLDER_MODE") != "1":
            raise RuntimeError(f"Runner {runner_script} missing and PLACEHOLDER_MODE!=1.")
        raw_response_bytes = _placeholder_role_response(role, stdin_payload)
    else:
        with tempfile.TemporaryDirectory(prefix=f"sandbox_{role}_") as sandbox_cwd:
            env = {
                "PATH": os.environ.get("PATH", ""),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "ROLE": role,
                "MODEL": model,
                "CAPABILITIES": "patch_only" if role == "worker" else "json_only",
            }
            if read_only_worktree:
                env["READ_ONLY_WORKTREE"] = str(read_only_worktree)

            res = subprocess.run(
                [sys.executable, str(runner_script)],
                input=input_bytes,
                capture_output=True,
                env=env,
                cwd=sandbox_cwd,
                check=False,
                timeout=180,
            )
            if res.returncode != 0:
                raise RuntimeError(f"Role '{role}' failed: {res.stderr.decode('utf-8', errors='replace')}")
            raw_response_bytes = res.stdout

    response_checksum = sha256_hex(raw_response_bytes)
    parsed = json.loads(raw_response_bytes.decode("utf-8"))

    if role == "worker" and "worker_explanation" in parsed:
        explanation = parsed.pop("worker_explanation")
        append_audit_event(
            event_type="worker_narrative",
            role=role,
            model=model,
            payload={"task_id": stdin_payload.get("task", {}).get("task_id"), "explanation": explanation},
            plan_hash=plan_hash,
            channel="narrative",
        )

    append_audit_event(
        event_type="role_invocation",
        role=role,
        model=model,
        payload={
            "request_id": parsed.get("request_id", "placeholder-req"),
            "token_usage": parsed.get("token_usage", {"prompt": 0, "completion": 0}),
            "input_sha256": input_checksum,
            "raw_response_sha256": response_checksum,
            "sanitized_output": parsed,
        },
        plan_hash=plan_hash,
        channel="audit",
    )
    return parsed


def _placeholder_role_response(role: str, stdin_payload: dict[str, Any]) -> bytes:
    if role == "orchestrator":
        out = {
            "request_id": "sim-orch-001",
            "token_usage": {"prompt": 410, "completion": 190},
            "tasks": stdin_payload["plan"]["work_packages"],
        }
    elif role == "worker":
        task_id = stdin_payload["task"]["task_id"]
        fixture_env = os.environ.get("FIXTURE_DIFF_PATH")
        fixture_path = Path(fixture_env) if fixture_env else (REPO_ROOT / "fixtures" / f"{task_id}.patch")
        diff_content = fixture_path.read_text(encoding="utf-8") if fixture_path.exists() else ""
        out = {
            "request_id": f"sim-work-{task_id}",
            "token_usage": {"prompt": 820, "completion": 350},
            "unified_diff": diff_content,
            "worker_explanation": "Simulated worker narrative isolated to narrative_log.jsonl.",
        }
    else:
        code_only = stdin_payload.get("code_only", {})
        attested_hashes = {rel: sha256_hex(content) for rel, content in code_only.items()}
        out = {
            "request_id": "sim-crit-001",
            "token_usage": {"prompt": 600, "completion": 120},
            "reviewed_file_hashes": attested_hashes,
            "findings": [],
        }
    return canonical_json(out).encode("utf-8")


def load_and_hash_plan() -> tuple[dict[str, Any], str]:
    if not PLAN_PATH.exists():
        raise FileNotFoundError(f"Missing {PLAN_PATH}.")
    raw = PLAN_PATH.read_bytes()
    return json.loads(raw.decode("utf-8")), sha256_hex(raw)


def validate_orchestrator_output(
    orch_output: dict[str, Any], plan: dict[str, Any], plan_hash: str
) -> list[dict[str, Any]]:
    if not isinstance(orch_output, dict) or "tasks" not in orch_output:
        raise ValueError("Orchestrator output must be a JSON object with a 'tasks' list.")

    tasks = orch_output["tasks"]
    plan_by_id = {wp["task_id"]: wp for wp in plan["work_packages"]}
    expected_audit_ids = set(plan["all_audit_ids"])
    seen_task_ids: set[str] = set()
    covered_audit_ids: set[str] = set()

    validated_tasks: list[dict[str, Any]] = []
    for t in tasks:
        tid = t.get("task_id")
        if tid in seen_task_ids:
            raise ValueError(f"Duplicate task_id in orchestrator output: {tid}")
        if tid not in plan_by_id:
            raise ValueError(f"Unknown task_id in orchestrator output: {tid}")
        seen_task_ids.add(tid)

        canonical_wp = plan_by_id[tid]
        if set(t.get("audit_ids", [])) != set(canonical_wp["audit_ids"]):
            raise ValueError(f"Orchestrator altered audit_ids for {tid}")
        if set(t.get("allowed_paths", [])) != set(canonical_wp["allowed_paths"]):
            raise ValueError(f"Orchestrator altered allowed_paths for {tid}")
        if set(t.get("required_tests", [])) != set(canonical_wp["required_tests"]):
            raise ValueError(f"Orchestrator altered required_tests for {tid}")

        covered_audit_ids |= set(canonical_wp["audit_ids"])
        validated_tasks.append(canonical_wp)

    waived_ids = set(plan.get("waived_audit_ids", {}).keys())
    missing = expected_audit_ids - (covered_audit_ids | waived_ids)
    if missing:
        raise ValueError(f"Uncovered audit IDs: {sorted(missing)}")

    append_audit_event(
        event_type="orchestrator_plan_validated",
        role="supervisor",
        model="deterministic",
        payload={"task_ids": [t["task_id"] for t in validated_tasks], "covered_audit_ids": sorted(covered_audit_ids)},
        plan_hash=plan_hash,
    )
    return validated_tasks


def get_working_tree_state(cwd: Path = REPO_ROOT) -> tuple[str, str, str, str]:
    """
    Returns (head_commit_sha, index_write_tree_sha, porcelain_status, porcelain_sha256).
    Uses `git write-tree` and hashes `git status --porcelain` so working tree state is
    cryptographically bound.
    """
    head_sha = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
    ).stdout.strip()
    write_tree_sha = subprocess.run(
        ["git", "write-tree"], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
    ).stdout.strip()
    porcelain = subprocess.run(
        ["git", "status", "--porcelain"], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
    ).stdout.strip()
    porcelain_hash = sha256_hex(porcelain)
    return head_sha, write_tree_sha, porcelain, porcelain_hash


def apply_patch_in_worktree(
    task_id: str, attempt: int, baseline_ref: str, unified_diff: str
) -> tuple[bool, Path, str]:
    wt_path = WORKTREES_DIR / task_id / f"attempt_{attempt}"
    if wt_path.exists():
        subprocess.run(["git", "worktree", "remove", "--force", str(wt_path)], cwd=REPO_ROOT, check=False)
        shutil.rmtree(wt_path, ignore_errors=True)
    wt_path.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        ["git", "worktree", "add", "--detach", str(wt_path), baseline_ref],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )

    if not unified_diff.strip():
        return False, wt_path, "Worker returned an empty unified diff."

    patch_file = wt_path / ".worker.patch"
    patch_file.write_text(unified_diff, encoding="utf-8")

    chk = subprocess.run(
        ["git", "apply", "--check", str(patch_file)], cwd=wt_path, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
    )
    if chk.returncode != 0:
        patch_file.unlink(missing_ok=True)
        return False, wt_path, f"git apply --check failed:\n{chk.stderr}"

    app = subprocess.run(
        ["git", "apply", str(patch_file)], cwd=wt_path, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
    )
    patch_file.unlink(missing_ok=True)
    if app.returncode != 0:
        return False, wt_path, f"git apply failed:\n{app.stderr}"

    subprocess.run(["git", "add", "-N", "."], cwd=wt_path, check=True, capture_output=True)
    return True, wt_path, "Patch applied cleanly in isolated worktree."


def enforce_task_scope(
    task: dict[str, Any], wt_path: Path, attempt: int, plan_hash: str
) -> tuple[bool, str, list[str]]:
    diff_names = subprocess.run(
        ["git", "diff", "HEAD", "--name-only"], cwd=wt_path, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
    ).stdout.splitlines()

    touched_files = sorted({PurePosixPath(p).as_posix() for p in diff_names if p.strip()})
    allowed_globs = task.get("allowed_paths", [])
    forbidden_globs = task.get(
        "forbidden_paths",
        [
            "supervisor.py",
            "verify_audit_log.py",
            "remediation_plan.json",
            "gates.json",
            "runners/**",
            "pipeline_audit_trail.jsonl",
        ],
    )
    violations: list[str] = []
    if not touched_files:
        violations.append("No files modified in worktree.")

    for fpath in touched_files:
        if any(matches_glob(fpath, pat) for pat in forbidden_globs):
            violations.append(f"Forbidden path modified: {fpath}")
        if not any(matches_glob(fpath, pat) for pat in allowed_globs):
            violations.append(f"Path outside allowed_paths: {fpath}")

    numstat = subprocess.run(
        ["git", "diff", "HEAD", "--numstat"], cwd=wt_path, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True
    ).stdout.splitlines()

    total_lines = 0
    for line in numstat:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            total_lines += int(parts[0]) + int(parts[1])

    max_lines = task.get("max_changed_lines", 600)
    if total_lines > max_lines:
        violations.append(f"Diff size {total_lines} lines exceeds max_changed_lines ({max_lines}).")

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    scope_report_path = EVIDENCE_DIR / f"{task['task_id']}_attempt_{attempt}.scope_report.json"
    scope_report = {
        "task_id": task["task_id"],
        "attempt": attempt,
        "passed": len(violations) == 0,
        "total_changed_lines": total_lines,
        "max_changed_lines": max_lines,
        "touched_files": touched_files,
        "violations": violations,
    }
    scope_report_path.write_text(json.dumps(scope_report, indent=2), encoding="utf-8")

    if violations:
        append_audit_event(
            event_type="scope_violation",
            role="supervisor",
            model="deterministic",
            payload=scope_report,
            plan_hash=plan_hash,
        )
        return False, "\n".join(violations), touched_files

    return True, f"Scope verified ({len(touched_files)} files, {total_lines} lines).", touched_files


def read_files_from_worktree(wt_path: Path, touched_files: list[str]) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for rel_path in touched_files:
        full_path = wt_path / rel_path
        if full_path.exists() and full_path.is_file():
            snapshot[rel_path] = full_path.read_bytes().decode("utf-8", errors="replace")
    return snapshot


def run_scripted_gates(cwd: Path, include_mutating: bool = False) -> tuple[bool, list[dict[str, Any]]]:
    default_gates = [
        {"name": "ruff", "cmd": [sys.executable, "-m", "ruff", "check", "src", "tests"], "read_only": True},
        {"name": "pytest_suite", "cmd": [sys.executable, "-m", "pytest", "-q"], "read_only": True},
        {"name": "bandit", "cmd": [sys.executable, "-m", "bandit", "-q", "-r", "src/"], "read_only": True},
        {"name": "pip_audit", "cmd": [sys.executable, "-m", "pip_audit", "-r", "requirements.txt"], "read_only": True},
        {"name": "gitleaks", "cmd": ["gitleaks", "detect", "--no-git", "-v"], "read_only": True},
        {
            "name": "break_glass_staging_mutation_drill",
            "cmd": [sys.executable, "-m", "unittest", "tests/test_phase4_backup_and_break_glass.py"],
            "read_only": False,
        },
    ]
    gates = json.loads(GATES_CONFIG_PATH.read_text(encoding="utf-8")) if GATES_CONFIG_PATH.exists() else default_gates
    results: list[dict[str, Any]] = []

    gate_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    for gate in gates:
        if not gate.get("read_only", True) and not include_mutating:
            continue
        cmd = [sys.executable if token == "PYTHON" else token for token in gate["cmd"]]
        try:
            res = subprocess.run(cmd, cwd=cwd, env=gate_env, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=180)
            entry = {
                "gate": gate["name"],
                "cmd": cmd,
                "cwd": str(cwd),
                "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "read_only": gate.get("read_only", True),
                "returncode": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
            }
        except FileNotFoundError:
            entry = {
                "gate": gate["name"],
                "cmd": cmd,
                "cwd": str(cwd),
                "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "read_only": gate.get("read_only", True),
                "returncode": 127,
                "stdout": "",
                "stderr": f"Command not found: {cmd[0]}",
            }
        results.append(entry)
        if entry["returncode"] != 0:
            return False, results

    return True, results


def run_acceptance(task: dict[str, Any], cwd: Path) -> tuple[bool, list[dict[str, Any]]]:
    required_tests = task.get("required_tests", [])
    if not required_tests:
        return False, [{"test_target": "<none>", "returncode": 1, "stdout": "", "stderr": "No required_tests bound."}]

    gate_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    results: list[dict[str, Any]] = []
    for test_target in required_tests:
        chk_pytest = subprocess.run([sys.executable, "-m", "pytest", "--version"], capture_output=True, check=False)
        if chk_pytest.returncode == 0:
            cmd = [sys.executable, "-B", "-m", "pytest", "-q", test_target]
        else:
            cmd = [sys.executable, "-B", "-m", "unittest", test_target]

        res = subprocess.run(cmd, cwd=cwd, env=gate_env, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=120)
        results.append(
            {
                "test_target": test_target,
                "cwd": str(cwd),
                "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "returncode": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
            }
        )
        if res.returncode != 0:
            return False, results

    return True, results


def verify_critic_attestation(critic_out: dict[str, Any], code_snapshot: dict[str, str]) -> tuple[bool, str]:
    expected_hashes = {rel: sha256_hex(content) for rel, content in code_snapshot.items()}
    attested = critic_out.get("reviewed_file_hashes", {})
    if attested != expected_hashes:
        return False, f"Critic attestation mismatch: attested {attested} != expected {expected_hashes}"
    return True, "Critic file hash attestation verified."


@dataclass
class EvidencePacket:
    packet_id: str
    packet_sha256: str
    packet_path: Path
    patch_path: Path
    summary_text: str


def build_evidence_packet(
    task: dict[str, Any],
    attempt: int,
    baseline_ref: str,
    wt_path: Path,
    touched_files: list[str],
    gate_results: list[dict[str, Any]],
    acceptance_results: list[dict[str, Any]],
    critic_findings: list[dict[str, Any]],
    critic_attested: bool,
) -> EvidencePacket:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    packet_id = f"{task['task_id']}_attempt_{attempt}"

    diff_text = subprocess.run(
        ["git", "diff", "HEAD", "--", *touched_files],
        cwd=wt_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout

    file_hashes = {
        rel: sha256_hex((wt_path / rel).read_bytes())
        for rel in touched_files
        if (wt_path / rel).exists() and (wt_path / rel).is_file()
    }

    patch_path = EVIDENCE_DIR / f"{packet_id}.patch"
    patch_path.write_text(diff_text, encoding="utf-8")

    gates_txt_path = EVIDENCE_DIR / f"{packet_id}.gates.txt"
    gates_txt_path.write_text(
        json.dumps({"gates": gate_results, "acceptance": acceptance_results}, indent=2),
        encoding="utf-8",
    )

    packet_data = {
        "packet_id": packet_id,
        "task_id": task["task_id"],
        "audit_ids": task["audit_ids"],
        "attempt": attempt,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_base_ref": baseline_ref,
        "file_hashes_sha256": file_hashes,
        "patch_sha256": sha256_hex(diff_text),
        "gate_exit_codes": {g["gate"]: g["returncode"] for g in gate_results},
        "acceptance_exit_codes": {a["test_target"]: a["returncode"] for a in acceptance_results},
        "critic_attestation_valid": critic_attested,
        "critic_advisory_findings": critic_findings,
    }
    packet_sha256 = sha256_hex(canonical_json(packet_data))
    packet_data["packet_sha256"] = packet_sha256

    packet_json_path = EVIDENCE_DIR / f"{packet_id}.json"
    packet_json_path.write_text(json.dumps(packet_data, indent=2), encoding="utf-8")

    summary = (
        f"\n================ EVIDENCE PACKET [{packet_id}] ================\n"
        f"  Packet JSON   : {packet_json_path}\n"
        f"  Patch Artifact: {patch_path}\n"
        f"  Gates Log     : {gates_txt_path}\n"
        f"  Baseline Ref  : {baseline_ref}\n"
        f"  File Hashes   : {json.dumps(file_hashes, indent=4)}\n"
        f"  Gate Codes    : {packet_data['gate_exit_codes']}\n"
        f"  Acceptance    : {packet_data['acceptance_exit_codes']}\n"
        f"  Critic Notes  : {len(critic_findings)} finding(s) (Attested={critic_attested})\n"
        f"  PACKET SHA256 : {packet_sha256}\n"
        f"====================================================================\n"
    )
    return EvidencePacket(packet_id, packet_sha256, packet_json_path, patch_path, summary)


def require_human_evidence_signoff(packet: EvidencePacket, plan_hash: str) -> None:
    print(packet.summary_text)
    if os.environ.get("TRIAL_STOP_AT_EVIDENCE") == "1":
        append_audit_event(
            event_type="trial_paused_at_evidence_gate",
            role="supervisor",
            model="deterministic",
            payload={"packet_id": packet.packet_id, "packet_sha256": packet.packet_sha256},
            plan_hash=plan_hash,
        )
        print(
            f"[TRIAL_STOP_AT_EVIDENCE=1] Halting cleanly BEFORE promote/commit.\n"
            f"Inspect {packet.patch_path} and {packet.packet_path}.\n"
            f"Main working tree was NOT modified."
        )
        sys.exit(0)

    expected_cmd = f"approve {packet.packet_sha256}"
    response = input(f"Inspect {packet.patch_path} then type '{expected_cmd}': ").strip()
    if response != expected_cmd:
        append_audit_event(
            event_type="human_signoff_rejected",
            role="human",
            model="HITL",
            payload={"packet_id": packet.packet_id, "packet_sha256": packet.packet_sha256, "input": response},
            plan_hash=plan_hash,
        )
        raise SystemExit("Human rejected evidence packet. Aborting without promoting worktree.")

    append_audit_event(
        event_type="human_signoff_approved",
        role="human",
        model="HITL",
        payload={"packet_id": packet.packet_id, "packet_sha256": packet.packet_sha256},
        plan_hash=plan_hash,
    )


def promote_and_advance_baseline(
    task_id: str, wt_path: Path, touched_files: list[str], packet_sha256: str, plan_hash: str, tag_note: str = ""
) -> str:
    for rel_path in touched_files:
        src = wt_path / rel_path
        dst = REPO_ROOT / rel_path
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        elif dst.exists():
            dst.unlink()

    subprocess.run(["git", "add", "-A", "--", *touched_files], cwd=REPO_ROOT, check=True)
    commit_msg = f"promote({task_id}): verified packet {packet_sha256[:16]} {tag_note}".strip()
    subprocess.run(["git", "commit", "-m", commit_msg, "--", *touched_files], cwd=REPO_ROOT, check=True)

    new_head, new_tree, _, new_porcelain_hash = get_working_tree_state(REPO_ROOT)
    append_audit_event(
        event_type="worktree_promoted_and_committed",
        role="supervisor",
        model="deterministic",
        payload={
            "task_id": task_id,
            "packet_sha256": packet_sha256,
            "new_baseline_head_sha": new_head,
            "new_write_tree_sha": new_tree,
            "porcelain_sha256": new_porcelain_hash,
            "committed_files": touched_files,
        },
        plan_hash=plan_hash,
    )
    return new_head


def request_break_glass_override(
    task: dict[str, Any],
    last_packet: EvidencePacket | None,
    last_wt_path: Path | None,
    last_touched_files: list[str],
    last_feedback: str,
    plan_hash: str,
) -> tuple[dict[str, Any], str | None]:
    if os.environ.get("HUMAN_BREAK_GLASS") != "1":
        raise SystemExit(
            f"[STOP] Task {task['task_id']} failed {MAX_RETRIES} retries and HUMAN_BREAK_GLASS!=1. Halting."
        )

    if task.get("critical", False) and not os.environ.get("SECOND_APPROVER_FILE"):
        raise SystemExit(
            f"[STOP] Task {task['task_id']} is CRITICAL. Break-glass requires SECOND_APPROVER_FILE."
        )

    pkt_hash = last_packet.packet_sha256 if last_packet else "no_packet"
    action = input(
        f"MAX RETRIES EXHAUSTED for {task['task_id']}.\n"
        f"Type 'waive {pkt_hash}' (if plan permits) or 'force_promote {pkt_hash}': "
    ).strip()

    if action == f"waive {pkt_hash}":
        if not task.get("allow_waiver", False):
            raise SystemExit(f"Task {task['task_id']} does not allow waivers in remediation_plan.json.")
        mode = "waived"
    elif action == f"force_promote {pkt_hash}":
        if not last_wt_path or not last_touched_files:
            raise SystemExit("Cannot force_promote: no valid worktree patch exists.")
        mode = "force_promoted"
    else:
        raise SystemExit("Break-glass aborted by human.")

    ticket_id = input("Mandatory Incident/Ticket ID: ").strip()
    reason = input("Mandatory Override Justification (>=15 chars): ").strip()
    if not ticket_id or len(reason) < 15:
        raise SystemExit("Break-glass rejected: valid ticket_id and detailed reason required.")

    new_head: str | None = None
    if mode == "force_promoted" and last_wt_path and last_packet:
        new_head = promote_and_advance_baseline(
            task["task_id"],
            last_wt_path,
            last_touched_files,
            last_packet.packet_sha256,
            plan_hash,
            tag_note=f"[BREAK-GLASS-TAINTED ticket:{ticket_id}]",
        )

    override_record = {
        "task_id": task["task_id"],
        "audit_ids": task["audit_ids"],
        "mode": mode,
        "packet_sha256": pkt_hash,
        "ticket_id": ticket_id,
        "reason": reason,
        "promoted_head_sha": new_head,
        "last_failure_feedback": last_feedback,
    }
    append_audit_event(
        event_type="break_glass_override",
        role="human_break_glass",
        model="HITL",
        payload=override_record,
        plan_hash=plan_hash,
    )
    return override_record, new_head


def final_task_accounting(
    plan: dict[str, Any],
    task_outcomes: dict[str, str],
    plan_hash: str,
) -> None:
    plan_by_id = {wp["task_id"]: wp for wp in plan["work_packages"]}
    unaccounted: list[str] = []
    illegal_waivers: list[str] = []
    covered_audit_ids: set[str] = set()

    for tid, wp in plan_by_id.items():
        outcome = task_outcomes.get(tid)
        if outcome not in ("promoted", "force_promoted", "waived"):
            unaccounted.append(f"{tid} (status={outcome})")
            continue
        if outcome == "waived" and not wp.get("allow_waiver", False):
            illegal_waivers.append(tid)
            continue
        covered_audit_ids |= set(wp["audit_ids"])

    missing_audit_ids = set(plan["all_audit_ids"]) - (
        covered_audit_ids | set(plan.get("waived_audit_ids", {}).keys())
    )
    if unaccounted or illegal_waivers or missing_audit_ids:
        raise SystemExit(
            f"[STOP] Final task accounting failed! "
            f"unaccounted={unaccounted}, illegal_waivers={illegal_waivers}, missing_audit_ids={sorted(missing_audit_ids)}"
        )

    append_audit_event(
        event_type="final_task_accounting_verified",
        role="supervisor",
        model="deterministic",
        payload={"task_outcomes": task_outcomes, "covered_audit_ids": sorted(covered_audit_ids)},
        plan_hash=plan_hash,
    )


def final_verification_gate(
    plan: dict[str, Any],
    task_outcomes: dict[str, str],
    approved_packet_hashes: list[str],
    overrides: list[dict[str, Any]],
    plan_hash: str,
) -> None:
    final_task_accounting(plan, task_outcomes, plan_hash)

    print("\n=== RUNNING FINAL MERGED RE-VERIFICATION GATES (INCLUDING MUTATING DRILLS) ===")
    head_sha, write_tree_sha, porcelain, porcelain_hash = get_working_tree_state(REPO_ROOT)

    dirty_code_lines = [
        line
        for line in porcelain.splitlines()
        if not any(
            ign in line
            for ign in (
                "pipeline_audit_trail.jsonl",
                ".audit_head_sha256",
                "narrative_log.jsonl",
                "evidence/",
                "worktrees/",
                "supervisor.py",
                "verify_audit_log.py",
                "remediation_plan.json",
                "gates.json",
                "fixtures/",
            )
        )
    ]
    if dirty_code_lines:
        raise SystemExit(
            "[STOP] Working tree has uncommitted code modifications outside promoted commits:\n"
            + "\n".join(dirty_code_lines)
        )

    gates_ok, final_gate_results = run_scripted_gates(cwd=REPO_ROOT, include_mutating=True)
    if not gates_ok:
        append_audit_event(
            event_type="final_verification_failed",
            role="supervisor",
            model="deterministic",
            payload={"gate_results": final_gate_results},
            plan_hash=plan_hash,
        )
        raise SystemExit("[STOP] Final verification gates failed on merged repository state!")

    bundle_payload = {
        "plan_hash": plan_hash,
        "git_head_sha": head_sha,
        "git_write_tree_sha": write_tree_sha,
        "porcelain_sha256": porcelain_hash,
        "task_outcomes": task_outcomes,
        "approved_evidence_packets": approved_packet_hashes,
        "break_glass_overrides": overrides,
        "tainted_release": len(overrides) > 0,
        "final_gate_exit_codes": {g["gate"]: g["returncode"] for g in final_gate_results},
    }
    release_bundle_hash = sha256_hex(canonical_json(bundle_payload))

    print("\n=== FINAL RELEASE GATEWAY ===")
    print(f"  Git HEAD Commit SHA    : {head_sha}")
    print(f"  Git Write-Tree SHA     : {write_tree_sha}")
    print(f"  Porcelain Status Hash  : {porcelain_hash}")
    print(f"  Plan SHA256            : {plan_hash}")
    print(f"  Task Outcomes          : {task_outcomes}")
    print(f"  Verified Packets ({len(approved_packet_hashes)}) : {approved_packet_hashes}")
    print(f"  Break-Glass Overrides  : {len(overrides)} (Tainted={bundle_payload['tainted_release']})")
    print(f"  RELEASE BUNDLE SHA256  : {release_bundle_hash}")

    expected_prefix = "approve_tainted" if overrides else "approve"
    expected = f"{expected_prefix} {release_bundle_hash}"
    confirm = input(f"\nNothing counts as released until you type '{expected}': ").strip()
    if confirm != expected:
        append_audit_event(
            event_type="final_release_rejected",
            role="human",
            model="HITL",
            payload={"release_bundle_hash": release_bundle_hash, "input": confirm},
            plan_hash=plan_hash,
        )
        raise SystemExit("Final release rejected by human.")

    append_audit_event(
        event_type="final_release_approved",
        role="human",
        model="HITL",
        payload={**bundle_payload, "release_bundle_hash": release_bundle_hash},
        plan_hash=plan_hash,
    )
    print(f"Release {release_bundle_hash} signed off and sealed in {AUDIT_LOG_PATH.name}.")


def run_supervisor() -> None:
    ok, msg, _ = verify_audit_trail(AUDIT_LOG_PATH, AUDIT_HEAD_SEAL_PATH)
    if not ok:
        raise RuntimeError(msg)

    plan, plan_hash = load_and_hash_plan()
    baseline_ref, _, _, _ = get_working_tree_state(REPO_ROOT)

    orch_raw = invoke_isolated_role("orchestrator", {"plan": plan, "plan_hash": plan_hash}, plan_hash)
    tasks = validate_orchestrator_output(orch_raw, plan, plan_hash)

    approved_packets: list[str] = []
    overrides: list[dict[str, Any]] = []
    task_outcomes: dict[str, str] = {}

    active_task_filter = os.environ.get("ACTIVE_TASK_ID")
    for task in tasks:
        task_id = task["task_id"]
        if active_task_filter and task_id != active_task_filter:
            continue
        print(f"\n>>> Starting Task {task_id} at Baseline {baseline_ref[:12]} (Audit IDs: {task['audit_ids']}) <<<")
        append_audit_event(
            event_type="task_dispatch_ack",
            role="supervisor",
            model="deterministic",
            payload={"task_id": task_id, "plan_hash": plan_hash, "baseline_ref": baseline_ref},
            plan_hash=plan_hash,
        )

        feedback: str | None = None
        last_packet: EvidencePacket | None = None
        last_wt_path: Path | None = None
        last_touched_files: list[str] = []
        task_succeeded = False

        for attempt in range(1, MAX_RETRIES + 1):
            worker_out = invoke_isolated_role(
                "worker",
                {"task": task, "attempt": attempt, "baseline_ref": baseline_ref, "feedback": feedback},
                plan_hash,
            )

            applied_ok, wt_path, apply_msg = apply_patch_in_worktree(
                task_id, attempt, baseline_ref, worker_out.get("unified_diff", "")
            )
            last_wt_path = wt_path
            if not applied_ok:
                feedback = f"Patch Application Failed:\n{apply_msg}"
                continue

            scope_ok, scope_msg, touched_files = enforce_task_scope(task, wt_path, attempt, plan_hash)
            last_touched_files = touched_files
            if not scope_ok:
                feedback = f"Scope Violation:\n{scope_msg}"
                continue

            gates_ok, gate_results = run_scripted_gates(cwd=wt_path, include_mutating=False)
            acceptance_ok, acceptance_results = run_acceptance(task, cwd=wt_path)

            # Re-verify scope after gates/acceptance to ensure no unexpected files or tracked bytecode were mutated
            post_scope_ok, post_scope_msg, post_touched_files = enforce_task_scope(task, wt_path, attempt, plan_hash)
            if not post_scope_ok or post_touched_files != touched_files:
                feedback = f"Post-Gate Scope Drift:\n{post_scope_msg}"
                continue

            code_snapshot = read_files_from_worktree(wt_path, touched_files)
            critic_out = invoke_isolated_role(
                "critic",
                {
                    "task_id": task_id,
                    "audit_ids": task["audit_ids"],
                    "acceptance_criteria": task["acceptance_criteria"],
                    "code_only": code_snapshot,
                },
                plan_hash,
                read_only_worktree=wt_path,
            )
            critic_attested, attest_msg = verify_critic_attestation(critic_out, code_snapshot)
            critic_findings = critic_out.get("findings", [])
            critical_critic_findings = [f for f in critic_findings if f.get("severity") == "critical"]

            last_packet = build_evidence_packet(
                task,
                attempt,
                baseline_ref,
                wt_path,
                touched_files,
                gate_results,
                acceptance_results,
                critic_findings,
                critic_attested,
            )

            task_passed = (
                scope_ok
                and gates_ok
                and acceptance_ok
                and critic_attested
                and (len(critical_critic_findings) == 0)
            )

            if not task_passed:
                feedback = json.dumps(
                    {
                        "gates_ok": gates_ok,
                        "acceptance_ok": acceptance_ok,
                        "critic_attested": critic_attested,
                        "critic_attestation_msg": attest_msg,
                        "gate_failures": [g for g in gate_results if g["returncode"] != 0],
                        "acceptance_failures": [a for a in acceptance_results if a["returncode"] != 0],
                        "critical_critic_findings": critical_critic_findings,
                    },
                    indent=2,
                )
                print(f"  [Attempt {attempt}/{MAX_RETRIES}] Task failed checks:\n{feedback}")
                continue

            require_human_evidence_signoff(last_packet, plan_hash)

            baseline_ref = promote_and_advance_baseline(
                task_id, wt_path, touched_files, last_packet.packet_sha256, plan_hash
            )
            approved_packets.append(last_packet.packet_sha256)
            task_outcomes[task_id] = "promoted"
            task_succeeded = True
            break

        if not task_succeeded:
            override_info, maybe_new_head = request_break_glass_override(
                task, last_packet, last_wt_path, last_touched_files, feedback or "Unknown failure", plan_hash
            )
            overrides.append(override_info)
            task_outcomes[task_id] = override_info["mode"]
            if maybe_new_head:
                baseline_ref = maybe_new_head

    final_verification_gate(plan, task_outcomes, approved_packets, overrides, plan_hash)


if __name__ == "__main__":
    run_supervisor()
