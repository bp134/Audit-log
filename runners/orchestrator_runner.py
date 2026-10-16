#!/usr/bin/env python3
"""Isolated Orchestrator Runner (opencode/gemini-4-argon)."""

import json
import sys


def main() -> None:
    payload = json.loads(sys.stdin.read())
    out = {
        "request_id": "orch-gemini4-argon-wp2",
        "token_usage": {"prompt": 512, "completion": 240},
        "tasks": payload["plan"]["work_packages"],
    }
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
