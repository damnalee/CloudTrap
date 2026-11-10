#!/usr/bin/env python3
"""Convert Cowrie JSONL logs into credential-safe CloudTrap events."""

import argparse
import json
import re
import sys

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_INPUT = (
    PROJECT_ROOT / "data/cowrie/var/log/cowrie/cowrie.json"
)
DEFAULT_OUTPUT = PROJECT_ROOT / "data/processed"

SECRET_PATTERN = re.compile(
    r'(?i)\b(password|passwd|token|api[_-]?key|secret)'
    r'(\s*[=:]\s*)(["\']?)([^\s"\']+)(["\']?)'
)


def sanitize_command(command):
    """Redact common secret assignments in captured commands."""
    if not isinstance(command, str):
        return None

    return SECRET_PATTERN.sub(
        lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]",
        command
    )


def normalize_event(raw):
    """Whitelist safe fields; never copy raw passwords or messages."""

    event_type = raw.get("eventid", "unknown")

    event = {
        "timestamp": raw.get("timestamp"),
        "session_id": raw.get("session"),
        "event_type": event_type,
        "source_ip": raw.get("src_ip"),
        "protocol": raw.get("protocol"),
    }

    # Authentication events
    if event_type.startswith("cowrie.login."):
        event["username"] = raw.get("username")
        event["password_attempted"] = "password" in raw

        if event_type == "cowrie.login.success":
            event["auth_result"] = "success"
        elif event_type == "cowrie.login.failed":
            event["auth_result"] = "failed"
        else:
            event["auth_result"] = "unknown"

    # Commands executed inside the honeypot
    if event_type == "cowrie.command.input":
        event["command"] = sanitize_command(raw.get("input"))

    # Session duration
    if event_type == "cowrie.session.closed":
        event["duration_ms"] = raw.get("duration_ms")

    # Remove empty fields
    return {
        key: value
        for key, value in event.items()
        if value is not None
    }


def load_events(input_path):
    events = []
    malformed_lines = 0

    with input_path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                raw = json.loads(line)

                if not isinstance(raw, dict):
                    malformed_lines += 1
                    continue

                events.append(normalize_event(raw))

            except json.JSONDecodeError:
                malformed_lines += 1

    return events, malformed_lines


def generate_summary(events, malformed_lines, input_path):
    event_counts = Counter()
    source_ips = Counter()
    sessions = set()

    login_success = 0
    login_failed = 0
    command_count = 0

    for event in events:
        event_counts[event["event_type"]] += 1

        if event.get("source_ip"):
            source_ips[event["source_ip"]] += 1

        if event.get("session_id"):
            sessions.add(event["session_id"])

        if event.get("auth_result") == "success":
            login_success += 1
        elif event.get("auth_result") == "failed":
            login_failed += 1

        if event["event_type"] == "cowrie.command.input":
            command_count += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(input_path),
        "total_events": len(events),
        "malformed_lines": malformed_lines,
        "unique_sessions": len(sessions),
        "unique_source_ips": len(source_ips),
        "login_attempts": {
            "successful": login_success,
            "failed": login_failed,
        },
        "commands_observed": command_count,
        "events_by_type": dict(sorted(event_counts.items())),
        "top_source_ips": [
            {"ip": ip, "events": count}
            for ip, count in source_ips.most_common(10)
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Process CloudTrap Cowrie logs"
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    if not args.input.is_file():
        print(f"ERROR: Input log not found: {args.input}", file=sys.stderr)
        return 1

    try:
        events, malformed = load_events(args.input)

        args.output.mkdir(parents=True, exist_ok=True)

        events_file = args.output / "events.jsonl"
        summary_file = args.output / "summary.json"

        with events_file.open("w", encoding="utf-8") as file:
            for event in events:
                file.write(json.dumps(event) + "\n")

        summary = generate_summary(events, malformed, args.input)

        summary_file.write_text(
            json.dumps(summary, indent=2),
            encoding="utf-8",
        )

        print("\n=== CloudTrap Processing Complete ===")
        print(f"Events processed: {len(events)}")
        print(f"Malformed lines: {malformed}")
        print(f"Unique sessions: {summary['unique_sessions']}")
        print(f"Unique source IPs: {summary['unique_source_ips']}")
        print(f"Commands observed: {summary['commands_observed']}")
        print(f"\nNormalized events: {events_file}")
        print(f"Attack summary: {summary_file}")

        return 0

    except (OSError, UnicodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
