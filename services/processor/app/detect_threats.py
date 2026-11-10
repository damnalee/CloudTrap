#!/usr/bin/env python3
"""Rule-based threat detection for CloudTrap."""

import argparse
import json
import re
import sys

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_INPUT = PROJECT_ROOT / "data/processed/events.jsonl"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/processed/alerts.json"

COMMAND_RULES = [
    (
        "suspicious.remote_script_execution",
        re.compile(
            r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sh|bash)\b",
            re.IGNORECASE,
        ),
        "high",
        "Remote content is being piped directly into a shell.",
    ),
    (
        "suspicious.persistence_attempt",
        re.compile(
            r"\bcrontab\b|/etc/cron(?:\.|/)",
            re.IGNORECASE,
        ),
        "medium",
        "Command appears to modify or inspect scheduled tasks.",
    ),
]


def parse_timestamp(value):
    """Parse Cowrie timestamps into timezone-aware datetimes."""
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed
    except ValueError:
        return None


def load_events(path):
    """Load normalized JSONL events and count malformed records."""
    events = []
    malformed = 0

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if isinstance(event, dict):
                    events.append(event)
                else:
                    malformed += 1

            except json.JSONDecodeError:
                malformed += 1

    return events, malformed


def make_alert(rule_id, severity, source_ip, session_id,
               occurred_at, description, **details):
    """Create a safe alert without raw credentials or commands."""
    alert = {
        "rule_id": rule_id,
        "severity": severity,
        "source_ip": source_ip,
        "session_id": session_id,
        "occurred_at": occurred_at,
        "description": description,
    }

    alert.update(details)
    return alert


def detect_threats(
    events,
    brute_force_threshold=5,
    brute_force_window_minutes=5,
    success_window_minutes=10,
):
    """Analyze normalized events and return detected threat alerts."""

    alerts = []
    logins_by_ip = defaultdict(list)
    commands = []

    for event in events:
        event_type = event.get("event_type")
        source_ip = event.get("source_ip")
        session_id = event.get("session_id")
        timestamp = parse_timestamp(event.get("timestamp"))

        if not source_ip or not timestamp:
            continue

        if event_type in ("cowrie.login.failed", "cowrie.login.success"):
            logins_by_ip[source_ip].append({
                "type": event_type,
                "timestamp": timestamp,
                "session_id": session_id,
            })

        elif event_type == "cowrie.command.input":
            commands.append({
                "event": event,
                "timestamp": timestamp,
                "source_ip": source_ip,
                "session_id": session_id,
            })

    # RULE 1: Multiple failed login attempts within a time window.
    for source_ip, login_events in logins_by_ip.items():
        failed = sorted(
            [
                item for item in login_events
                if item["type"] == "cowrie.login.failed"
            ],
            key=lambda item: item["timestamp"],
        )

        window = timedelta(minutes=brute_force_window_minutes)

        for index, first in enumerate(failed):
            end = first["timestamp"] + window

            matching = [
                item for item in failed[index:]
                if item["timestamp"] <= end
            ]

            if len(matching) >= brute_force_threshold:
                alerts.append(make_alert(
                    rule_id="authentication.brute_force",
                    severity="high",
                    source_ip=source_ip,
                    session_id=first["session_id"],
                    occurred_at=first["timestamp"].isoformat(),
                    description=(
                        "Repeated failed SSH logins detected "
                        "within a short time window."
                    ),
                    failed_attempts=len(matching),
                    threshold=brute_force_threshold,
                    window_minutes=brute_force_window_minutes,
                ))
                break

    # RULE 2: Failed logins followed by a successful login.
    for source_ip, login_events in logins_by_ip.items():
        ordered = sorted(
            login_events,
            key=lambda item: item["timestamp"],
        )

        for success in ordered:
            if success["type"] != "cowrie.login.success":
                continue

            prior_failures = [
                item for item in ordered
                if item["type"] == "cowrie.login.failed"
                and timedelta(0) <= (
                    success["timestamp"] - item["timestamp"]
                ) <= timedelta(minutes=success_window_minutes)
            ]

            if prior_failures:
                alerts.append(make_alert(
                    rule_id="authentication.failure_then_success",
                    severity="high",
                    source_ip=source_ip,
                    session_id=success["session_id"],
                    occurred_at=success["timestamp"].isoformat(),
                    description=(
                        "A successful login followed failed "
                        "authentication attempts from the same IP."
                    ),
                    preceding_failures=len(prior_failures),
                    window_minutes=success_window_minutes,
                ))

    # RULES 3 and 4: Suspicious command patterns.
    for item in commands:
        command = item["event"].get("command", "")

        if not isinstance(command, str):
            continue

        for rule_id, pattern, severity, description in COMMAND_RULES:
            if pattern.search(command):
                alerts.append(make_alert(
                    rule_id=rule_id,
                    severity=severity,
                    source_ip=item["source_ip"],
                    session_id=item["session_id"],
                    occurred_at=item["timestamp"].isoformat(),
                    description=description,
                ))

    alerts.sort(
        key=lambda alert: (
            alert["occurred_at"],
            alert["rule_id"],
        )
    )

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="CloudTrap threat detection engine"
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
        print(f"ERROR: Input not found: {args.input}", file=sys.stderr)
        return 1

    try:
        events, malformed = load_events(args.input)

        alerts = detect_threats(events)

        args.output.parent.mkdir(parents=True, exist_ok=True)

        result = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "events_analyzed": len(events),
            "malformed_lines": malformed,
            "total_alerts": len(alerts),
            "alerts_by_severity": {
                severity: sum(
                    1 for alert in alerts
                    if alert["severity"] == severity
                )
                for severity in ("high", "medium", "low")
            },
            "alerts": alerts,
        }

        args.output.write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )

        print("\n=== CloudTrap Threat Detection ===")
        print(f"Events analyzed: {len(events)}")
        print(f"Malformed lines: {malformed}")
        print(f"Threat alerts: {len(alerts)}")
        print(f"High severity: {result['alerts_by_severity']['high']}")
        print(f"Medium severity: {result['alerts_by_severity']['medium']}")
        print(f"Alerts saved to: {args.output}")

        return 0

    except (OSError, UnicodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
