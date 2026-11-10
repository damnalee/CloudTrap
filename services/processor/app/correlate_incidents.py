#!/usr/bin/env python3
"""Group related CloudTrap alerts into security incidents."""

import argparse
import hashlib
import json
import sys

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_INPUT = PROJECT_ROOT / "data/processed/alerts.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/processed/incidents.json"

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SAFE_DETAIL_FIELDS = (
    "failed_attempts",
    "preceding_failures",
    "threshold",
    "window_minutes",
)


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp

    except ValueError:
        return None


def prepare_alerts(alerts):
    """Validate alerts and retain only safe, necessary fields."""

    prepared = []
    skipped = 0

    for alert in alerts:
        if not isinstance(alert, dict):
            skipped += 1
            continue

        timestamp = parse_timestamp(alert.get("occurred_at"))
        source_ip = alert.get("source_ip")

        if not timestamp or not isinstance(source_ip, str) or not source_ip:
            skipped += 1
            continue

        severity = alert.get("severity", "low")

        if severity not in SEVERITY_RANK:
            severity = "low"

        safe = {
            "rule_id": str(alert.get("rule_id", "unknown")),
            "severity": severity,
            "source_ip": source_ip,
            "session_id": alert.get("session_id"),
            "occurred_at": timestamp.isoformat(),
            "description": str(alert.get("description", "")),
        }

        for field in SAFE_DETAIL_FIELDS:
            value = alert.get(field)

            if type(value) is int:
                safe[field] = value

        prepared.append({
            "timestamp": timestamp,
            "alert": safe,
        })

    prepared.sort(
        key=lambda item: (
            item["timestamp"],
            item["alert"]["source_ip"],
        )
    )

    return prepared, skipped


def make_incident_id(source_ip, first_seen):
    """Generate a repeatable incident identifier."""
    identity = f"{source_ip}|{first_seen.isoformat()}"
    digest = hashlib.sha256(identity.encode()).hexdigest()[:12]

    return f"INC-{digest.upper()}"


def correlate_alerts(alerts, window_minutes=30):
    """
    Group alerts from the same source IP when they occur
    within the configured window from the incident's first alert.
    """

    if window_minutes < 0:
        raise ValueError("window_minutes cannot be negative")

    prepared, skipped = prepare_alerts(alerts)

    groups = []
    active_by_ip = {}

    window = timedelta(minutes=window_minutes)

    for item in prepared:
        timestamp = item["timestamp"]
        alert = item["alert"]
        source_ip = alert["source_ip"]

        current = active_by_ip.get(source_ip)

        if (
            current is None
            or timestamp - current["first_timestamp"] > window
        ):
            current = {
                "source_ip": source_ip,
                "first_timestamp": timestamp,
                "items": [],
            }

            groups.append(current)
            active_by_ip[source_ip] = current

        current["items"].append(item)

    incidents = []

    for group in groups:
        items = group["items"]

        incident_alerts = [
            item["alert"] for item in items
        ]

        first_seen = items[0]["timestamp"]
        last_seen = items[-1]["timestamp"]

        source_ip = group["source_ip"]

        severity = max(
            (a["severity"] for a in incident_alerts),
            key=lambda value: SEVERITY_RANK[value],
        )

        rules = sorted({
            a["rule_id"] for a in incident_alerts
        })

        sessions = sorted({
            a["session_id"]
            for a in incident_alerts
            if a.get("session_id")
        })

        incidents.append({
            "incident_id": make_incident_id(source_ip, first_seen),
            "severity": severity,
            "source_ip": source_ip,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "duration_seconds": int(
                (last_seen - first_seen).total_seconds()
            ),
            "alert_count": len(incident_alerts),
            "attack_patterns": rules,
            "session_ids": sessions,
            "alerts": incident_alerts,
        })

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "correlation_window_minutes": window_minutes,
        "alerts_received": len(alerts),
        "alerts_skipped": skipped,
        "total_incidents": len(incidents),
        "incidents_by_severity": dict(
            Counter(i["severity"] for i in incidents)
        ),
        "incidents": incidents,
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Correlate CloudTrap alerts into incidents"
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

    parser.add_argument(
        "--window-minutes",
        type=int,
        default=30,
    )

    args = parser.parse_args()

    if not args.input.is_file():
        print(f"ERROR: Input not found: {args.input}", file=sys.stderr)
        return 1

    try:
        payload = json.loads(
            args.input.read_text(encoding="utf-8")
        )

        if not isinstance(payload, dict):
            raise ValueError("Input must be a JSON object")

        alerts = payload.get("alerts")

        if not isinstance(alerts, list):
            raise ValueError("Input must contain an alerts array")

        result = correlate_alerts(
            alerts,
            window_minutes=args.window_minutes,
        )

        args.output.parent.mkdir(parents=True, exist_ok=True)

        args.output.write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )

        print("\n=== CloudTrap Incident Correlation ===")
        print(f"Alerts received: {result['alerts_received']}")
        print(f"Alerts skipped: {result['alerts_skipped']}")
        print(f"Incidents generated: {result['total_incidents']}")
        print(
            "Incident severity: "
            f"{result['incidents_by_severity']}"
        )
        print(f"Saved to: {args.output}")

        return 0

    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
