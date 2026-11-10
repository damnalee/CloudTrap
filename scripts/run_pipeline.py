#!/usr/bin/env python3
"""Run the complete local CloudTrap processing pipeline."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "services" / "processor" / "app"
sys.path.insert(0, str(APP_DIR))

from process_cowrie import generate_summary, load_events
from detect_threats import detect_threats
from correlate_incidents import correlate_alerts

DEFAULT_INPUT = ROOT / "data/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_OUTPUT = ROOT / "data/processed"


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def write_jsonl(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Cowrie ingestion, threat detection and incident correlation."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--brute-force-threshold", type=int, default=5)
    parser.add_argument("--brute-force-window", type=int, default=5)
    parser.add_argument("--correlation-window", type=int, default=30)
    args = parser.parse_args()

    if args.brute_force_threshold < 2:
        parser.error("--brute-force-threshold must be at least 2")
    if args.brute_force_window < 1 or args.correlation_window < 0:
        parser.error("time windows must be non-negative; brute-force window must be positive")
    if not args.input.is_file():
        print(f"ERROR: Cowrie log not found: {args.input}", file=sys.stderr)
        print("Start Cowrie and create at least one SSH session first.", file=sys.stderr)
        return 1

    try:
        events, malformed = load_events(args.input)
        summary = generate_summary(events, malformed, Path(args.input.name))
        # Keep generated artifacts portable: never store the Mac's absolute path.
        summary["source_file"] = args.input.name

        alerts = detect_threats(
            events,
            brute_force_threshold=args.brute_force_threshold,
            brute_force_window_minutes=args.brute_force_window,
        )

        alert_payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "events_analyzed": len(events),
            "malformed_lines": malformed,
            "total_alerts": len(alerts),
            "alerts_by_severity": {
                severity: sum(1 for alert in alerts if alert["severity"] == severity)
                for severity in ("high", "medium", "low")
            },
            "alerts": alerts,
        }

        incident_payload = correlate_alerts(
            alerts,
            window_minutes=args.correlation_window,
        )

        args.output_dir.mkdir(parents=True, exist_ok=True)
        write_jsonl(args.output_dir / "events.jsonl", events)
        write_json(args.output_dir / "summary.json", summary)
        write_json(args.output_dir / "alerts.json", alert_payload)
        write_json(args.output_dir / "incidents.json", incident_payload)

        print("\n=== CloudTrap Pipeline Complete ===")
        print(f"Input records:        {len(events) + malformed}")
        print(f"Normalized events:    {len(events)}")
        print(f"Malformed lines:      {malformed}")
        print(f"Unique sessions:      {summary['unique_sessions']}")
        print(f"Unique source IPs:    {summary['unique_source_ips']}")
        print(f"Threat alerts:        {alert_payload['total_alerts']}")
        print(f"Correlated incidents: {incident_payload['total_incidents']}")
        print(f"Output directory:     {args.output_dir}")
        print("\nGenerated: events.jsonl, summary.json, alerts.json, incidents.json")
        return 0

    except (OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"ERROR: Pipeline failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
