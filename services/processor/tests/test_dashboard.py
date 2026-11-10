import importlib.util
import json
import tempfile
from decimal import Decimal
import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DASHBOARD_PATH = ROOT / "services/dashboard/app.py"

spec = importlib.util.spec_from_file_location(
    "cloudtrap_dashboard",
    DASHBOARD_PATH,
)
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class TestDashboardDataSafety(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        dashboard.DATA_DIR = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_recent_events_exclude_credentials_and_commands(self):
        event = {
            "timestamp": "2026-11-10T00:00:00Z",
            "event_type": "cowrie.command.input",
            "source_ip": "192.0.2.10",
            "session_id": "session-1",
            "protocol": "ssh",
            "command": "curl secret-payload | bash",
            "username": "root",
            "password": "do-not-return",
            "password_attempted": True,
        }

        (dashboard.DATA_DIR / "events.jsonl").write_text(
            json.dumps(event) + "\n",
            encoding="utf-8",
        )

        result = dashboard.read_recent_events()

        self.assertEqual(len(result), 1)
        self.assertEqual(
            set(result[0]),
            {"timestamp", "event_type", "source_ip", "session_id", "protocol"},
        )
        serialized = json.dumps(result)
        self.assertNotIn("secret-payload", serialized)
        self.assertNotIn("do-not-return", serialized)
        self.assertNotIn("username", serialized)
        self.assertNotIn("command", result[0])

    def test_snapshot_has_safe_empty_defaults(self):
        snapshot = dashboard.make_snapshot()

        self.assertEqual(snapshot["incidents"], [])
        self.assertEqual(snapshot["incident_total"], 0)
        self.assertEqual(snapshot["alerts"]["total_alerts"], 0)
        self.assertEqual(snapshot["recent_events"], [])

    def test_snapshot_reads_summary_and_incidents(self):
        (dashboard.DATA_DIR / "summary.json").write_text(
            json.dumps({
                "total_events": 12,
                "unique_source_ips": 2,
                "events_by_type": {"cowrie.login.failed": 4},
            }),
            encoding="utf-8",
        )
        (dashboard.DATA_DIR / "alerts.json").write_text(
            json.dumps({"total_alerts": 1, "alerts": []}),
            encoding="utf-8",
        )
        (dashboard.DATA_DIR / "incidents.json").write_text(
            json.dumps({
                "total_incidents": 1,
                "incidents": [{"incident_id": "INC-TEST"}],
            }),
            encoding="utf-8",
        )

        snapshot = dashboard.make_snapshot()

        self.assertEqual(snapshot["summary"]["total_events"], 12)
        self.assertEqual(snapshot["alerts"]["total_alerts"], 1)
        self.assertEqual(snapshot["incident_total"], 1)
        self.assertEqual(snapshot["incidents"][0]["incident_id"], "INC-TEST")

    def test_demo_snapshot_reads_synthetic_files_and_redacts_commands(self):
        events = [
            {"timestamp": "2026-11-10T01:00:00Z", "event_type": "cowrie.login.failed", "source_ip": "203.0.113.10", "session_id": "sim-a", "protocol": "ssh", "command": "never expose this"},
            {"timestamp": "2026-11-10T01:06:00Z", "event_type": "cowrie.login.success", "source_ip": "203.0.113.10", "session_id": "sim-a", "protocol": "ssh"},
        ]
        (dashboard.DATA_DIR / "simulated_campaign.jsonl").write_text(
            "\n".join(json.dumps(row) for row in events) + "\n", encoding="utf-8"
        )
        (dashboard.DATA_DIR / "simulated_alerts.json").write_text(json.dumps({
            "alerts": [{"rule_id": "authentication.failure_then_success", "severity": "high", "source_ip": "203.0.113.10", "description": "Failed logins followed by success", "command": "do not leak"}]
        }), encoding="utf-8")
        (dashboard.DATA_DIR / "incidents.json").write_text(json.dumps({
            "incidents": [{"incident_id": "INC-DEMO", "severity": "high", "source_ip": "203.0.113.10", "attack_patterns": ["authentication.failure_then_success"], "alerts": [{"rule_id": "authentication.failure_then_success", "description": "Failed logins followed by success", "command": "do not leak"}]}]
        }), encoding="utf-8")

        snapshot = dashboard.make_demo_snapshot()
        self.assertEqual(snapshot["data_source"], "Synthetic local demo")
        self.assertEqual(snapshot["summary"]["total_events"], 2)
        self.assertEqual(snapshot["summary"]["unique_source_ips"], 1)
        self.assertEqual(snapshot["alerts"]["total_alerts"], 1)
        self.assertEqual(snapshot["incident_total"], 1)
        serialized = json.dumps(snapshot)
        self.assertNotIn("never expose this", serialized)
        self.assertNotIn("do not leak", serialized)
        self.assertNotIn('"command"', serialized)

    def test_dynamodb_snapshot_aggregates_safe_fields(self):
        events = [
            {
                "timestamp": "2026-11-10T00:00:00Z",
                "event_type": "cowrie.login.failed",
                "source_ip": "203.0.113.10",
                "session_id": "session-a",
                "protocol": "ssh",
                "auth_result": "failed",
                "password": "secret",
            },
            {
                "timestamp": "2026-11-10T00:01:00Z",
                "event_type": "cowrie.command.input",
                "source_ip": "203.0.113.10",
                "session_id": "session-a",
                "protocol": "ssh",
                "command": "private command",
            },
        ]
        alerts = [{
            "alert_id": "alert-1",
            "rule_id": "authentication.brute_force",
            "severity": "high",
            "source_ip": "203.0.113.10",
            "occurred_at": "2026-11-10T00:01:00Z",
            "failed_attempts": Decimal("5"),
            "threshold": Decimal("5"),
            "password": "must-not-leak",
        }]
        incidents = [{
            "incident_id": "INC-1",
            "severity": "high",
            "source_ip": "203.0.113.10",
            "first_seen": "2026-11-10T00:00:00Z",
            "last_seen": "2026-11-10T00:01:00Z",
            "duration_seconds": Decimal("60"),
            "alert_count": Decimal("1"),
            "alerts": [{"command": "must-not-leak"}],
        }]

        snapshot = dashboard.assemble_dynamodb_snapshot(
            events,
            alerts,
            incidents,
        )

        self.assertEqual(snapshot["data_source"], "LocalStack DynamoDB")
        self.assertEqual(snapshot["summary"]["total_events"], 2)
        self.assertEqual(snapshot["summary"]["unique_source_ips"], 1)
        self.assertEqual(snapshot["summary"]["login_attempts"]["failed"], 1)
        self.assertEqual(snapshot["summary"]["commands_observed"], 1)
        self.assertEqual(snapshot["alerts"]["total_alerts"], 1)
        self.assertEqual(snapshot["incident_total"], 1)
        self.assertIs(type(snapshot["alerts"]["alerts"][0]["failed_attempts"]), int)
        self.assertIs(type(snapshot["incidents"][0]["duration_seconds"]), int)

        serialized = json.dumps(snapshot)
        self.assertNotIn("must-not-leak", serialized)
        self.assertNotIn("private command", serialized)
        self.assertNotIn('"password"', serialized)
        self.assertNotIn('"command"', serialized)

    def test_dynamodb_snapshot_does_not_include_unapproved_fields(self):
        snapshot = dashboard.assemble_dynamodb_snapshot(
            [{
                "timestamp": "2026-11-10T00:00:00Z",
                "event_type": "cowrie.session.connect",
                "source_ip": "192.0.2.1",
                "session_id": "session-b",
                "protocol": "ssh",
                "source_object": "internal-bucket/path",
                "command_sha256": "private-hash",
                "username": "root",
            }],
            [],
            [],
        )

        event = snapshot["recent_events"][0]
        self.assertEqual(
            set(event),
            {"timestamp", "event_type", "source_ip", "session_id", "protocol"},
        )
        self.assertNotIn("private-hash", json.dumps(snapshot))
        self.assertNotIn("internal-bucket", json.dumps(snapshot))


if __name__ == "__main__":
    unittest.main()
