import importlib.util
import json
import tempfile
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


if __name__ == "__main__":
    unittest.main()
