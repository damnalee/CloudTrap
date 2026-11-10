import json
import sys
import tempfile
import unittest

from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1])
)

from app.process_cowrie import (
    normalize_event,
    sanitize_command,
    load_events,
    generate_summary,
)


class TestCloudTrapProcessor(unittest.TestCase):

    def test_successful_login(self):
        raw = {
            "eventid": "cowrie.login.success",
            "session": "test123",
            "src_ip": "192.168.1.10",
            "protocol": "ssh",
            "username": "root",
            "password": "secret123",
            "timestamp": "2026-11-10T00:00:00Z",
            "message": "login succeeded"
        }

        event = normalize_event(raw)

        self.assertEqual(event["auth_result"], "success")
        self.assertEqual(event["username"], "root")
        self.assertTrue(event["password_attempted"])
        self.assertNotIn("password", event)
        self.assertNotIn("message", event)

    def test_failed_login(self):
        raw = {
            "eventid": "cowrie.login.failed",
            "username": "admin",
            "password": "123456"
        }

        event = normalize_event(raw)

        self.assertEqual(event["auth_result"], "failed")
        self.assertNotIn("password", event)

    def test_command_capture(self):
        raw = {
            "eventid": "cowrie.command.input",
            "input": "whoami"
        }

        event = normalize_event(raw)

        self.assertEqual(event["command"], "whoami")

    def test_secret_redaction(self):
        command = "export API_KEY=abc123"

        result = sanitize_command(command)

        self.assertNotIn("abc123", result)
        self.assertIn("[REDACTED]", result)

    def test_unknown_event_does_not_copy_raw_fields(self):
        raw = {
            "eventid": "unknown.event",
            "password": "secret123",
            "message": "sensitive message"
        }

        event = normalize_event(raw)

        self.assertNotIn("password", event)
        self.assertNotIn("message", event)

    def test_malformed_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.json"

            path.write_text(
                '{"eventid":"cowrie.session.connect"}\n'
                'invalid json\n',
                encoding="utf-8"
            )

            events, malformed = load_events(path)

            self.assertEqual(len(events), 1)
            self.assertEqual(malformed, 1)

    def test_summary_counts(self):
        events = [
            {
                "event_type": "cowrie.login.success",
                "source_ip": "192.168.1.10",
                "session_id": "abc"
            },
            {
                "event_type": "cowrie.command.input",
                "source_ip": "192.168.1.10",
                "session_id": "abc"
            }
        ]

        summary = generate_summary(events, 0, Path("test.json"))

        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["unique_sessions"], 1)
        self.assertEqual(summary["unique_source_ips"], 1)
        self.assertEqual(summary["commands_observed"], 1)


if __name__ == "__main__":
    unittest.main()
