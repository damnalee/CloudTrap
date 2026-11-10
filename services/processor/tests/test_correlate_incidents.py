import sys
import unittest

from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1])
)

from app.correlate_incidents import correlate_alerts


def make_alert(ip, minute, rule, severity="medium", **extra):
    return {
        "rule_id": rule,
        "severity": severity,
        "source_ip": ip,
        "session_id": "test-session",
        "occurred_at": f"2026-11-10T01:{minute:02d}:00Z",
        "description": "Simulated test alert",
        **extra,
    }


class TestIncidentCorrelation(unittest.TestCase):

    def test_same_ip_alerts_are_grouped(self):
        alerts = [
            make_alert("203.0.113.10", 0, "authentication.brute_force"),
            make_alert("203.0.113.10", 6, "authentication.failure_then_success"),
        ]

        result = correlate_alerts(alerts)

        self.assertEqual(result["total_incidents"], 1)
        self.assertEqual(result["incidents"][0]["alert_count"], 2)

    def test_different_ips_create_separate_incidents(self):
        alerts = [
            make_alert("203.0.113.10", 0, "authentication.brute_force"),
            make_alert("198.51.100.24", 5, "suspicious.persistence_attempt"),
        ]

        result = correlate_alerts(alerts)

        self.assertEqual(result["total_incidents"], 2)

    def test_alerts_outside_window_are_separated(self):
        alerts = [
            make_alert("203.0.113.10", 0, "authentication.brute_force"),
            make_alert("203.0.113.10", 31, "authentication.brute_force"),
        ]

        result = correlate_alerts(alerts)

        self.assertEqual(result["total_incidents"], 2)

    def test_incident_uses_highest_severity(self):
        alerts = [
            make_alert("198.51.100.24", 0, "persistence", "medium"),
            make_alert("198.51.100.24", 2, "remote_execution", "high"),
        ]

        result = correlate_alerts(alerts)

        self.assertEqual(
            result["incidents"][0]["severity"],
            "high",
        )

    def test_invalid_alert_is_skipped(self):
        alerts = [
            make_alert("203.0.113.10", 0, "test"),
            {"rule_id": "invalid", "occurred_at": "not-a-date"},
        ]

        result = correlate_alerts(alerts)

        self.assertEqual(result["alerts_received"], 2)
        self.assertEqual(result["alerts_skipped"], 1)
        self.assertEqual(result["total_incidents"], 1)

    def test_incident_ids_are_deterministic(self):
        alerts = [
            make_alert("203.0.113.10", 0, "authentication.brute_force")
        ]

        first = correlate_alerts(alerts)
        second = correlate_alerts(alerts)

        self.assertEqual(
            first["incidents"][0]["incident_id"],
            second["incidents"][0]["incident_id"],
        )

    def test_sensitive_fields_are_not_copied(self):
        alerts = [
            make_alert(
                "203.0.113.10",
                0,
                "authentication.brute_force",
                password="super-secret-password",
                command="sensitive captured command",
            )
        ]

        result = correlate_alerts(alerts)
        serialized = str(result)

        self.assertNotIn("super-secret-password", serialized)
        self.assertNotIn("sensitive captured command", serialized)

    def test_empty_alert_list(self):
        result = correlate_alerts([])

        self.assertEqual(result["total_incidents"], 0)
        self.assertEqual(result["alerts_received"], 0)


if __name__ == "__main__":
    unittest.main()
