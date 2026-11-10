"""AWS Lambda consumer for CloudTrap S3 -> SQS -> Lambda ingestion."""

import hashlib
import json
import os
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import boto3
from botocore.exceptions import ClientError

from process_cowrie import normalize_event
from detect_threats import detect_threats
from correlate_incidents import correlate_alerts


REGION = os.environ.get("AWS_REGION", "us-east-1")
ENDPOINT_URL = os.environ.get("CLOUDTRAP_ENDPOINT_URL") or None
RAW_BUCKET = os.environ.get("RAW_BUCKET_NAME", "cloudtrap-raw-logs")
EVENTS_TABLE = os.environ.get("EVENTS_TABLE", "CloudTrapEvents")
ALERTS_TABLE = os.environ.get("ALERTS_TABLE", "CloudTrapAlerts")
INCIDENTS_TABLE = os.environ.get("INCIDENTS_TABLE", "CloudTrapIncidents")
TOPIC_ARN = os.environ.get("ALERTS_TOPIC_ARN", "")
MAX_OBJECT_BYTES = int(os.environ.get("MAX_OBJECT_BYTES", "26214400"))


def aws_client(service):
    return boto3.client(
        service,
        region_name=REGION,
        endpoint_url=ENDPOINT_URL,
    )


def aws_resource(service):
    return boto3.resource(
        service,
        region_name=REGION,
        endpoint_url=ENDPOINT_URL,
    )


def stable_id(*parts):
    joined = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def parse_cowrie_jsonl(content):
    """Parse newline-delimited Cowrie JSON and normalize through the shared processor."""
    events = []
    malformed = 0

    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue

        if not isinstance(raw, dict):
            malformed += 1
            continue

        if "eventid" in raw:
            # Raw Cowrie JSONL: normalize it using the shared local processor.
            event = normalize_event(raw)
        elif isinstance(raw.get("event_type"), str):
            # CloudTrap-normalized JSONL: preserve the safe schema fields needed
            # for detection. These values remain transient in Lambda memory;
            # DynamoDB storage below applies a stricter metadata-only whitelist.
            event = {
                "timestamp": raw.get("timestamp"),
                "session_id": raw.get("session_id") or raw.get("session"),
                "event_type": raw.get("event_type"),
                "source_ip": raw.get("source_ip") or raw.get("src_ip"),
                "protocol": raw.get("protocol"),
            }
            for field in (
                "auth_result",
                "password_attempted",
                "duration_ms",
                "username",
                "command",
            ):
                if raw.get(field) is not None:
                    event[field] = raw[field]
        else:
            malformed += 1
            continue

        if not event.get("timestamp") or not event.get("event_type"):
            malformed += 1
            continue

        events.append(event)

    return events, malformed


def put_once(table, key_name, item):
    """Insert idempotently; return False if the deterministic ID already exists."""
    try:
        table.put_item(
            Item=item,
            ConditionExpression=f"attribute_not_exists({key_name})",
        )
        return True
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return False
        raise


def store_safe_event(table, event, bucket, object_key):
    """Store event metadata, but never store password or command contents."""
    event_id = stable_id(
        event.get("session_id"),
        event.get("timestamp"),
        event.get("event_type"),
        event.get("source_ip"),
    )

    item = {
        "event_id": event_id,
        "timestamp": str(event.get("timestamp", "")),
        "event_type": str(event.get("event_type", "unknown")),
        "source_ip": str(event.get("source_ip", "unknown")),
        "session_id": str(event.get("session_id", "unknown")),
        "protocol": str(event.get("protocol", "unknown")),
        "source_bucket": bucket,
        "source_object": object_key,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }

    for field in ("auth_result", "password_attempted", "duration_ms"):
        value = event.get(field)
        if value is not None and isinstance(value, (str, int, bool)):
            item[field] = value

    # Intentionally omit username and command text from persistent cloud storage.
    if event.get("event_type") == "cowrie.command.input":
        command = event.get("command")
        if isinstance(command, str):
            item["command_sha256"] = hashlib.sha256(
                command.encode("utf-8")
            ).hexdigest()

    return put_once(table, "event_id", item)


def process_s3_object(bucket, key):
    if bucket != RAW_BUCKET:
        raise ValueError(f"Unexpected source bucket: {bucket}")

    s3 = aws_client("s3")
    response = s3.get_object(Bucket=bucket, Key=key)
    content_length = response.get("ContentLength", 0)

    if content_length > MAX_OBJECT_BYTES:
        raise ValueError(
            f"S3 object exceeds the {MAX_OBJECT_BYTES}-byte processing limit"
        )

    body = response["Body"].read()
    if len(body) > MAX_OBJECT_BYTES:
        raise ValueError("Downloaded S3 object exceeds processing limit")

    text = body.decode("utf-8", errors="replace")
    events, malformed = parse_cowrie_jsonl(text)

    dynamodb = aws_resource("dynamodb")
    events_table = dynamodb.Table(EVENTS_TABLE)
    alerts_table = dynamodb.Table(ALERTS_TABLE)
    incidents_table = dynamodb.Table(INCIDENTS_TABLE)

    stored_events = 0
    duplicate_events = 0

    for event in events:
        if store_safe_event(events_table, event, bucket, key):
            stored_events += 1
        else:
            duplicate_events += 1

    alerts = detect_threats(events)
    stored_alerts = 0
    high_severity_alerts = 0
    notified_alerts = 0
    sns = aws_client("sns") if TOPIC_ARN else None

    for alert in alerts:
        alert_id = stable_id(
            alert.get("rule_id"),
            alert.get("source_ip"),
            alert.get("session_id"),
            alert.get("occurred_at"),
        )
        item = {"alert_id": alert_id, **alert}

        inserted = put_once(alerts_table, "alert_id", item)
        if not inserted:
            continue

        stored_alerts += 1

        if alert.get("severity") in ("high", "critical"):
            high_severity_alerts += 1

        if sns and alert.get("severity") in ("high", "critical"):
            message = {
                "project": "CloudTrap",
                "severity": alert.get("severity"),
                "source_ip": alert.get("source_ip"),
                "rule_id": alert.get("rule_id"),
                "occurred_at": alert.get("occurred_at"),
                "description": alert.get("description"),
                "alert_id": alert_id,
            }
            sns.publish(
                TopicArn=TOPIC_ARN,
                Subject="CloudTrap high-severity threat alert",
                Message=json.dumps(message, ensure_ascii=False),
            )
            notified_alerts += 1

    incident_result = correlate_alerts(alerts, window_minutes=30)
    stored_incidents = 0

    for incident in incident_result.get("incidents", []):
        incident_item = dict(incident)
        inserted = put_once(
            incidents_table,
            "incident_id",
            incident_item,
        )
        if inserted:
            stored_incidents += 1

    metrics = aws_client("cloudwatch")
    metrics.put_metric_data(
        Namespace="CloudTrap",
        MetricData=[
            {
                "MetricName": "EventsProcessed",
                "Unit": "Count",
                "Value": stored_events,
            },
            {
                "MetricName": "AlertsGenerated",
                "Unit": "Count",
                "Value": stored_alerts,
            },
            {
                "MetricName": "HighSeverityAlerts",
                "Unit": "Count",
                "Value": high_severity_alerts,
            },
            {
                "MetricName": "IncidentsGenerated",
                "Unit": "Count",
                "Value": stored_incidents,
            },
            {
                "MetricName": "MalformedLines",
                "Unit": "Count",
                "Value": malformed,
            },
        ],
    )

    # Log only aggregate counts. Do not log raw lines, passwords or commands.
    print(json.dumps({
        "status": "processed",
        "bucket": bucket,
        "object_key": key,
        "events_parsed": len(events),
        "events_stored": stored_events,
        "duplicate_events": duplicate_events,
        "malformed_lines": malformed,
        "alerts_detected": len(alerts),
        "alerts_stored": stored_alerts,
        "high_severity_alerts": high_severity_alerts,
        "alerts_notified": notified_alerts,
        "incidents_stored": stored_incidents,
    }))

    return {
        "events_parsed": len(events),
        "events_stored": stored_events,
        "duplicate_events": duplicate_events,
        "malformed_lines": malformed,
        "alerts_detected": len(alerts),
        "alerts_stored": stored_alerts,
        "high_severity_alerts": high_severity_alerts,
        "incidents_stored": stored_incidents,
    }


def lambda_handler(event, context):
    failures = []

    for record in event.get("Records", []):
        message_id = record.get("messageId")
        try:
            body = json.loads(record.get("body", "{}"))

            # S3 sends a one-time test notification when bucket notifications
            # are configured. It is not an object event and should be acked.
            if body.get("Event") == "s3:TestEvent":
                print(json.dumps({
                    "status": "ignored_s3_test_event",
                    "message_id": message_id,
                }))
                continue

            s3_records = body.get("Records", [])
            if not s3_records:
                raise ValueError("SQS body did not contain S3 event records")

            for s3_record in s3_records:
                s3_info = s3_record.get("s3", {})
                bucket = s3_info.get("bucket", {}).get("name")
                key = unquote_plus(
                    s3_info.get("object", {}).get("key", "")
                )

                if not bucket or not key:
                    raise ValueError("S3 event is missing bucket or object key")

                process_s3_object(bucket, key)

        except Exception as error:
            print(json.dumps({
                "status": "failed",
                "message_id": message_id,
                "error_type": type(error).__name__,
            }))
            if message_id:
                failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": failures}
