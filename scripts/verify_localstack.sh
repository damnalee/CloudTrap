#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "[1/6] Checking local service endpoints"
curl -fsS http://127.0.0.1:4566/_localstack/health >/dev/null
curl -fsS http://127.0.0.1:8501/ >/dev/null
echo "  LocalStack and dashboard endpoints respond."

echo "[2/6] Checking Lambda state and SQS mapping"
LAMBDA_STATE="$(docker compose exec -T localstack awslocal lambda get-function-configuration --function-name CloudTrapIngest --query State --output text | tr -d '\r')"
MAPPING_STATE="$(docker compose exec -T localstack awslocal lambda list-event-source-mappings --function-name CloudTrapIngest --query 'EventSourceMappings[0].State' --output text | tr -d '\r')"
[[ "$LAMBDA_STATE" == "Active" ]]
[[ "$MAPPING_STATE" == "Enabled" ]]
echo "  Lambda: $LAMBDA_STATE; SQS mapping: $MAPPING_STATE"

echo "[3/6] Checking required DynamoDB tables"
TABLES="$(docker compose exec -T localstack awslocal dynamodb list-tables --query 'TableNames' --output json)"
python3 -c 'import json,sys; required={"CloudTrapEvents","CloudTrapAlerts","CloudTrapIncidents"}; present=set(json.loads(sys.argv[1])); missing=required-present; print("  Tables:", ", ".join(sorted(present))); sys.exit(bool(missing))' "$TABLES"

echo "[4/6] Checking stored event fields for secrets"
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT
docker compose exec -T localstack awslocal dynamodb scan --table-name CloudTrapEvents --output json > "$TMP_FILE"
python3 - "$TMP_FILE" <<'PY'
import json
import sys

items = json.load(open(sys.argv[1], encoding="utf-8")).get("Items", [])
sensitive = {"password", "username", "command", "message", "input"}
found = sorted({key for item in items for key in item if key in sensitive})
print(f"  Events stored: {len(items)}")
if found:
    print("  ERROR: sensitive fields present:", ", ".join(found))
    raise SystemExit(1)
print("  No password, username, raw command, message or input attributes found.")
PY

echo "[5/6] Checking CloudWatch metrics"
METRICS="$(docker compose exec -T localstack awslocal cloudwatch list-metrics --namespace CloudTrap --query 'Metrics[].MetricName' --output json)"
python3 -c 'import json,sys; values=set(json.loads(sys.argv[1])); expected={"EventsProcessed","AlertsGenerated","HighSeverityAlerts","IncidentsGenerated","MalformedLines"}; missing=expected-values; print("  Metrics:", ", ".join(sorted(values))); sys.exit(bool(missing))' "$METRICS"

echo "[6/6] Checking queue and dead-letter queue"
QUEUE_URL="http://localhost:4566/000000000000/cloudtrap-ingest"
DLQ_URL="http://localhost:4566/000000000000/cloudtrap-ingest-dlq"
docker compose exec -T localstack awslocal sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible --output json
docker compose exec -T localstack awslocal sqs get-queue-attributes --queue-url "$DLQ_URL" --attribute-names ApproximateNumberOfMessages --output json

echo "CloudTrap local AWS verification complete."
