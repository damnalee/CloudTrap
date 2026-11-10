#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT/infra/terraform"
TF=(terraform -chdir="$TF_DIR")
export TF_VAR_localstack_endpoint="http://localhost:4566"

if ! curl -fsS --max-time 3 http://localhost:4566/_localstack/health >/dev/null; then
  echo "LocalStack is not healthy at localhost:4566. Start it with: make stack-up" >&2
  exit 1
fi

import_if_missing() {
  local address="$1" id="$2"
  local state
  state="$("${TF[@]}" state list 2>/dev/null || true)"
  if printf '%s\n' "$state" | grep -Fxq "$address"; then
    echo "[state] already tracked: $address"
  else
    echo "[import] $address"
    "${TF[@]}" import "$address" "$id"
  fi
}

# This imports the resources created by the earlier LocalStack bootstrap.
# It does not delete or recreate them; Terraform takes ownership of their state.
if docker exec cloudtrap-localstack awslocal s3api head-bucket --bucket cloudtrap-raw-logs >/dev/null 2>&1; then
  import_if_missing aws_s3_bucket.raw_logs cloudtrap-raw-logs
  import_if_missing aws_s3_bucket_notification.raw_logs cloudtrap-raw-logs
fi

for pair in \
  'aws_sqs_queue.ingest|https://sqs.us-east-1.amazonaws.com/000000000000/cloudtrap-ingest' \
  'aws_sqs_queue.dlq|https://sqs.us-east-1.amazonaws.com/000000000000/cloudtrap-ingest-dlq'; do
  address="${pair%%|*}"; id="${pair#*|}"
  if [[ "$address" == *ingest ]]; then queue="cloudtrap-ingest"; else queue="cloudtrap-ingest-dlq"; fi
  if docker exec cloudtrap-localstack awslocal sqs get-queue-url --queue-name "$queue" >/dev/null 2>&1; then import_if_missing "$address" "$id"; fi
  if [[ "$queue" == "cloudtrap-ingest" ]]; then import_if_missing aws_sqs_queue_policy.allow_s3 "$id"; fi
done

for table in events:CloudTrapEvents alerts:CloudTrapAlerts incidents:CloudTrapIncidents; do
  address="${table%%:*}"; name="${table#*:}"
  if docker exec cloudtrap-localstack awslocal dynamodb describe-table --table-name "$name" >/dev/null 2>&1; then
    import_if_missing "aws_dynamodb_table.$address" "$name"
  fi
done

TOPIC="arn:aws:sns:us-east-1:000000000000:cloudtrap-threat-alerts"
if docker exec cloudtrap-localstack awslocal sns get-topic-attributes --topic-arn "$TOPIC" >/dev/null 2>&1; then import_if_missing aws_sns_topic.alerts "$TOPIC"; fi

if docker exec cloudtrap-localstack awslocal iam get-role --role-name cloudtrap-lambda-role >/dev/null 2>&1; then
  import_if_missing aws_iam_role.lambda cloudtrap-lambda-role
  if docker exec cloudtrap-localstack awslocal iam get-role-policy --role-name cloudtrap-lambda-role --policy-name CloudTrapIngestPolicy >/dev/null 2>&1; then
    import_if_missing aws_iam_role_policy.lambda cloudtrap-lambda-role:CloudTrapIngestPolicy
  fi
fi

if docker exec cloudtrap-localstack awslocal lambda get-function --function-name CloudTrapIngest >/dev/null 2>&1; then
  import_if_missing aws_lambda_function.ingest CloudTrapIngest
  mapping="$(docker exec cloudtrap-localstack awslocal lambda list-event-source-mappings --function-name CloudTrapIngest --query 'EventSourceMappings[0].UUID' --output text)"
  if [[ -n "$mapping" && "$mapping" != "None" ]]; then import_if_missing aws_lambda_event_source_mapping.sqs "$mapping"; fi
fi

if docker exec cloudtrap-localstack awslocal logs describe-log-groups --log-group-name-prefix /aws/lambda/CloudTrapIngest --query 'logGroups[0].logGroupName' --output text | grep -q CloudTrapIngest; then
  import_if_missing aws_cloudwatch_log_group.lambda /aws/lambda/CloudTrapIngest
fi

echo "[CloudTrap] Existing LocalStack resources imported. Review with: make infra-plan"
