#!/usr/bin/env bash
set -euo pipefail

REGION="$AWS_DEFAULT_REGION"
if [[ -z "$REGION" ]]; then REGION="us-east-1"; fi
ACCOUNT_ID="000000000000"
BUCKET="cloudtrap-raw-logs"
QUEUE_NAME="cloudtrap-ingest"
DLQ_NAME="cloudtrap-ingest-dlq"
FUNCTION_NAME="CloudTrapIngest"
ROLE_NAME="cloudtrap-lambda-role"
EVENTS_TABLE="CloudTrapEvents"
ALERTS_TABLE="CloudTrapAlerts"
INCIDENTS_TABLE="CloudTrapIncidents"
TOPIC_NAME="cloudtrap-threat-alerts"

ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$ROLE_NAME"

echo "[CloudTrap] Bootstrapping LocalStack resources in $REGION"

# S3 raw-log archive
awslocal s3 mb "s3://$BUCKET" --region "$REGION" >/dev/null 2>&1 || true

# SQS input queue and dead-letter queue
DLQ_URL="$(awslocal sqs create-queue --queue-name "$DLQ_NAME" --query QueueUrl --output text)"
DLQ_ARN="$(awslocal sqs get-queue-attributes --queue-url "$DLQ_URL" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)"

QUEUE_URL="$(awslocal sqs create-queue --queue-name "$QUEUE_NAME" --query QueueUrl --output text)"
QUEUE_ARN="$(awslocal sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)"

REDRIVE_POLICY="$(python3 -c 'import json,sys; print(json.dumps({"deadLetterTargetArn":sys.argv[1],"maxReceiveCount":"3"}))' "$DLQ_ARN")"
QUEUE_ATTRIBUTES="$(python3 -c 'import json,sys; print(json.dumps({"RedrivePolicy":sys.argv[1],"VisibilityTimeout":"360"}))' "$REDRIVE_POLICY")"
awslocal sqs set-queue-attributes --queue-url "$QUEUE_URL" --attributes "$QUEUE_ATTRIBUTES" >/dev/null

# Allow only S3 notifications originating from this bucket to enter the queue.
QUEUE_POLICY="$(python3 - "$QUEUE_ARN" "$BUCKET" "$ACCOUNT_ID" <<'PY'
import json
import sys
queue_arn, bucket, account = sys.argv[1:]
print(json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "AllowCloudTrapS3Notifications",
        "Effect": "Allow",
        "Principal": {"Service": "s3.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue_arn,
        "Condition": {
            "ArnLike": {"aws:SourceArn": "arn:aws:s3:::" + bucket},
            "StringEquals": {"aws:SourceAccount": account}
        }
    }]
}))
PY
)"
QUEUE_POLICY_ATTRIBUTES="$(python3 -c 'import json,sys; print(json.dumps({"Policy":sys.argv[1]}))' "$QUEUE_POLICY")"
awslocal sqs set-queue-attributes --queue-url "$QUEUE_URL" --attributes "$QUEUE_POLICY_ATTRIBUTES" >/dev/null

# Idempotently create the three durable data tables.
if ! awslocal dynamodb describe-table --table-name "$EVENTS_TABLE" >/dev/null 2>&1; then
  awslocal dynamodb create-table \
    --table-name "$EVENTS_TABLE" \
    --attribute-definitions AttributeName=event_id,AttributeType=S \
    --key-schema AttributeName=event_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST >/dev/null
fi

if ! awslocal dynamodb describe-table --table-name "$ALERTS_TABLE" >/dev/null 2>&1; then
  awslocal dynamodb create-table \
    --table-name "$ALERTS_TABLE" \
    --attribute-definitions AttributeName=alert_id,AttributeType=S \
    --key-schema AttributeName=alert_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST >/dev/null
fi

if ! awslocal dynamodb describe-table --table-name "$INCIDENTS_TABLE" >/dev/null 2>&1; then
  awslocal dynamodb create-table \
    --table-name "$INCIDENTS_TABLE" \
    --attribute-definitions AttributeName=incident_id,AttributeType=S \
    --key-schema AttributeName=incident_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST >/dev/null
fi

awslocal dynamodb wait table-exists --table-name "$EVENTS_TABLE"
awslocal dynamodb wait table-exists --table-name "$ALERTS_TABLE"
awslocal dynamodb wait table-exists --table-name "$INCIDENTS_TABLE"

# SNS topic receives new high-severity alert notifications.
TOPIC_ARN="$(awslocal sns create-topic --name "$TOPIC_NAME" --query TopicArn --output text)"

# Least-privilege execution role for the ingestion Lambda.
TRUST_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document "$TRUST_POLICY" >/dev/null 2>&1 || true

ROLE_POLICY="$(python3 - "$BUCKET" "$QUEUE_ARN" "$EVENTS_TABLE" "$ALERTS_TABLE" "$INCIDENTS_TABLE" "$TOPIC_ARN" <<'PY'
import json
import sys
bucket, queue_arn, events_table, alerts_table, incidents_table, topic = sys.argv[1:]
region = "us-east-1"
account = "000000000000"
resources = [
    "arn:aws:s3:::" + bucket + "/*",
    queue_arn,
    "arn:aws:dynamodb:" + region + ":" + account + ":table/" + events_table,
    "arn:aws:dynamodb:" + region + ":" + account + ":table/" + alerts_table,
    "arn:aws:dynamodb:" + region + ":" + account + ":table/" + incidents_table,
    topic,
]
print(json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [resources[0]]},
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], "Resource": [resources[1]]},
        {"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": resources[2:5]},
        {"Effect": "Allow", "Action": ["sns:Publish"], "Resource": [resources[5]]},
        {"Effect": "Allow", "Action": ["cloudwatch:PutMetricData"], "Resource": ["*"]},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": ["*"]}
    ]
}))
PY
)"
awslocal iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name CloudTrapIngestPolicy \
  --policy-document "$ROLE_POLICY" >/dev/null

# Package the same normalization/detection/correlation modules used locally.
PACKAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$PACKAGE_DIR" /tmp/cloudtrap-ingest.zip' EXIT
cp /opt/lambda-src/lambda/lambda_function.py "$PACKAGE_DIR/"
cp /opt/lambda-src/processor/process_cowrie.py "$PACKAGE_DIR/"
cp /opt/lambda-src/processor/detect_threats.py "$PACKAGE_DIR/"
cp /opt/lambda-src/processor/correlate_incidents.py "$PACKAGE_DIR/"
(cd "$PACKAGE_DIR" && zip -q -r /tmp/cloudtrap-ingest.zip .)

LAMBDA_ENVIRONMENT="$(python3 - "$TOPIC_ARN" <<'PY'
import json
import sys
print(json.dumps({"Variables": {
    "CLOUDTRAP_ENDPOINT_URL": "http://localstack:4566",
    "RAW_BUCKET_NAME": "cloudtrap-raw-logs",
    "EVENTS_TABLE": "CloudTrapEvents",
    "ALERTS_TABLE": "CloudTrapAlerts",
    "INCIDENTS_TABLE": "CloudTrapIncidents",
    "ALERTS_TOPIC_ARN": sys.argv[1],
    "MAX_OBJECT_BYTES": "26214400"
}}))
PY
)"

if awslocal lambda get-function --function-name "$FUNCTION_NAME" >/dev/null 2>&1; then
  awslocal lambda update-function-code \
    --function-name "$FUNCTION_NAME" \
    --zip-file fileb:///tmp/cloudtrap-ingest.zip >/dev/null
  awslocal lambda update-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --environment "$LAMBDA_ENVIRONMENT" \
    --timeout 60 \
    --memory-size 256 >/dev/null
else
  awslocal lambda create-function \
    --function-name "$FUNCTION_NAME" \
    --runtime python3.13 \
    --role "$ROLE_ARN" \
    --handler lambda_function.lambda_handler \
    --zip-file fileb:///tmp/cloudtrap-ingest.zip \
    --timeout 60 \
    --memory-size 256 \
    --environment "$LAMBDA_ENVIRONMENT" \
    --region "$REGION" >/dev/null
fi

awslocal lambda wait function-active-v2 --function-name "$FUNCTION_NAME"

# Connect SQS to Lambda; avoid duplicate event source mappings on restarts.
MAPPINGS="$(awslocal lambda list-event-source-mappings --function-name "$FUNCTION_NAME" --output json)"
if ! printf '%s' "$MAPPINGS" | grep -q "$QUEUE_ARN"; then
  awslocal lambda create-event-source-mapping \
    --function-name "$FUNCTION_NAME" \
    --event-source-arn "$QUEUE_ARN" \
    --batch-size 5 \
    --function-response-types ReportBatchItemFailures \
    --region "$REGION" >/dev/null
fi

# S3 sends JSON object-created events to SQS; the queue activates Lambda.
NOTIFICATION_CONFIG="$(python3 - "$QUEUE_ARN" <<'PY'
import json
import sys
print(json.dumps({
    "QueueConfigurations": [{
        "QueueArn": sys.argv[1],
        "Events": ["s3:ObjectCreated:*"],
        "Filter": {
            "Key": {
                "FilterRules": [{"Name": "suffix", "Value": ".json"}]
            }
        }
    }]
}))
PY
)"
awslocal s3api put-bucket-notification-configuration \
  --bucket "$BUCKET" \
  --notification-configuration "$NOTIFICATION_CONFIG" >/dev/null

echo "[CloudTrap] Local AWS pipeline is ready:"
echo "  S3 bucket:     $BUCKET"
echo "  SQS queue:     $QUEUE_NAME (DLQ: $DLQ_NAME)"
echo "  Lambda:        $FUNCTION_NAME (python3.13)"
echo "  DynamoDB:      $EVENTS_TABLE, $ALERTS_TABLE, $INCIDENTS_TABLE"
echo "  SNS topic:     $TOPIC_NAME"
