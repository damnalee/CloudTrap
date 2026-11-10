# CloudTrap

CloudTrap is a local-first SSH honeypot and threat-analysis platform. It uses Cowrie to capture SSH interaction, converts Cowrie JSON events into credential-safe records, detects suspicious behaviour with transparent rules, correlates alerts into incidents, and presents the results in a local dashboard.

> **Safety:** CloudTrap is a security research prototype. Keep the honeypot bound to localhost while developing. Do not expose it to the public internet until the AWS network, IAM, egress, logging, and operational controls have been reviewed. Cowrie's raw logs can contain attempted passwords; never commit or publish raw logs.

## Current architecture

~~~text
SSH test client
    |
    v
Cowrie honeypot (Docker, localhost:2222)
    |
    v
data/cowrie/var/log/cowrie/cowrie.json  [raw; ignored by Git]
    |
    v
Python normalization (credential-safe whitelist)
    |
    +--> events.jsonl
    +--> summary.json
    |
    v
Rule-based threat detection
    |
    v
alerts.json
    |
    v
Incident correlation
    |
    v
incidents.json
    |
    v
Local dashboard (localhost:8501)
~~~

The local prototype uses Python's standard library for processing and the dashboard. Docker runs Cowrie and the dashboard. No AWS account is needed for local development.

## Requirements

- macOS with Docker Desktop running
- Docker Compose
- Python 3.10 or newer
- Git

## Start the honeypot

From the repository root:

~~~bash
docker compose up -d cowrie
docker compose ps
docker compose logs --tail=40 cowrie
~~~

Cowrie listens only on 127.0.0.1:2222. Create a local test session:

~~~bash
ssh -p 2222 root@127.0.0.1
~~~

Use a throwaway test password, then try benign commands such as whoami, uname -a, and id, followed by exit. Never type a real or reused password into the honeypot: Cowrie records attempted credentials in raw logs.

## Run the complete pipeline

After at least one SSH session:

~~~bash
python3 scripts/run_pipeline.py
~~~

Optional parameters:

~~~bash
python3 scripts/run_pipeline.py \
  --input data/cowrie/var/log/cowrie/cowrie.json \
  --output-dir data/processed \
  --brute-force-threshold 5 \
  --brute-force-window 5 \
  --correlation-window 30
~~~

Generated artifacts:

| File | Purpose |
|---|---|
| events.jsonl | Normalized events; password and raw message fields are not copied |
| summary.json | Event, session, IP and event-type counts |
| alerts.json | Rule-based suspicious-behaviour alerts |
| incidents.json | Alerts grouped by source IP and correlation window |

The processor deliberately uses a field whitelist. The dashboard API further restricts event fields and does not serve command text or username/password fields.

## Run a synthetic attack campaign

The simulation uses documentation-only IP ranges and synthetic events. It does not connect to or attack external hosts.

~~~bash
python3 scripts/generate_test_campaign.py
python3 services/processor/app/detect_threats.py \
  --input data/processed/simulated_campaign.jsonl \
  --output data/processed/simulated_alerts.json
python3 services/processor/app/correlate_incidents.py \
  --input data/processed/simulated_alerts.json \
  --output data/processed/incidents.json
~~~

Expected result: 9 synthetic events, 4 alerts, and 2 correlated incidents.

## Start the dashboard

Build and start the dashboard container:

~~~bash
docker compose up -d --build dashboard
docker compose ps
~~~

Open:

http://127.0.0.1:8501

The dashboard polls its local read-only data mount every 10 seconds. It shows event totals, source IP count, alert totals, incidents, severity filters, event distribution, and recent activity. It does not expose raw Cowrie logs.

To stop only the dashboard:

~~~bash
docker compose stop dashboard
~~~

To stop Cowrie:

~~~bash
docker compose stop cowrie
~~~

## Local AWS integration with LocalStack

CloudTrap includes a local AWS-style ingestion pipeline. It uses a pinned LocalStack Community image (`localstack/localstack:4.14.0`) because newer LocalStack images require an authentication token. This older image is for local development only and is not a current, security-maintained emulator release. Keep its gateway bound to localhost; do not expose port 4566 publicly.

Start LocalStack:

~~~bash
docker compose up -d localstack
docker compose ps
docker compose logs --tail=80 localstack
~~~

The ready hook provisions:

| Local AWS service | Purpose |
|---|---|
| S3 (`cloudtrap-raw-logs`) | Stores raw JSON objects |
| SQS (`cloudtrap-ingest`) | Buffers S3 object notifications |
| SQS DLQ (`cloudtrap-ingest-dlq`) | Holds messages that repeatedly fail |
| Lambda (`CloudTrapIngest`) | Parses, detects and correlates events |
| DynamoDB (`CloudTrapEvents`, `CloudTrapAlerts`, `CloudTrapIncidents`) | Stores credential-safe event, alert and incident records |
| SNS (`cloudtrap-threat-alerts`) | Receives high-severity alert notifications |
| CloudWatch | Receives aggregate processing metrics and Lambda logs |

Upload the synthetic campaign:

~~~bash
python3 scripts/generate_test_campaign.py
./scripts/upload_to_localstack.sh \
  data/processed/simulated_campaign.jsonl \
  simulated/demo-campaign.json
~~~

Upload the real Cowrie JSON log:

~~~bash
./scripts/upload_to_localstack.sh \
  data/cowrie/var/log/cowrie/cowrie.json \
  cowrie/local-session.json
~~~

S3 notifications enqueue the object event, SQS invokes Lambda, and Lambda writes safe metadata to DynamoDB. The Lambda accepts both raw Cowrie JSON records (`eventid`) and CloudTrap-normalized records (`event_type`). It does not write usernames, passwords, raw commands or raw messages to DynamoDB; command events retain a SHA-256 fingerprint only. High/critical alert notifications are published to the local SNS topic.

Inspect the tables:

~~~bash
docker compose exec localstack awslocal dynamodb scan \
  --table-name CloudTrapEvents --select COUNT
docker compose exec localstack awslocal dynamodb scan \
  --table-name CloudTrapAlerts --select COUNT
docker compose exec localstack awslocal dynamodb scan \
  --table-name CloudTrapIncidents --select COUNT
~~~

Inspect the CloudTrap metrics:

~~~bash
docker compose exec localstack awslocal cloudwatch list-metrics \
  --namespace CloudTrap
~~~

The dashboard reads the three LocalStack DynamoDB tables through Boto3 and displays their event, alert and incident records. It scans at most 1,000 rows per table, uses a strict response-field whitelist, and never returns credentials or raw command content. If LocalStack is unavailable, it falls back to the local `data/processed` JSON artifacts. The dashboard remains bound to `127.0.0.1:8501`; before adapting this scan-based prototype for production-scale AWS data, replace scans with indexed queries and add server-side caching.

LocalStack state in the selected Community image may be recreated when the container is recreated. The ready hook is idempotent and provisions the resources again, but test records may need to be regenerated and uploaded after a reset.

## AWS Terraform configuration (not deployed)

Terraform defines the real AWS ingestion/storage layer: private encrypted S3, SQS with a dead-letter queue, DynamoDB tables, Lambda, least-privilege execution permissions, SNS notifications, CloudWatch metrics/alarms and a CloudWatch dashboard. It does not yet provision the EC2 Cowrie sensor or a public honeypot network; that design needs an explicit exposure and egress review before deployment.

Build the Lambda archive and validate the Terraform configuration locally:

~~~bash
python3 scripts/package_lambda.py
$HOME/.local/bin/terraform fmt -check -recursive
$HOME/.local/bin/terraform -chdir=infra/terraform init -backend=false
$HOME/.local/bin/terraform -chdir=infra/terraform validate
~~~

These commands do not create AWS resources. A Terraform plan requires authenticated AWS credentials; an apply would create billable resources and must be reviewed and explicitly approved first. Copy `infra/terraform/terraform.tfvars.example` to `terraform.tfvars` only when preparing an actual deployment, and never commit the real tfvars file.

## Tests

Run all unit tests:

~~~bash
python3 -m unittest discover -s services/processor/tests -v
~~~

The suite covers normalization, credential-field exclusion, malformed records, threat rules, benign activity, and incident grouping. The Lambda-specific tests run inside LocalStack's Python environment:

~~~bash
docker compose exec -T localstack bash -lc \
  'PYTHONPATH=/opt/lambda-src/lambda:/opt/lambda-src/processor python -m unittest discover -s /opt/lambda-src/lambda -p test_lambda_local.py -v'
~~~

Run the local AWS configuration and data-safety checks:

~~~bash
./scripts/verify_localstack.sh
~~~

## Data and Git hygiene

- Raw Cowrie data under data/cowrie/ is ignored.
- Generated files under data/processed/ are ignored.
- Environment files, private keys and local Python environments are ignored.
- Do not commit real captured logs, passwords, downloaded malware samples, cloud credentials, or identifying incident exports.

Check before committing:

~~~bash
git status --short
git check-ignore -v data/cowrie/var/log/cowrie/cowrie.json
git check-ignore -v data/processed/incidents.json
~~~

## Roadmap

- [x] Local Cowrie honeypot
- [x] Credential-safe event normalization
- [x] Rule-based threat detection
- [x] Incident correlation
- [x] Synthetic attack campaign
- [x] Local dashboard
- [ ] Broader rule coverage and additional regression tests
- [x] Local AWS ingestion simulation (S3, SQS, Lambda, DynamoDB)
- [x] Local SNS notifications and CloudWatch metrics
- [x] Terraform AWS ingestion/storage configuration and validation
- [ ] EC2 Cowrie sensor, isolated VPC and egress controls
- [ ] Real AWS deployment after account, region, budget and exposure review

CloudTrap has been tested against LocalStack, not a real AWS account. Real AWS resources have not been created. The EC2 sensor and public-network design remain outstanding, and deployment requires an authenticated account plus an explicit review of cost, region, inbound exposure and outbound restrictions.
