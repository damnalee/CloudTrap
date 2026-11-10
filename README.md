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

## Tests

Run all unit tests:

~~~bash
python3 -m unittest discover -s services/processor/tests -v
~~~

The suite covers normalization, credential-field exclusion, malformed records, threat rules, benign activity, and incident grouping.

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
- [ ] AWS ingestion and storage (S3, SQS, Lambda, DynamoDB)
- [ ] Notifications and CloudWatch monitoring
- [ ] Terraform infrastructure and deployment hardening

CloudTrap is not yet connected to AWS. The AWS stage will be added after local tests, dashboard verification, and a review of account cost and security settings.
