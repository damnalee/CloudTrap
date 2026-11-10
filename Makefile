SHELL := /bin/bash
PYTHON ?= python3
TF_DIR := infra/terraform
TERRAFORM ?= $(shell command -v terraform 2>/dev/null || printf '%s/.local/bin/terraform' "$(HOME)")
TF_VARS := -var=localstack_endpoint=http://localhost:4566
.PHONY: help test demo pipeline stack-up stack-status stack-logs infra-init infra-import-existing infra-plan infra-apply infra-destroy dashboard
help:
	@echo "make test | demo | dashboard | stack-up | infra-init | infra-plan | infra-apply | infra-destroy"
test:
	$(PYTHON) -m unittest discover -s services/processor/tests -v
demo:
	$(PYTHON) scripts/generate_test_campaign.py
	$(PYTHON) services/processor/app/detect_threats.py --input data/processed/simulated_campaign.jsonl --output data/processed/simulated_alerts.json
	$(PYTHON) services/processor/app/correlate_incidents.py --input data/processed/simulated_alerts.json --output data/processed/incidents.json
pipeline:
	$(PYTHON) scripts/run_pipeline.py
stack-up:
	docker compose up -d --build
stack-status:
	docker compose ps
stack-logs:
	docker compose logs --tail=100 localstack cowrie dashboard
infra-init:
	$(PYTHON) scripts/package_lambda.py
	$(TERRAFORM) -chdir=$(TF_DIR) init
infra-import-existing: infra-init
	bash scripts/import_localstack_state.sh
infra-plan: infra-import-existing
	$(PYTHON) scripts/package_lambda.py
	$(TERRAFORM) -chdir=$(TF_DIR) plan $(TF_VARS)
infra-apply: infra-import-existing
	$(PYTHON) scripts/package_lambda.py
	@echo "Applying only to LocalStack at http://localhost:4566 (never real AWS)."
	$(TERRAFORM) -chdir=$(TF_DIR) apply $(TF_VARS)
infra-destroy:
	@echo "Destroying Terraform-managed resources in LocalStack only."
	$(TERRAFORM) -chdir=$(TF_DIR) destroy $(TF_VARS)
dashboard:
	CLOUDTRAP_DATA_SOURCE=demo $(PYTHON) services/dashboard/app.py --host 127.0.0.1 --port 8502
