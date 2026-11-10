#!/usr/bin/env bash
set -euo pipefail
# LocalStack starts empty; Terraform owns all simulated resources.
echo "[CloudTrap] LocalStack is healthy. Run make infra-plan, review, then make infra-apply."
