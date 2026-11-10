#!/usr/bin/env bash
set -euo pipefail

BUCKET="cloudtrap-raw-logs"

INPUT="data/cowrie/var/log/cowrie/cowrie.json"
if [[ $# -ge 1 ]]; then
  INPUT="$1"
fi

KEY=""
if [[ $# -ge 2 ]]; then
  KEY="$2"
fi

case "$INPUT" in
  data/cowrie/var/log/cowrie/*)
    CONTAINER_INPUT="/cowrie-logs/$(basename "$INPUT")"
    ;;
  data/processed/*)
    CONTAINER_INPUT="/processed/$(basename "$INPUT")"
    ;;
  *)
    echo "Allowed inputs: data/cowrie/var/log/cowrie/* or data/processed/*" >&2
    exit 2
    ;;
esac

if [[ ! -f "$INPUT" ]]; then
  echo "Input file not found: $INPUT" >&2
  exit 1
fi

if [[ -z "$KEY" ]]; then
  case "$INPUT" in
    data/processed/*.jsonl)
      KEY="simulated/$(basename "$INPUT" .jsonl).json"
      ;;
    *)
      KEY="cowrie/$(date -u +%Y/%m/%d/%H%M%S)-$(basename "$INPUT")"
      ;;
  esac
fi

echo "Uploading $INPUT to s3://$BUCKET/$KEY in LocalStack"
docker compose exec -T localstack awslocal s3 cp "$CONTAINER_INPUT" "s3://$BUCKET/$KEY"
echo "Uploaded. S3 -> SQS -> Lambda processing should begin automatically."
