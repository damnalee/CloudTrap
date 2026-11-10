#!/usr/bin/env python3
"""Build the CloudTrap Lambda deployment zip from shared processor modules."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "infra/terraform/build/cloudtrap-ingest.zip"
SOURCES = [ROOT / "services/lambda/lambda_function.py", ROOT / "services/processor/app/process_cowrie.py", ROOT / "services/processor/app/detect_threats.py", ROOT / "services/processor/app/correlate_incidents.py"]
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with ZipFile(OUTPUT, "w", ZIP_DEFLATED) as archive:
    for source in SOURCES:
        if not source.is_file(): raise SystemExit(f"Missing Lambda source: {source}")
        archive.write(source, source.name)
print(f"Packaged {len(SOURCES)} modules: {OUTPUT.relative_to(ROOT)}")
