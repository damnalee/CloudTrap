#!/usr/bin/env python3
"""Package CloudTrap's Lambda handler and shared processor modules."""

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "infra/terraform/build/cloudtrap-ingest.zip"

SOURCES = {
    "lambda_function.py": ROOT / "services/lambda/lambda_function.py",
    "process_cowrie.py": ROOT / "services/processor/app/process_cowrie.py",
    "detect_threats.py": ROOT / "services/processor/app/detect_threats.py",
    "correlate_incidents.py": ROOT / "services/processor/app/correlate_incidents.py",
}


def main() -> int:
    missing = [str(path) for path in SOURCES.values() if not path.is_file()]
    if missing:
        raise SystemExit("Missing Lambda source files:\n" + "\n".join(missing))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    temporary = OUTPUT.with_suffix(".zip.tmp")
    with zipfile.ZipFile(
        temporary,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for archive_name, source_path in SOURCES.items():
            archive.write(source_path, arcname=archive_name)

    temporary.replace(OUTPUT)
    print(f"Created {OUTPUT}")
    print(f"Source modules: {len(SOURCES)}")
    print(f"Archive bytes: {OUTPUT.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
