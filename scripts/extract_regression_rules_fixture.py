#!/usr/bin/env python3
"""Extract minimal ubuntu/jammy rules for after-update regression tests."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL_RULES = ROOT / "data" / "normalized" / "ubuntu" / "jammy" / "rules.json"
OUT_DIR = ROOT / "testdata" / "normalized" / "ubuntu" / "jammy"

KEEP_SOURCES = {
    "ffmpeg",
    "gst-plugins-bad1.0",
    "python-pip",
    "zvbi",
    "libreoffice",
    "util-linux",
    "fonts-opensymbol",
}


def main() -> None:
    if not FULL_RULES.is_file():
        raise SystemExit(
            f"missing {FULL_RULES}; run: openness-resolver feed sync --vendor ubuntu"
        )

    rules = json.loads(FULL_RULES.read_text())
    subset = [r for r in rules if r.get("source_package") in KEEP_SOURCES]
    if not subset:
        raise SystemExit("no rules matched KEEP_SOURCES")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "rules.json").write_text(json.dumps(subset, indent=1) + "\n")
    meta = {
        "source_name": "ubuntu-oval-usn-jammy-fixture",
        "source_url": "https://github.com/s4e-io/openness-resolver/tree/main/testdata/normalized/ubuntu/jammy",
        "downloaded_at": "2026-08-10T00:00:00Z",
        "sha256": "fixture",
        "size_bytes": 0,
        "parser_version": "ubuntu-oval/1.1.0",
        "raw_object_id": "testdata-fixture",
        "snapshot_dir": "testdata/normalized/ubuntu/jammy",
    }
    (OUT_DIR / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"wrote {len(subset)} rules to {OUT_DIR}")


if __name__ == "__main__":
    main()
