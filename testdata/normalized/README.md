# Normalized rules fixtures (CI)

Small vendor rule snapshots used by integration tests. **Not** a full feed mirror.

| Path | Purpose | Size (approx.) |
|------|---------|----------------|
| `ubuntu/jammy/` | `TestAfterUpdateEvidenceBinaryFixedRegression` | ~4.5 MB |

Full vendor data is produced locally with `openness-resolver feed sync --all` under `data/normalized/` (gitignored).

## Regenerating the Ubuntu jammy fixture

When the regression test or evidence file changes, refresh from a local full sync:

```bash
python3 scripts/extract_regression_rules_fixture.py
go test ./internal/resolver/ -run TestAfterUpdateEvidenceBinaryFixedRegression
```

The script keeps rules for source packages that contribute to the after-update regression (`ffmpeg`, `gst-plugins-bad1.0`, `python-pip`, `zvbi`, `libreoffice`, `util-linux`, `fonts-opensymbol`).
