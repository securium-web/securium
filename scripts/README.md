# Repository Scripts

`validate_repo.py` performs deterministic, offline repository and state checks
using only the Python standard library. It never contacts ChromiumDash.

`chromium_update.py` separates live fetching from offline parsing, validation,
comparison, and state writing. It is read-only unless `--write-candidate` is
explicitly supplied:

```powershell
python scripts/chromium_update.py check
python scripts/chromium_update.py check --json
python scripts/chromium_update.py check --offline-fixture tests/fixtures/chromiumdash/valid-stable-windows.json
python scripts/chromium_update.py check --write-candidate
```

The detector may write only unqualified candidate state. It cannot change
qualified or released state. See `docs/CANDIDATE_DETECTION.md` for the upstream
contract, decisions, exit codes, and machine-readable report.
