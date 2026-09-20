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

`patch_qualify.py` consumes the existing qualification request, an explicit
source tree, downstream repository root, and new disposable workspace:

```powershell
python scripts/patch_qualify.py `
  --request tests/fixtures/patch-engine/requests/valid.json `
  --source tests/fixtures/patch-engine/sources/base `
  --repository-root tests/fixtures/patch-engine/repositories/success `
  --workspace artifacts/synthetic-patch-validation `
  --source-kind synthetic-fixture `
  --fixture-id local-test `
  --json
```

Exit `0` means the synthetic engine run passed; exit `1` means the stage failed;
argument errors use `2`. The workspace must not exist and must not overlap the
source. The engine never reads or writes canonical upstream state. See
`docs/PATCH_QUALIFICATION.md` for evidence and Git semantics.
