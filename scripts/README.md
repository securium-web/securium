# Repository Scripts

`validate_repo.py` performs deterministic, offline repository and state checks
using only the Python standard library. This includes the canonical
network/service policy and schema. It never contacts ChromiumDash.

`network_policy.py` validates the versioned service policy and compares
invented or future evidence without network access or canonical-state writes:

```powershell
python scripts/network_policy.py validate --policy policy/network-service-policy.json
python scripts/network_policy.py compare --policy policy/network-service-policy.json --current-inventory path/to/inventory.json --json
```

Comparison results are explicitly marked synthetic. The current fixtures prove
only static classification and fail-closed comparison behavior; they are not
Chromium network observations. See `docs/NETWORK_SERVICE_POLICY.md`.

`build_policy.py` validates the canonical intended build policy, its required
baseline, global-credential boundary, pending source-verification status, and
references to approved network services:

```powershell
python scripts/build_policy.py
```

It does not inspect Chromium, run GN, resolve environment overrides, or claim
runtime behavior. See `docs/BUILD_POLICY.md`.

`verify_build_policy.py` is the work-in-progress Windows exact-SHA GN evidence
collector. It fails missing/mismatched arguments and detected environment
overrides, and never promotes qualification state. A GN match remains
`INCOMPLETE` pending effective-target and credential semantic review. See
`docs/BUILD_POLICY_VERIFICATION.md` for historical attempts. The optional
`--patch-evidence` argument binds collection to an unchanged real integration.
`verify_foundation_1b.py --build-evidence <json> --patch-evidence <json>
--evidence <new-json>` completes the separately reviewed exact-SHA build-only
gate after generated headers exist. It does not certify runtime credentials
or network behavior; see `docs/CHROMIUM_154_QUALIFICATION.md`.

`real_patch_qualify.py` uses the same strict engine with verified clean
Chromium Git identity and a new detached integration worktree. Its evidence is
explicitly nonsynthetic. See `docs/PATCH_QUALIFICATION.md` for arguments,
failure boundaries and separation from offline fixtures.

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
