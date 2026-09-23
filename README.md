# Securium

Securium is a minimal downstream Chromium security patch project. Its proposed
secure-profile design would require external key authorization before selected
Chromium profile secrets can be decrypted, so possession of copied profile
files alone is insufficient for the explicitly qualified OSCrypt-covered
surface.

Securium is not whole-profile encryption. It does not claim to protect history,
web storage, profile metadata, every Chromium database, or an unlocked browser
from compromised trusted processes. The secure-profile architecture is an
experimental candidate and no production browser release exists yet.

> **Status: first Chromium compatibility patch adopted; build verification in progress**
>
> **Highest completed evidence: exact-SHA PATCH-APPLY**
>
> **No production security patches exist yet.**
>
> **No Chromium build has been qualified from this repository.**
>
> **No production browser release exists.**

The reconciled secure-profile core design is a strong candidate for a synthetic
Chromium routing experiment. It is not runtime-qualified. See
`docs/SECURE_PROFILE_ARCHITECTURE.md` and
`docs/SECURE_PROFILE_FOUNDATION_1.md`.

Privacy Foundation 0 now defines the static network/service policy vocabulary,
six high-level product decisions, including explicitly user-initiated Lens,
and deterministic comparison rules
for future exact-SHA inventories and runtime observations. It changes no
Chromium behavior and provides no runtime network evidence. See
`docs/NETWORK_SERVICE_POLICY.md`.

Privacy Foundation 1A now defines the intended unbranded build-policy manifest,
including an explicit global-credential boundary and a future effective-value
verification contract. Per-revision results are recorded separately from the
intended manifest. See `docs/BUILD_POLICY.md`.

Privacy Foundation 1B is in progress: an exact-SHA GN evidence collector and
offline tests exist, and the pinned root source checkout and toolchain setup
are complete on the Windows worker, including dependency sync and hooks.
Lens may remain compiled under its disclosed user-initiated service policy.
The first compatibility patch preserves `enable_compose=false` with narrow
build guards. See `docs/CHROMIUM_154_QUALIFICATION.md` for current exact-SHA
results and `docs/BUILD_POLICY_VERIFICATION.md` for historical investigation.

## Repository role

This repository is the canonical downstream delta, not a Chromium source tree.
It owns the ordered patch series, downstream source, maintenance policy,
tracking state, Stable candidate detection, static checks, and placeholders for
later build, test, qualification, and release automation. It also contains a
synthetic-fixture engine that validates future downstream materialization and
patch-application mechanics without qualifying Chromium.

The maintenance equation is:

```text
Chromium Stable
      +
ordered Chromium Secure patches
      +
downstream-owned files
      =
qualified Chromium Secure source tree
```

Chromium changes rapidly and its security releases need prompt adoption. A
small, explicit patch series reduces long-term divergence and maintenance cost.
Patch failures are useful: they make changed upstream assumptions visible
instead of allowing an old fork to drift silently.

For future secure-profile revisions, each Stable adoption must also enumerate
and classify the exact-SHA OSCrypt consumer surface. A changed or unclassified
profile-relevant acquisition is a qualification blocker, not an invitation to
route every consumer blindly.

Future privacy qualification likewise requires an exact-SHA inventory of
browser-native network capabilities. New or materially changed unclassified
native capabilities fail; ordinary web, site, and extension traffic remains
separately attributed rather than being treated as browser-native service
traffic.

## Intended update flow

```text
Chromium Stable release detected
        |
        v
record unqualified candidate
        |
        v
qualification request
        |
        v
sync exact upstream SHA (future real worker)
        |
        v
materialize downstream files + apply ordered patches
        |
        v
compile
        |
        v
security + compatibility tests
        |
        v
package/sign
        |
        v
publish signed update
```

Candidate detection, repository-level static validation, and synthetic patch
engine validation exist today. Real Chromium source sync and every real
qualification stage remain future work. Synthetic PASS evidence proves only
that the engine behaved correctly against invented fixtures. Detection and
synthetic execution never imply Chromium qualification.

Future Codex automation may assist when a patch stops applying, an upstream
refactor breaks compilation, or qualification tests fail. Codex is an assistant
for adapting the downstream delta; it is not the authority that declares a
security release safe.

## Layout

- `patches/`: authoritative ordered Chromium patch series.
- `src/`: substantial downstream-owned source material.
- `state/`: separate candidate, qualified, and released revision state.
- `policy/`: versioned canonical build and network/service policy manifests and
  schemas.
- `scripts/`: deterministic repository tooling, candidate detection, and the
  build-policy validator plus synthetic patch and network-policy comparison
  engines.
- `tests/`: static, detector, and synthetic patch-engine checks now; real
  integration and security gates later.
- `docs/`: repository, secure-profile, network/service, security, upstream,
  patch, update, and qualification policy.
- `build/`, `updater/`, and `release/`: documented future boundaries.

Run the currently supported gate with:

```powershell
python scripts/validate_repo.py
python -m unittest discover -s tests/static -p "test_*.py"
python scripts/build_policy.py
python scripts/network_policy.py validate --policy policy/network-service-policy.json
python scripts/chromium_update.py check --offline-fixture tests/fixtures/chromiumdash/valid-stable-windows.json
python scripts/patch_qualify.py --request tests/fixtures/patch-engine/requests/valid.json --source tests/fixtures/patch-engine/sources/base --repository-root tests/fixtures/patch-engine/repositories/success --workspace artifacts/local-synthetic-check --source-kind synthetic-fixture --fixture-id local-check
```

The first four commands are the required offline `STATIC` gate. The fifth
demonstrates a read-only offline candidate check. A live read-only check uses
`python scripts/chromium_update.py check`; add `--json` for automation. Candidate
state changes require the explicit `--write-candidate` option. See
`docs/CANDIDATE_DETECTION.md` for decisions and authority boundaries.
The last command creates explicitly synthetic evidence and must use a new,
disposable workspace. See `docs/PATCH_QUALIFICATION.md`.

## Licensing boundary

Original material in this repository is available under the BSD 3-Clause
License in `LICENSE`, where legally applicable. Chromium and any upstream code
referenced by future patches remain governed by their own upstream licenses and
notices. This repository does not replace, relicense, or reproduce Chromium's
licensing tree. Future packaging must preserve all applicable upstream notices.
