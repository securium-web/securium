# Chromium Secure

Chromium Secure is a minimal downstream Chromium patch project intended to
strengthen protection of Chromium profile secrets. Its intended boundary is
stronger protection for secrets at rest and resistance to copied or stolen
profile data. A protected profile may require external key material to unlock,
and explicitly configured stronger protection must not silently downgrade.

This does not make an unlocked browser or compromised machine safe. Malware
running while Chromium and its secrets are available, elevated administrator
compromise, and compromised update infrastructure are separate threat classes.

> **Status: static control plane / architecture only**
>
> **Qualification level: STATIC ONLY**
>
> **No production security patches exist yet.**
>
> **No Chromium build has been qualified from this repository.**

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
- `scripts/`: deterministic repository tooling, candidate detection, and the
  synthetic patch engine.
- `tests/`: static, detector, and synthetic patch-engine checks now; real
  integration and security gates later.
- `docs/`: architecture, security, upstream, candidate, patch, update, and
  qualification policy.
- `build/`, `updater/`, and `release/`: documented future boundaries.

Run the currently supported gate with:

```powershell
python scripts/validate_repo.py
python -m unittest discover -s tests/static -p "test_*.py"
python scripts/chromium_update.py check --offline-fixture tests/fixtures/chromiumdash/valid-stable-windows.json
python scripts/patch_qualify.py --request tests/fixtures/patch-engine/requests/valid.json --source tests/fixtures/patch-engine/sources/base --repository-root tests/fixtures/patch-engine/repositories/success --workspace artifacts/local-synthetic-check --source-kind synthetic-fixture --fixture-id local-check
```

The first two commands are the required offline `STATIC` gate. The third
demonstrates a read-only offline candidate check. A live read-only check uses
`python scripts/chromium_update.py check`; add `--json` for automation. Candidate
state changes require the explicit `--write-candidate` option. See
`docs/CANDIDATE_DETECTION.md` for decisions and authority boundaries.
The final command creates explicitly synthetic evidence and must use a new,
disposable workspace. See `docs/PATCH_QUALIFICATION.md`.

## Licensing boundary

Original material in this repository is available under the BSD 3-Clause
License in `LICENSE`, where legally applicable. Chromium and any upstream code
referenced by future patches remain governed by their own upstream licenses and
notices. This repository does not replace, relicense, or reproduce Chromium's
licensing tree. Future packaging must preserve all applicable upstream notices.
