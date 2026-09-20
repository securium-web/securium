# Update Pipeline

Candidate detection is implemented as static/control-plane tooling. Chromium
source integration and all qualification and release phases remain future work.

1. **Poll Chromium Stable metadata (implemented).** Fetch or accept an offline
   ChromiumDash response without changing qualified or released state.
2. **Detect a new exact Stable SHA (implemented).** Resolve the Chrome version
   and Chromium commit SHA, compare them with local state, and optionally record
   only an unqualified candidate through an atomic replacement.
3. **Sync a persistent Chromium checkout (future).** Obtain the exact source
   efficiently and verify checkout identity.
4. **Apply the downstream delta (engine validated synthetically; real gate
   future).** Create a disposable integration tree, materialize `src/chromium/`
   deterministically, and apply `patches/series` in order. Current PASS evidence
   is always marked synthetic and cannot qualify a candidate.
5. **Compile (future).** Use real target build machines and retained
   configurations.
6. **Run compatibility and security qualification (future).** Execute defined
   tests and retain evidence for the candidate. A secure-profile-capable
   adoption must mechanically enumerate the exact-SHA OSCrypt acquisition set,
   classify every relevant consumer, compare it with the prior accepted
   inventory, and fail on a new or changed unclassified profile-sensitive path.
   A privacy-capable adoption must separately generate the exact-SHA native
   network capability inventory, compare semantic deltas with the canonical
   service policy, and fail new or materially changed unclassified native
   capabilities. Runtime observation and network qualification remain later
   artifacts; neither may be inferred from source inventory alone.
7. **Package and sign (future).** Produce platform artifacts only after required
   review.
8. **Publish signed updater metadata (future).** Bind versions and hashes under
   the approved independent trust anchor, then advance released state through
   the release authority.

The intended failure path is:

```text
patch/build/test failure
        |
        v
collect evidence
        |
        v
Codex repair branch/PR
        |
        v
full qualification reruns
        |
        v
human review where security semantics changed
```

Repair inputs should include old and new SHAs, failed patches and rejects,
relevant upstream diffs and files, and complete build/test logs. A repaired
patch receives no inherited qualification: affected gates rerun. Architecture
invalidations stop the pipeline instead of being hidden behind a workaround.

For `NEW_CANDIDATE`, JSON output includes the versioned minimal qualification
request defined by `state/qualification-request.schema.json`. Future generated
repair evidence belongs under an ignored
`artifacts/qualification/<chromium-sha>/` tree or an equivalent durable CI
artifact store. It may contain failed patches, `.rej` files, upstream diffs,
affected source snapshots, compile logs, and test logs. That collection is not
implemented by the detector.

The synthetic engine now emits the bounded patch-failure portion of this future
repair input: request, ordered and applied patches, failed patch and hash,
affected paths, Git diagnostics, and evidence. Real-worker old/new upstream
files, upstream diffs, compile logs, and test logs remain future additions.

## Secure-profile experiment sequence

The next architecture experiment is Foundation 1: synthetic profile crypto
routing on a Chromium-capable worker. It must recover a test PEK before full
protected-profile construction, create one profile-owned `OSCryptAsync`, route
the required classified consumers, and retain the complete matrix described in
`docs/SECURE_PROFILE_FOUNDATION_1.md`.

Real FIDO, Windows Hello/TPM, App-Bound envelope composition, recovery,
migration, packaging, and release work remain later independent slices. A
Foundation 1 result receives no authority to update `qualified` or `released`
unless a future qualification pipeline separately satisfies the applicable
state-transition requirements.

## Privacy foundation sequence

Foundation 0 is the static policy specification in
`docs/NETWORK_SERVICE_POLICY.md`. The next task is **Privacy Foundation 1 —
Build Policy Manifest** on a Chromium-capable worker: generate a complete
exact-SHA native network capability inventory, map each capability to an
approved semantic service or fail it as unclassified, and propose separately
reviewed policy amendments for unresolved services. Runtime capture and network
qualification comparison remain subsequent work.
