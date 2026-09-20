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
4. **Apply the downstream delta (future).** Create a disposable integration
   tree, inject downstream source deterministically, and apply `patches/series`
   in order.
5. **Compile (future).** Use real target build machines and retained
   configurations.
6. **Run compatibility and security qualification (future).** Execute defined
   tests and retain evidence for the candidate.
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
