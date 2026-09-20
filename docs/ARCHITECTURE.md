# Architecture

## Responsibilities and artifact boundaries

This repository is the canonical source for Chromium Secure's ordered patches,
downstream-owned files, policy, tests, and maintenance automation. Released
Chromium Stable remains the authoritative browser source. A temporary
integration tree combines an exact upstream checkout with this repository's
delta; it is generated, disposable, and must never become the source of truth.

```text
ChromiumDash --> detector --> candidate (UNQUALIFIED)
                                  |
canonical patch repository -------+
  patches + src + policy + tests  |
                                  v
                       temporary integration tree
                                  |
                                  v
                            build machines
                                  |
                                  v
                       qualification evidence
                                  |
                         reviewed approval
                                  |
                                  v
                       signing and packaging
                                  |
                                  v
                     release + updater metadata
```

Source artifacts are reviewed files in upstream Chromium and this repository.
Generated integration trees, object files, packages, logs, signatures, updater
metadata, and release artifacts are products. Some products may later be
retained as evidence, but they are not editable downstream source.

## State authorities

The project state has three separate records. The detector may change only an
unqualified `candidate`; a future qualification pipeline may change only
`qualified`; and a future release pipeline may change only `released`. Detection
is read-only by default and cannot promote either later state. The executable
schema and write rules are defined in `scripts/chromium_update.py` and documented
in `state/README.md`.

## Downstream-owned implementation

Substantial Chromium Secure logic should live under `src/` so ownership,
licensing, testing, and review boundaries remain clear. Small patches should
connect that logic at stable Chromium integration boundaries. This arrangement
reduces conflicts, discourages accidental forks of upstream implementations,
and makes divergence measurable.

## Update lifecycle

1. Detect released Chromium Stable metadata and validate a candidate without
   changing qualified or released state.
2. Optionally record the proposed Chrome version and exact Chromium commit SHA
   as an explicitly unqualified candidate.
3. Sync a persistent upstream checkout and create a clean integration tree.
4. Inject downstream-owned files deterministically and apply `patches/series`.
5. Compile on real target infrastructure.
6. Run compatibility, runtime, and security qualification gates.
7. Review evidence and any security-semantic changes.
8. Package, sign, and publish artifacts and cryptographically anchored updater
   metadata.
9. Update canonical qualified or released state only through its owning
   authority and only to the level actually achieved.

Codex repair belongs between a failed integration/qualification attempt and a
fresh run of all affected gates. Update detection, repair, qualification,
approval, signing, and publishing are separate authorities. Codex must not sign
or publish and must stop when upstream invalidates the approved security model.

Steps 1 and 2 now exist as a static/control-plane component. Build machines,
Chromium integration, qualification, signing, and publication remain future
work. `docs/CANDIDATE_DETECTION.md` defines the implemented API, decision, and
failure semantics.
