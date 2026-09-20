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
                                  v
                         qualification request
                                  |
canonical patch repository -------+
  patches + src + policy + tests  |
                                  v
                       temporary integration tree
                                  |
                    materialize + apply patches
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

## Secure-profile design baseline

The proposed secure profile is an experimental downstream architecture, not an
existing Chromium capability. Its current baseline is a random per-profile PEK,
recovered by Securium before protected-profile runtime construction, exposed
through one Securium `KeyProvider` in a profile-owned `OSCryptAsync`, and routed
only to explicitly classified profile-sensitive consumers. Ordinary profiles
retain Chromium's browser-global OSCrypt behavior.

Locked state belongs to the Securium profile lifecycle above `OSCryptAsync`.
The protected crypto context is constructed only after unlock has produced the
PEK; a completed temporarily-unavailable provider is not a reusable locked
state. The routing identity must be available before full `ProfileImpl`
construction and is not yet frozen to `Profile*`.

`docs/SECURE_PROFILE_ARCHITECTURE.md` is the canonical reconciled experimental
baseline. `docs/SECURE_PROFILE_FOUNDATION_1.md` specifies the next synthetic
Chromium routing experiment. Neither document adds patches, runtime evidence,
or qualification.

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

For a secure-profile-capable adoption, the qualification worker must also
mechanically inventory exact-SHA OSCrypt acquisitions, classify each relevant
consumer, and block on new or changed unclassified profile-sensitive paths.

Codex repair belongs between a failed integration/qualification attempt and a
fresh run of all affected gates. Update detection, repair, qualification,
approval, signing, and publishing are separate authorities. Codex must not sign
or publish and must stop when upstream invalidates the approved security model.

Steps 1 and 2 now exist as a static/control-plane component. Build machines,
real Chromium integration, qualification, signing, and publication remain
future work. The materialization and patch engine is validated only with
synthetic source trees; it cannot write canonical state. `docs/PATCH_QUALIFICATION.md`
defines its boundary, while `docs/CANDIDATE_DETECTION.md` defines candidate
detection.
