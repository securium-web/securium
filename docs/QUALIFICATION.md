# Qualification Levels

Evidence levels are cumulative. Each label requires its own evidence plus every
preceding level. Results apply only to the exact recorded Chromium SHA, patch
series, downstream source revision, platform, and configuration.

## STATIC

Repository consistency, required-file presence, patch-series metadata, patch
shape, candidate/state schema checks, and offline detector tests pass without a
Chromium checkout. Required pull-request validation uses committed fixtures and
does not depend on ChromiumDash availability. A successful optional live lookup
is still only `STATIC` metadata evidence. Synthetic materialization and patch
engine tests also remain `STATIC`: they validate machinery, not a Chromium
candidate.

## PATCH-APPLY

All downstream-owned files are integrated deterministically and every ordered
patch applies cleanly to the exact target Chromium SHA in a clean tree. Rejects
or fuzz outside approved policy fail the gate.

This level requires a real Chromium Git checkout with actual HEAD verified
against the qualification request. Evidence with `synthetic: true` or
`engine_validation: SYNTHETIC_FIXTURE_ONLY` cannot satisfy this level.

## COMPILE

The declared target build configuration compiles successfully on approved
infrastructure, with retained source identity, configuration, toolchain, and
logs.

## TEST

The defined automated compatibility and regression suites pass against the
compiled candidate, with results retained and failures unresolved by test
weakening.

## RUNTIME

Required browser behaviors are validated in a real supported runtime using
documented scenarios and platform configurations.

## SECURITY-QUALIFIED

Approved tests explicitly exercise defined security invariants, evidence is
reviewed, and security-semantic changes receive explicit human approval.

## RELEASE-QUALIFIED

Packaging, artifact hashes, signing, updater metadata, provenance, rollback
policy, and release authorization all validate for the candidate.

The repository currently supports and claims **STATIC only**. No Chromium SHA,
build, runtime behavior, security property, platform, updater, or release is
qualified.
