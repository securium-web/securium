# Qualification Levels

Evidence levels are cumulative. Each label requires its own evidence plus every
preceding level. Results apply only to the exact recorded Chromium SHA, patch
series, downstream source revision, platform, and configuration.

## Architecture claim vocabulary

Architecture documents may label an individual claim `DOCUMENTED`,
`IMPLEMENTATION-DERIVED`, `INFERRED`, `EXPERIMENTAL`, or `QUALIFIED`.
These are provenance/status labels, not additional project evidence levels.
`QUALIFIED` requires the applicable gates below on an exact revision and cannot
be inferred from review agreement, source inspection, or static documentation.

## STATIC

Repository consistency, required-file presence, patch-series metadata, patch
shape, candidate/state schema checks, and offline detector tests pass without a
Chromium checkout. Required pull-request validation uses committed fixtures and
does not depend on ChromiumDash availability. A successful optional live lookup
is still only `STATIC` metadata evidence. Synthetic materialization and patch
engine tests also remain `STATIC`: they validate machinery, not a Chromium
candidate.

Network/service policy schema validation and synthetic policy-comparison tests
also remain `STATIC`. They validate policy syntax, bounded taxonomies, adoption
delta rules, and mismatch logic against invented evidence. They do not prove
that Chromium implements the policy or that a runtime emitted only allowed
traffic.

Build-policy manifest validation also remains `STATIC`. It proves only that the
intended unbranded configuration, credential boundary, service references, and
future verification contract are internally consistent. It does not prove that
GN accepts a setting, that Chromium resolves the expected value, that
environment overrides are absent, or that a browser behaves accordingly.

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

For secure-profile routing, this includes the accepted Foundation 1 matrix and
an exact-SHA OSCrypt consumer inventory. The inventory must classify each
relevant acquisition as browser-global, profile-sensitive, feature-gated
profile-sensitive, migration-only, or irrelevant. New or changed unclassified
profile-relevant acquisitions block the secure-profile result. A Foundation 1
pass establishes routing/lifecycle evidence only; it does not qualify external
providers, migration, App-Bound composition, runtime relock, or the product as a
whole.

For network/service policy, this level requires a source inventory bound to the
exact Chromium SHA, scenario-scoped observations from the real supported
runtime, and deterministic comparison with the canonical policy. Unclassified
native connections, observed denied or replaced-upstream services, unmet
conditions or user actions, semantic overreach, and missing explicit
`MUST_OBSERVE` behavior fail. Absence alone is not evidence unless a scenario
declares `MUST_OBSERVE`.

## SECURITY-QUALIFIED

Approved tests explicitly exercise defined security invariants, evidence is
reviewed, and security-semantic changes receive explicit human approval.

## RELEASE-QUALIFIED

Packaging, artifact hashes, signing, updater metadata, provenance, rollback
policy, and release authorization all validate for the candidate.

The repository currently supports and claims **STATIC only**. No Chromium SHA,
build, runtime behavior, security property, platform, updater, or release is
qualified.
