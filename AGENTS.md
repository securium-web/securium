# Chromium Secure Agent Rules

These rules govern every automated or AI-assisted change to this repository.
Read this file and the relevant documents under `docs/` before editing patches,
downstream source, update state, or qualification tooling.

## Repository role

Chromium Secure is not an independent browser implementation. Released
Chromium Stable is the authoritative upstream. This repository stores only the
ordered downstream delta, downstream-owned files, policy, tests, and automation.
Generated Chromium integration trees are disposable build products and are
never canonical downstream source.

## Upstream preservation

- Preserve upstream behavior except where Chromium Secure explicitly and
  narrowly changes it.
- Avoid unrelated Chromium changes, cosmetic churn, and reformatting in
  Chromium-owned code.
- Never carry arbitrary copies of upstream implementation merely to avoid a
  patch conflict.
- Track release candidates against an exact Stable version and commit SHA.

## Minimal patch policy

Prefer a downstream-owned implementation plus a small Chromium integration
patch over large modifications inside Chromium implementation files. Minimize
the number of touched upstream lines and files. Keep one conceptual concern per
patch where practical. `patches/series` is the authoritative deterministic
order; every patch needs a descriptive filename, narrow purpose, and rationale
when that purpose is not obvious.

## Security-sensitive behavior

The intended product direction is stronger protection for Chromium profile
secrets using external key material, potentially an OS keyring and/or
hardware-backed security key. The design is not implemented or approved yet.

Never resolve compatibility, patch, build, or test failures by:

- introducing a silent weaker fallback or bypassing intended authentication;
- persisting plaintext secrets or weakening key separation;
- disabling security tests or deleting assertions because upstream changed;
- substituting best-effort behavior where fail-closed behavior is required; or
- silently creating a new key when protected material is inaccessible.

Stop for explicit architecture and security review if an upstream change makes
an invariant infeasible or ambiguous.

## Upstream update handling

When Chromium changes underneath a patch:

1. Determine what changed upstream.
2. Identify the affected downstream assumption.
3. Modify the smallest possible downstream surface.
4. Preserve documented security invariants.
5. Add or update tests if semantics changed.
6. Document residual uncertainty.
7. Rerun every applicable qualification gate.

Patch application or compilation alone is never sufficient security evidence.

## Evidence levels

Use only these ordered evidence labels:

`STATIC`, `PATCH-APPLY`, `COMPILE`, `TEST`, `RUNTIME`,
`SECURITY-QUALIFIED`, `RELEASE-QUALIFIED`.

This repository currently supports only `STATIC`. Never claim a higher level
without performing the requirements in `docs/QUALIFICATION.md`. Do not mark
TODO gates as passing, invent CI results, claim a Chromium version is supported
without qualification, or alter canonical release state unless the documented
qualification pipeline succeeded.

## Update-state authority

`DETECTED != QUALIFIED` and `QUALIFIED != RELEASED`. The metadata detector may
change only `state/upstream.json`'s `candidate` record. A future qualification
pipeline is the sole authority for `qualified`, and a future release pipeline is
the sole authority for `released`. A new Chromium SHA requires qualification.
Failure to contact or understand upstream must preserve all local state, and an
unchanged SHA must not refresh timestamps or otherwise mutate candidate state.

## Codex update repair

Before repairing a Chromium update, read `docs/ARCHITECTURE.md`,
`docs/SECURITY_MODEL.md`, `docs/UPSTREAM_POLICY.md`, `docs/PATCH_POLICY.md`, and
`docs/QUALIFICATION.md`. Codex may prepare patch repairs and evidence reports,
but must not publish releases, sign builds, weaken invariants, or decide that a
security-semantic change is acceptable without explicit human review. Build and
test success do not prove security equivalence.

## Change discipline

- Keep repository tooling dependency-light and deterministic.
- Do not add network access to the static validator.
- Use PascalCase where applicable and preserve established camelCase names.
- State evidence and uncertainty precisely in change reports.
