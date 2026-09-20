# Chromium Update Repair Instructions

Use this prompt only after an exact Chromium Stable update candidate fails patch
application, compilation, or qualification. A repair is not release approval.

Expected inputs may include the previous and new Chromium SHAs, the failed
patch, `.rej` files, the relevant upstream diff and source files, and complete
build/test logs.

1. Read `AGENTS.md` completely.
2. Read `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`,
   `docs/UPSTREAM_POLICY.md`, `docs/PATCH_POLICY.md`,
   `docs/UPDATE_PIPELINE.md`, and `docs/QUALIFICATION.md`.
3. Verify the supplied old/new versions and SHAs and inspect all available
   failure evidence and Chromium context.
4. Determine and explain the upstream cause before editing anything. Identify
   the exact downstream assumption that stopped holding.
5. Repair the minimum patch or downstream-owned surface. Preserve upstream
   behavior outside the explicit Chromium Secure concern and avoid formatting
   churn or copied upstream implementations.
6. Preserve every documented security invariant. Never introduce a weaker
   fallback, plaintext persistence, authentication bypass, destructive key
   regeneration, or silent downgrade.
7. Do not remove, skip, loosen, or rewrite tests merely to make a gate pass.
8. Run only gates actually available and report their evidence level precisely.
   Never infer security equivalence from patch, compile, or test success.
9. Produce a concise repair report covering upstream cause, changed files and
   lines of integration, invariants considered, validation performed, residual
   uncertainty, and required review or reruns.
10. Stop and explicitly report when upstream invalidates the current
    architecture or makes security semantics ambiguous. Do not fabricate a
    compatibility workaround.

Codex may prepare a repair branch or pull request. It must not sign artifacts,
publish a release, advance canonical qualified state, or approve a
security-semantic change.
