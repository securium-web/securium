# Patch Qualification Foundation

## Boundary

`scripts/patch_qualify.py` validates deterministic downstream materialization
and patch application against invented source fixtures. A synthetic PASS means
the engine copied, materialized, and applied the declared inputs successfully.
It does **not** mean any Securium patch applies to any Chromium revision.

`scripts/real_patch_qualify.py` adds a separate real-source adapter. It verifies
the official Chromium origin URL, exact Git HEAD and version, a clean nonsparse
root, and creates a detached disposable worktree. It reuses this engine's patch
inspection, collision-safe materialization and strict ordered application.
Real evidence uses `synthetic=false`, `engine_validation=REAL_CHROMIUM` and a
separate validator; it cannot pass the synthetic evidence validator. The
record includes the upstream tree identity, patch/content digests, timestamps,
and resulting diff/file hashes. Follow-on gates reject changed integration
content or unexpected untracked files. Origin verification checks configured
identity, not a separate cryptographic attestation of the hosting service.

Run `real_patch_qualify.py --request <request.json> --source <clean-chromium-root>
--repository-root <securium-root> --workspace <new-disposable-directory>`.
Exit zero means real PATCH-APPLY passed. It does not modify canonical release
state. Worktree root cleanliness does not certify dependencies; dependency
hydration/provenance and all build checks remain separate. The synthetic
pipeline below remains available unchanged for offline tooling validation.

## Pipeline

```text
qualification request
        |
        v
validate synthetic source identity
        |
        v
validate downstream plan + patch series
        |
        v
copy source into disposable integration tree
        |
        v
materialize src/chromium/<path> at <integration-root>/<path>
        |
        v
git apply --check, then git apply, exactly in series order
        |
        v
synthetic PASS/FAIL evidence
```

The caller must identify the source as `synthetic-fixture` and provide a bounded
fixture ID. Evidence also records a deterministic tree-content hash. The schema
leaves source identity as a distinct object so a future real worker can record
repository identity, expected candidate SHA, actual Git HEAD, and clean/dirty
status without changing patch or materialization semantics.

## Preflight and path safety

Before creating the integration tree, the engine validates the request, source
tree, Git availability, complete patch series, every patch's structure and
paths, and the downstream materialization plan. The workspace must be new and
must not overlap the source.

Path checks reject traversal, absolute and drive-qualified paths, backslashes,
Windows alternate-data-stream colons, reserved device names, trailing dot/space
segments, `.git`, control characters, symlinks, and Windows reparse points.
Resolved destinations must remain below the integration root. These checks are
reasonable cross-platform controls, not a claim about every possible filesystem
race or exotic filesystem behavior.

Materialization collisions fail closed. A downstream file cannot replace an
upstream file or directory, and cannot traverse through an upstream file.

## Patch semantics

`patches/series` is authoritative. Blank lines and full-line comments are
ignored; entries must be unique, contiguous `0001-name.patch` filenames. Listed
patches must exist and unlisted top-level `.patch` files are rejected.

Git parses each patch during preflight. Binary and symlink patches are currently
unsupported. Application uses strict whitespace checks and intentionally omits
`--3way`, `--reject`, and `--unsafe-paths`. Each patch is checked against the
current integration tree and then applied, so declared dependencies work. A
failure stops immediately; partial application is always FAIL and the failed
integration tree remains in the disposable workspace for diagnosis.

`git apply` was selected instead of `git am` because it accepts raw Git diffs and
format-patch payloads, creates no commits, needs no commit identity, and cleanly
separates patch applicability from history construction.

## Evidence and repair bundle

`state/patch-apply-evidence.schema.json` fixes schema version 1, stage
`PATCH-APPLY`, and the mandatory synthetic markers. Evidence contains:

- candidate input and synthetic source identity;
- canonical request, series, patch, source-tree, and downstream-file hashes;
- Git version and ordered patch metadata;
- attempted and applied patches;
- failed patch, failure class, bounded diagnostics, and affected paths; and
- integration-tree status and optional repair-bundle filename.

No timestamps or absolute input paths are recorded, so equivalent inputs and
tool versions produce stable machine-readable evidence. PASS is constructed
only after all operations complete; callers cannot supply it.

Patch failures also produce `repair-bundle.json` containing the qualification
request, candidate, full ordered patch list, applied list, failed patch and hash,
affected paths, Git diagnostic, and an evidence snapshot. `git apply` is not run
with `--reject`, so the engine does not manufacture `.rej` files. A future real
worker will add old/new upstream files, upstream diffs, compile logs, and test
logs where those stages exist.

Failure classes are `INVALID_REQUEST`, `INVALID_SOURCE`, `INVALID_WORKSPACE`,
`INVALID_SERIES`, `UNSAFE_PATH`, `MATERIALIZATION_COLLISION`,
`MATERIALIZATION_FAILURE`, `PATCH_CHECK_FAILED`, `PATCH_APPLY_FAILED`,
`TOOL_MISSING`, `EVIDENCE_WRITE_FAILED`, and `INTERNAL_ERROR`.

## Authority

The patch engine accepts no canonical-state path and has no promotion operation.
Synthetic success cannot change `candidate`, `qualified`, or `released`. A
future qualification authority must reject synthetic evidence for real
candidate promotion and require all documented real-source gates.
