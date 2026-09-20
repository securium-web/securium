# Patch Policy

Patch filenames follow:

```text
0001-short-description.patch
0002-short-description.patch
...
```

`patches/series` controls deterministic order. Sequence numbers are contiguous,
start at `0001`, and match line order. The static validator rejects missing,
duplicate, malformed, and unlisted patch files.

Keep one conceptual concern per patch where practical. Avoid giant patches,
unrelated cleanup, format churn, and copies of entire Chromium implementations.
Substantial logic belongs in downstream-owned `src/`; patches should primarily
touch the smallest stable Chromium integration boundaries.

A normal development workflow may use focused Git commits against the exact
pinned Chromium checkout and export reviewed commits with `git format-patch`.
Patch messages should state purpose, affected invariant, and non-obvious
upstream assumptions. Regeneration must preserve reviewable intent and order.

Any patch failure is a qualification failure until resolved against the exact
target SHA. Application success establishes syntax and context compatibility
only; it does not establish compilation, runtime behavior, security equivalence,
or release suitability.

The patch engine uses `git apply --check` immediately before each ordered
`git apply`, with strict whitespace checking and without `--3way`, `--reject`,
or `--unsafe-paths`. This permits raw Git diffs and `git format-patch` output
without creating commits. Each patch sees prior patches' results; failure stops
the series and no later patch is attempted. Binary patches, symlink patches,
unsafe paths, malformed headers, unlisted patches, and non-contiguous series
numbering are rejected.
