# Patch Series

`series` is the authoritative patch order. Each non-comment, nonblank line is a
patch filename relative to this directory. Filenames use the form
`0001-short-description.patch`, with contiguous numbering matching series order.

To add a patch:

1. Develop an ordinary, focused Git commit against the pinned Chromium checkout.
2. Export it with `git format-patch` (or generate an equivalent Git-compatible
   patch) without unrelated changes.
3. Place it here with the next sequence number and add that filename to `series`.
4. Explain non-obvious motivation in the patch commit message.
5. Run static validation, followed by patch-apply and all higher gates when the
   required infrastructure exists.

Prefer one conceptual concern per patch. Put substantial implementation in
`src/` and use Chromium patches mainly at integration boundaries. Do not vendor
whole Chromium implementations. An unlisted `.patch` file is an error, patch
failure is a qualification failure, and clean application is not proof of
semantic correctness.
