# Downstream-Owned Source

Substantial Chromium Secure-owned implementations belong here rather than in
large patches to Chromium-owned files. The explicit mapping convention is:

```text
src/chromium/<path> -> <integration-root>/<path>
```

Only regular files below `src/chromium/` participate. Materialization order is
lexicographic. Absolute, traversal, drive-qualified, reserved Windows, symlink,
reparse-point, and `.git` paths are rejected. Existing upstream files or
directories are collisions and are never silently overwritten; modifications
to Chromium-owned files belong in patches.

This directory currently contains documentation only. It does not implement
secure profiles, a key provider, secret migration, or cryptography.
