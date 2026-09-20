# Tests

`static/` contains repository validation and candidate detector tests that run
without Chromium or live network access. Sanitized ChromiumDash responses live
under `fixtures/chromiumdash/`. Invented source trees, downstream repositories,
requests, and patches live under `fixtures/patch-engine/`. These validate engine
semantics only. `integration/` and `security/` reserve explicit future
qualification boundaries. Passing the current tests supports only the `STATIC`
evidence level.

Invented service-policy comparison cases live under
`fixtures/network-policy/`. They cover allowed, denied, conditional,
user-initiated, replaced, site-directed, extension-directed, inventory-delta,
and source-remapping behavior. They contain no Chromium traffic evidence and
cannot support runtime qualification.

The future Foundation 1 routing suite is specified in
`docs/SECURE_PROFILE_FOUNDATION_1.md`. It requires a real Chromium build and is
not part of the current static suite.
