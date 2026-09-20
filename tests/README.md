# Tests

`static/` contains repository validation and candidate detector tests that run
without Chromium or live network access. Sanitized ChromiumDash responses live
under `fixtures/chromiumdash/`. Invented source trees, downstream repositories,
requests, and patches live under `fixtures/patch-engine/`. These validate engine
semantics only. `integration/` and `security/` reserve explicit future
qualification boundaries. Passing the current tests supports only the `STATIC`
evidence level.
