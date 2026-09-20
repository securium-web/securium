# Upstream Policy

Production release candidates track released Chromium **Stable**, never an
unbounded branch tip. Every candidate must pin both the exact Chromium release
version and exact commit SHA in machine-readable state. The version provides
operator context; the SHA provides reproducibility. Neither value alone is
sufficient.

Chromium `main` may be used for investigation, advance compatibility work, or
development when explicitly labeled, but it is not a production release base.

Security and point releases must not wait for an arbitrary weekly or monthly
maintenance window. The candidate detector identifies Windows Stable metadata
through ChromiumDash's `fetch_releases` API. Future scheduling should run it as
soon as practical and dispatch qualification only for a newly recorded exact
SHA. Detection is a metadata operation; it does not prove patch applicability,
compile the browser, qualify behavior, or authorize release. Only the future
qualification authority may advance qualified state.

If Chromium republishes or advances a Stable version, the exact SHA change is a
new candidate and must be qualified. Never infer support for adjacent versions
or platforms from a previously qualified record.

ChromiumDash supplies a Chrome release `version` and a separate
`hashes.chromium` source commit. State records preserve this distinction as
`chrome_version` and `chromium_sha`. The detector follows the single record
returned by the official `num=1` query; it does not guess that the numerically
largest record in a wider historical response is authoritative. Older-than-local
responses, conflicting version/SHA mappings, and ambiguous responses stop
without modifying state.
