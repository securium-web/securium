# Privacy Foundation 1A: Build Policy Manifest

Status: `STATIC`

This document defines Securium's intended unbranded Chromium build policy. The
canonical machine-readable manifest is `policy/build-policy.json`, validated by
`policy/build-policy.schema.json` and `scripts/build_policy.py`.

Foundation 1A validates only that this intended policy is internally consistent.
It does not establish that any Chromium revision defines, accepts, or resolves
these settings.

## Three distinct layers

The build-policy process keeps three layers separate:

1. **Intended build policy** is the canonical Securium requirement in this
   repository. Foundation 1A implements this layer.
2. **Effective build configuration** is what GN and the real Chromium build
   resolve at an exact commit SHA after defaults, imports, toolchain behavior,
   and environment-derived credentials are considered. Foundation 1B must
   produce this evidence.
3. **Runtime behavior** is what the compiled browser actually does. It requires
   later runtime and network qualification and cannot be inferred from either
   of the first two layers.

```text
intended build-policy manifest
              |
              v
exact Chromium SHA + real environment
              |
              v
resolved effective build configuration
              |
              v
compile and later runtime/network qualification
```

## Manifest scope and semantics

The current manifest targets the Windows `GN` configuration for the intended
`SECURIUM_UNBRANDED_CHROMIUM` product. It contains no local paths, output
directories, toolchain locations, or machine-specific settings.

Each setting records:

- its GN-style name and intended exact, empty, allowed-set, or forbidden value;
- `REQUIRED_INVARIANT`, `EXPLICIT_DEFENSE`, or `PRODUCT_CHOICE` classification;
- `INVARIANT` or `PREFERRED` stability;
- rationale and related network service identifiers;
- whether real source verification is required; and
- verification status.

Every Foundation 1A entry is `PENDING_REAL_SOURCE_VERIFICATION` and requires a
real Chromium source checkout. `PREFERRED` identifies a changeable product
choice rather than a durable security invariant; a mismatch still blocks
automated build-policy qualification until the manifest is deliberately
amended and reviewed.

The schema supports `EXACT_VALUE`, `REQUIRED_EMPTY_STRING`, `ALLOWED_SET`, and
`FORBIDDEN_VALUE`. Exact and empty requirements inherently forbid every value
outside their declared constraint.

## Initial intended baseline

The manifest encodes these groups without claiming the symbols currently exist:

| Intent | Settings | Classification |
| --- | --- | --- |
| Unbranded product | `is_chrome_branded=false` | `REQUIRED_INVARIANT` |
| No global official credentials | `use_official_google_api_keys=false`; global API key and default OAuth fields empty | `REQUIRED_INVARIANT` |
| No Chrome browser updater integration | `enable_updater=false`; `enable_update_notifications=false` | `EXPLICIT_DEFENSE` |
| No RLZ integration | `enable_rlz=false` | `EXPLICIT_DEFENSE` |
| Retain Standard Safe Browsing intent | `safe_browsing_mode=1` | `REQUIRED_INVARIANT` |
| Product exclusions | `enable_compose=false` | `PRODUCT_CHOICE` / `PREFERRED` |

Lens may remain compiled, including infrastructure shared with other Chromium
features. `enable_lens_desktop=false` is no longer a required setting; GN may
use its upstream default. Lens is governed by the canonical `lens` service's
`USER_TRIGGERED_SERVICE` / `USER_INITIATED` policy, with clear disclosure before
visual/page context is sent to Google. Background or silent context transmission
is prohibited. This decision does not change Compose, credentials, or imply
runtime Lens qualification. No Chromium refactor to compile Lens out is planned.

No speculative `enable_glic` setting is present. The static validator rejects
that name rather than treating an unverified audit claim as a supported GN
argument.

## Credential boundary

Securium does not use global Chrome or Google credentials as a catch-all browser
configuration. The canonical policy requires:

- official Google API keys disabled;
- the global Google API key empty;
- the default OAuth client ID empty; and
- the default OAuth client secret empty.

Future service-specific credentials may be considered only for a service that
is explicitly retained in the network/service policy. Each credential must be
documented separately, scoped to that service, and never reused as a global
browser credential. Plaintext secrets must never be committed to this
repository.

Checked-in values are not sufficient evidence. Chromium may resolve credentials
from build or runtime environment sources. Foundation 1B must detect effective
credentials and forbidden environment-derived overrides. Any effective global
credential or other required-value mismatch fails build-policy verification.

## Relationship to network/service policy

The build manifest references canonical service identifiers instead of copying
service policy:

- `enable_updater=false` and disabled update notifications support the
  `chrome_browser_updater` `DENY` decision;
- `safe_browsing_mode=1` supports the retained `safe_browsing_standard` intent;
- disabled global credentials support the credential boundary but do not prove
  browser sign-in or service inactivity; and
- Compose remains an independent product exclusion; Lens has its own explicit
  user-initiated service approval in the network policy.

The validator requires every referenced service identifier to be approved in
`policy/network-service-policy.json`. Neither the manifest nor a successful GN
comparison proves a service's runtime traffic matches that policy.

## Static validation and failure semantics

`scripts/build_policy.py` validates deterministic serialization, schema and
manifest identifiers, unique and ordered setting names, bounded policy modes,
the complete required baseline, empty credential fields, disabled official
keys, credential-policy controls, approved service references, pending real
source verification, and absence of secret-looking credential values.

Missing, duplicate, contradictory, malformed, speculative, unknown, or
non-canonical policy fails. The repository validator and static CI run this
check offline. Success means only that the intended manifest is internally
consistent at `STATIC`.

## Explicitly deferred

Foundation 1A does not:

- check out or inspect Chromium source;
- prove that any named GN argument exists or retains the assumed meaning;
- run GN or compile Chromium;
- capture resolved build values or inspect environment overrides;
- prove browser sign-in, updater, Safe Browsing, Compose, Lens, RLZ, or Google
  service runtime behavior; or
- advance candidate, qualified, or released state.

## Foundation 1B handoff

Work in progress, worker findings, collector usage and remaining gates are
recorded in `docs/BUILD_POLICY_VERIFICATION.md`. Foundation 1B has not passed.

The exact next task is **Privacy Foundation 1B — Exact-SHA Build Policy
Verification** on a Chromium-capable worker. It must:

1. check out and verify the exact candidate Chromium SHA;
2. inspect the actual supported GN arguments and their current semantics;
3. run GN generation using a clean, recorded configuration;
4. capture deterministic resolved/effective build values;
5. detect build- or runtime-environment credential overrides;
6. compare effective values with this manifest;
7. fail on missing, renamed, changed, or mismatched required settings; and
8. retain build-policy evidence without claiming runtime privacy behavior.

Foundation 1B must propose reviewed manifest changes when upstream invalidates
an assumption. It must not silently drop a requirement or reinterpret a missing
setting as success.
