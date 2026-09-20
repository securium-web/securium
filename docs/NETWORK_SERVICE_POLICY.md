# Privacy Foundation 0: Network and Service Policy

Status: `STATIC`

This document defines Securium's canonical policy vocabulary for browser-native
network services. It is a specification and deterministic static comparison
contract. It does not prove that Chromium implements the policy, that a build
emits only approved traffic, or that any network behavior has been runtime
qualified.

## Scope and authority

The canonical policy is `policy/network-service-policy.json`, validated against
`policy/network-service-policy.schema.json` and the stricter deterministic
checks in `scripts/network_policy.py`.

Browser-native traffic is traffic initiated by browser-owned service logic
rather than by navigation or fetch behavior attributable to a user-requested
page, a site, or an extension. A native browser capability and any observed
native connection must map to an approved service policy. A new or materially
changed, unclassified native capability blocks network qualification.

This policy is not a hostname blocklist. Service identity is semantic: the
initiator, trigger, destination class, data categories, credential mode,
activation gates, and provider boundary together identify the capability.
Hostnames and URL constraints can narrow expected destinations, but cannot by
themselves prove which service initiated traffic or whether it was allowed.

## Four separate artifacts

The privacy qualification design deliberately separates four artifacts:

1. **Service policy manifest** — the product decision recorded now. It defines
   approved, denied, replaced, and pending semantics independent of a Chromium
   revision.
2. **Exact-SHA source inventory** — a future mechanically generated mapping of
   network-capable Chromium source at one verified commit SHA to policy service
   identities. Source locations are evidence, not stable service identity.
3. **Runtime observation** — future scenario-scoped evidence describing actual
   connections and the conditions or user actions present when they occurred.
4. **Network qualification result** — a deterministic comparison of the policy,
   inventory delta, and runtime observations. It records mismatches without
   changing canonical candidate, qualified, or released state.

Foundation 0 supplies only the first artifact and a synthetic comparison engine
for invented evidence. Chromium-derived inventories and runtime observations do
not exist yet.

## Traffic origin classes

- `BROWSER_NATIVE_BACKGROUND`: browser-owned work that may run without a
  contemporaneous user action or site request.
- `BROWSER_NATIVE_CONDITIONAL`: browser-owned work allowed only while an
  explicit policy condition is satisfied.
- `USER_TRIGGERED_SERVICE`: browser-owned service traffic caused by a specific,
  recorded user action.
- `USER_REQUESTED_WEB`: ordinary navigation, subresource, or fetch traffic
  resulting from a user's web request. It is outside native service policy.
- `SITE_DIRECTED`: traffic attributable to site behavior, including site
  reporting and service-worker activity.
- `EXTENSION_DIRECTED`: traffic attributable to an installed extension.

User-requested web, site-directed, and extension-directed traffic remains
separately attributable. It is not reclassified as approved browser-native
traffic merely because it uses Chromium networking code.

## Policy states

- `ALLOW_BACKGROUND`: the named native service may operate in the background,
  subject to its full semantic policy.
- `CONDITIONAL`: the named native service may operate only when its declared
  activation condition is satisfied.
- `USER_INITIATED`: the named native service may operate only after its declared
  user action.
- `SITE_DIRECTED`: traffic is attributable to a site, not a native service.
- `EXTENSION_DIRECTED`: traffic is attributable to an extension, not a native
  service.
- `DENY`: the service must not make a remote connection.
- `REPLACED`: the upstream provider must not be observed; an explicitly named
  replacement owns the approved boundary.
- `UNCLASSIFIED`: no decision has been approved. Native capabilities in this
  state fail qualification.

`APPROVED` means the product policy decision is canonical. It does not mean the
Chromium implementation is qualified. `PENDING_REVIEW` can be paired only with
`UNCLASSIFIED` and cannot define passing scenarios.

## Destination classes

The bounded destination taxonomy is:

- `GOOGLE_OWNED_SERVICE`
- `SECURIUM_SERVICE`
- `USER_SELECTED_PROVIDER`
- `SITE_CONTROLLED`
- `EXTENSION_CONTROLLED`
- `LOCAL_OR_LOCAL_NETWORK`
- `OTHER_THIRD_PARTY_SERVICE`
- `DYNAMIC_OR_UNKNOWN`

Destination constraints may record a hostname, hostname suffix, URL prefix, or
policy-selected value. They are secondary restrictions, never service identity.

## Data categories

The bounded data taxonomy is:

`CLIENT_VERSION`, `OS_PLATFORM`, `HARDWARE_CAPABILITIES`,
`COMPONENT_IDENTIFIERS`, `NETWORK_ADDRESS`, `URL`, `URL_HASH_OR_PREFIX`,
`SEARCH_INPUT`, `PAGE_CONTENT`, `TEXT_INPUT`, `GEOLOCATION_NETWORK_DATA`,
`ACCOUNT_IDENTITY`, `AUTHENTICATION_MATERIAL`, `EXTENSION_IDENTIFIERS`,
`SECURITY_INCIDENT_DATA`, `DIAGNOSTIC_DATA`, `MODEL_REQUEST_METADATA`,
`CONNECTIVITY_PROBE`, and `OTHER`.

These categories bound the policy vocabulary; they are not assertions that all
payload fields at a future exact Chromium SHA have already been identified.

## Credential modes

The bounded credential taxonomy is:

- `NONE`
- `SERVICE_SPECIFIC_API_CREDENTIAL`
- `BROWSER_ACCOUNT_OAUTH`
- `COOKIES`
- `SITE_CONTROLLED`
- `EXTENSION_CONTROLLED`

Changing the credential mode is a material semantic change even when a request
continues to use the same destination.

## Canonical service record

Every service record has a stable `service_id`, display name, traffic origin,
policy state and review status, destination and data classifications, credential
modes, a semantic trigger, optional condition or user action, build/feature/
policy/preference/provider control references, optional replacement boundary,
future exact-SHA mapping hints, qualification scenarios, and rationale.

Lists and service records are sorted and unique. Unknown fields, unsafe source
paths, invalid enum combinations, an empty rationale, and nondeterministic JSON
fail validation. The JSON Schema is a portable format contract; the Python
validator additionally enforces cross-field and deterministic-order rules.

## Exact-SHA inventory and adoption delta

A future inventory is bound to a full 40-character Chromium commit SHA and
version. Each capability records a stable inventory identifier, its mapped
service (or `null`), initiator, trigger, destinations, data, credentials,
activation gates, provider boundary, and source mapping.

On Chromium adoption:

- a new native capability without an approved policy mapping fails;
- a change to trigger, destination, data, credential, activation gate,
  initiator, provider, or service mapping is material and fails pending review;
- removal is recorded but does not fail;
- a source-path or traffic-annotation-only change requires remapping and
  revalidation but does not rewrite product policy;
- user-requested web behavior is not promoted into native policy;
- site and extension traffic remains separately attributed.

This makes source mapping replaceable across revisions while preserving stable
semantic policy decisions.

## Runtime comparison rules

A future observation is scoped to a named scenario and records satisfied
conditions, user actions, and classified connections. Comparison fails when:

- a native connection is unclassified or maps to a pending policy;
- a `DENY` service is observed;
- a `CONDITIONAL` service is observed without its condition;
- a `USER_INITIATED` service is observed without its user action;
- the upstream side of a `REPLACED` service is observed;
- the observed initiator, trigger, destination class, data, credential, or
  provider semantics exceed the approved policy; or
- a service marked `MUST_OBSERVE` for that scenario is absent.

Absence does not otherwise prove success. `MAY_OBSERVE` permits either outcome,
and `MUST_NOT_OBSERVE` fails if the service appears. Runtime comparison must not
promote repository qualification or mutate upstream state.

## Initial approved policy

Foundation 0 establishes only these high-level product decisions:

| Service | Decision | Boundary |
| --- | --- | --- |
| Remote metrics reporting | `DENY` | Remote reporting is denied; local diagnostics are separate. |
| Crashpad remote upload | `DENY` | Local capture may remain; remote upload is denied. |
| Safe Browsing Standard Protection | `ALLOW_BACKGROUND` | Retained at a high level; exact requests and credentials require exact-SHA qualification. |
| Chrome browser updater | `DENY` | Browser self-update is outside the downstream update model. |
| Component Updater | `ALLOW_BACKGROUND` | Retained at a high level for security components; exact providers require qualification. |

Ordinary `USER_REQUESTED_WEB` traffic is outside the native service policy.
`SITE_DIRECTED` and `EXTENSION_DIRECTED` traffic is separately attributed and
is not an implicit browser-native allowance.

The initial policy intentionally leaves destination constraints and source
mapping hints empty. Filling them without exact-SHA evidence would manufacture
precision.

## Explicitly unresolved

No policy decision is made here for Variations, Domain Reliability, GCM,
network geolocation providers, network time, Certificate Transparency
enforcement/update behavior, or other services found by the future exact-SHA
inventory. Their triggers, credentials, provider boundaries, privacy tradeoffs,
and required security behavior remain pending. Discovery of any such native
capability yields an unclassified failure until review produces a canonical
policy amendment.

## Qualification boundary and next foundation

The comparison tooling and tests use invented evidence only. They demonstrate
schema, classification, delta, and mismatch logic at `STATIC`; they do not
provide `PATCH-APPLY`, `COMPILE`, `TEST`, `RUNTIME`, or security evidence for
Chromium.

The next task is **Privacy Foundation 1 — Build Policy Manifest** on a
Chromium-capable worker. It should generate the first exact-SHA source inventory,
map every native network capability or fail it as unclassified, preserve the
four-artifact separation above, and propose policy amendments without silently
approving them.
