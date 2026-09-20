# Secure Profile Foundation 1

## Profile Crypto Routing Experiment

## Purpose and status

Foundation 1 is the next experimental Chromium slice. It exists only to prove
profile crypto ownership, early lifecycle, routing, isolation, and fail-closed
assumptions with a synthetic test PEK/provider.

```text
FOUNDATION 1: ready for experimental implementation
IMPLEMENTATION ENVIRONMENT: Chromium-capable worker required
CURRENT IMPLEMENTATION: none
CURRENT EVIDENCE: none
PROJECT QUALIFICATION: STATIC
```

Foundation 1 must not add FIDO, Windows Hello, TPM, recovery, migration,
App-Bound composition, packaging, or production key-slot cryptography.

## Experimental architecture

```text
browser-level protected-profile registry
        |
synthetic unlock before full protected-profile construction
        |
synthetic PEK available
        |
SecureProfileCryptoContext
        |
profile-owned OSCryptAsync
        |
single synthetic SecureProfileKeyProvider
        |
profile-specific Encryptor
```

The synthetic PEK must be deterministic or explicitly supplied by the test
harness, exist only for experiment execution, and never be represented as a
production key. `SecureProfileKeyProvider` immediately supplies the recovered
PEK when the profile `OSCryptAsync` begins initialization.

Locked is modeled above `OSCryptAsync`:

```text
PROTECTED_LOCKED
        |
synthetic unlock
        |
recover synthetic PEK
        |
construct crypto context and OSCryptAsync
        |
construct protected profile runtime
```

Foundation 1 must not initialize `OSCryptAsync` with
`kTemporarilyUnavailable` and later expect the same instance to retry.

## Early routing boundary

The browser-level registry must identify protected status without trusting the
target profile's own preferences. The experiment must find the earliest stable
identity usable before crypto-dependent `ProfileImpl` construction. Candidate
keys include stable profile identity/path and `ProfileKey`; a `Profile*`-only
API must not be frozen prematurely.

The experiment must instrument early preference and tracked-preference OSCrypt
use. It must show either that those acquisitions route through the protected
context or, with explicit evidence, that a particular acquisition is correctly
classified outside the protected boundary.

## Provider rules

The protected profile's provider set contains exactly one synthetic Securium
provider. It contains no DPAPI or App-Bound fallback. Ordinary profiles retain
the unmodified upstream browser-global provider set.

Synthetic failure modes must include unavailable, corrupt, and wrong PEK state.
Every failure leaves the protected profile locked and must not generate a
replacement PEK.

## Required consumer inventory

Before the experiment can complete, tooling must mechanically enumerate
OSCrypt acquisitions at the exact Chromium SHA. Every relevant acquisition is
recorded with source path/symbol, feature/configuration condition, rationale,
route, and test, using exactly one classification:

```text
browser-global
profile-sensitive -> route
feature-gated profile-sensitive -> route and test when active
migration-only
irrelevant
```

The minimum directly exercised routing surface is:

- early preference/tracked-preference OSCrypt use where classification requires
  protected routing;
- profile password store;
- account password store;
- WebData;
- normal persistent cookies;
- extension cookie persistence.

The inventory must also classify all other exact-SHA acquisitions, including
feature-gated consumers such as Sync, GCM, WebAuthn enclave state,
session/tab restore, bookmarks, history embeddings, and page-content storage
where present. This list is a research seed, not an exhaustive allowlist.

No consumer is routed merely because it mentions OSCrypt. A new, changed, or
unclassified profile-relevant acquisition blocks experiment completion.

## Required experiment matrix

Run at least two simultaneous persistent profiles:

```text
Profile A = protected
Profile B = ordinary
```

Retained evidence must prove all of the following:

1. Protected-profile unlock occurs before every required crypto-dependent
   profile-construction step.
2. A and B use the intended distinct encryption roots.
3. Ciphertext written under A cannot decrypt under B.
4. B retains ordinary upstream Chromium OSCrypt behavior.
5. A has no DPAPI or App-Bound fallback inside its protected profile OSCrypt
   provider set.
6. B remains usable while A is locked.
7. Profile password storage routes correctly.
8. Account password storage routes correctly.
9. WebData routes correctly.
10. Normal persistent cookies route correctly.
11. Extension cookie persistence routes correctly.
12. Network-service restart recreates or rebinds the correct profile crypto
    path.
13. Relevant storage partitions do not unexpectedly reacquire global OSCrypt.
14. OTR/incognito behavior is explicitly classified and tested where relevant.
15. Protected profile destruction and recreation do not reuse stale crypto
    state.
16. Corrupt or unavailable synthetic provider state fails closed.
17. No failure generates a replacement PEK.
18. Early preference/tracked-preference behavior is understood and routed where
    required.
19. Every relevant OSCrypt consumer at the exact Chromium SHA is classified.
20. Newly discovered or unclassified profile-sensitive consumers prevent the
    experiment from being considered complete.

## Evidence requirements

The experiment must retain:

- exact Chromium version and SHA;
- downstream commit and applied patch/source digests;
- platform, build configuration, and feature/Variations configuration;
- mechanical consumer inventory and classification diff against the prior
  adopted SHA, when one exists;
- build and test logs;
- instrumentation showing the selected OSCrypt identity at each exercised
  consumer;
- ciphertext isolation results;
- provider-set evidence for protected and ordinary profiles;
- network restart, storage partition, OTR, and destruction/recreation results;
- negative-test evidence for unavailable, corrupt, and wrong key state;
- unresolved consumers or lifecycle observations.

A failed or incomplete inventory is evidence, not permission to narrow the
claimed surface after the fact.

## Success boundary

Foundation 1 succeeds only when the full matrix passes on a real Chromium build
at the exact revision and reviewers accept the retained inventory and runtime
evidence. Success establishes the profile routing/lifecycle architecture only.

It does not imply:

- FIDO qualification;
- Windows Hello or TPM qualification;
- App-Bound qualification;
- recovery or migration qualification;
- updater, packaging, signing, or release qualification;
- whole-profile encryption;
- runtime relock;
- complete production secure-profile readiness.

Foundation 1 evidence may contribute to `COMPILE`, `TEST`, or `RUNTIME` only
when it satisfies the independent requirements of `docs/QUALIFICATION.md`.
Creating this specification and passing repository-static checks remains only
`STATIC`.

## Exit and stop conditions

Stop and return to architecture review if:

- unlock cannot precede a required protected-profile OSCrypt acquisition;
- required consumers cannot safely accept a profile-specific Encryptor;
- an ordinary fallback remains reachable for A;
- a network or storage lifecycle loses profile identity;
- consumer enumeration cannot detect meaningful routing changes;
- profile destruction leaves reusable protected crypto state; or
- an upstream change makes any durable security invariant ambiguous.

The next implementation task must run on a Chromium-capable worker and should
produce experiment-only downstream source, minimal integration patches, the
consumer-inventory tool, tests, and retained evidence. It must not introduce a
real external provider.
