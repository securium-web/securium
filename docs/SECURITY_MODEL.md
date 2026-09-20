# Security Model

This document establishes scope and durable invariants. It does not approve a
platform key provider, cryptographic protocol, migration design, or production
implementation. The reconciled experimental design and its unresolved
assumptions are in `docs/SECURE_PROFILE_ARCHITECTURE.md`.

## Threat classes

| Threat class | Intended direction | Current status |
| --- | --- | --- |
| Stolen or copied profile directory | Require external key material for explicitly protected secrets | Not implemented |
| Another non-elevated local user | Rely on reviewed OS isolation plus external key policy | Not implemented |
| Offline disk access | Avoid profile-only material being sufficient to recover protected secrets | Not implemented |
| Malware before unlock | Fail closed when required key material or authentication is unavailable | Not implemented |
| Malware while Chromium is unlocked | Separate threat; secrets may be available to a compromised process | Non-goal for profile-at-rest controls |
| Elevated user or local administrator compromise | Outside the guarantee of profile-at-rest controls | Non-goal |
| Compromised update infrastructure | Require independently anchored artifact and metadata trust | Future requirement |

Stronger at-rest protection can reduce the value of copied profile data; it
cannot categorically prevent malware on an already compromised or unlocked
machine from accessing secrets.

## Provisional core requirements

- An explicitly protected profile must not silently downgrade.
- Inaccessible required key material must fail closed.
- Protected secrets must not be persisted in plaintext.
- Migration must avoid destructive key regeneration and preserve recoverability
  according to an approved design.
- Key separation and authentication requirements must survive upstream repairs.
- Updater trust must be cryptographically anchored independently of ordinary
  transport trust.
- Each protected profile must use a cryptographically independent random PEK.
- Locked state must remain above the protected profile's `OSCryptAsync`; the PEK
  is recovered before constructing that crypto context and profile runtime.
- A protected profile's runtime OSCrypt provider set must not include ordinary
  DPAPI or App-Bound fallback providers.
- Ordinary profiles must retain upstream browser-global OSCrypt behavior.
- Failure to recover an existing PEK must never generate a replacement PEK.
- Protected claims must remain limited to the exact, qualified OSCrypt consumer
  inventory and configuration.
- Every adopted Chromium SHA must classify new and changed profile-relevant
  OSCrypt acquisitions before secure-profile qualification can pass.
- Unlock admits receiving Chromium processes and Encryptors into the trusted
  runtime boundary; discarding the PEK alone is not runtime relock.
- Browser-native network capabilities and connections must map to approved
  semantic service policy. New or materially changed unclassified native
  capabilities block network qualification; hostnames alone do not establish
  service identity.

These are requirements, not implementation claims. Their precise meaning,
platform behavior, recovery model, cryptographic choices, and test oracles must
be established by a dedicated design review. Any change affecting these
semantics requires explicit security review even if patches apply and tests pass.

The network/service invariant does not promise traffic anonymity, whole-browser
network silence, or control of destinations chosen by users, sites, or
extensions. Foundation 0 is a static specification only; its scope and future
runtime mismatch rules are defined in `docs/NETWORK_SERVICE_POLICY.md`.

## Experimental provider directions

The current architecture supports further experiments, not provider approval:

- FIDO uses a UV-associated WebAuthn PRF or CTAP `hmac-secret`-derived secret,
  a Securium domain-separated KDF, a KEK, and AEAD unwrap of the random PEK.
  WebAuthn `prf` and CTAP `hmac-secret` are not interchangeable protocol names.
- TPM-backed CNG is plausible; the exact Windows Hello per-unlock primitive is
  unresolved.
- App-Bound may become an additional `AND` envelope requirement only after
  Securium packaging is qualified. The regenerating Chromium App-Bound
  `KeyProvider` is not a Securium PEK provider.
- v1 returns to locked state through effective profile/browser teardown.
  Runtime relock remains deferred.
