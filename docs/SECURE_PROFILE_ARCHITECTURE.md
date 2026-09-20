# Experimental Secure-Profile Architecture

## Status

This document is the reconciled design baseline for the proposed Securium
secure profile. It is an experimental architecture, not an implementation or a
qualification result.

```text
SECURE-PROFILE CORE DESIGN: strong candidate
FOUNDATION 1: ready for experimental implementation on a Chromium-capable worker
SECURE-PROFILE ARCHITECTURE: not runtime-qualified
PROJECT QUALIFICATION: STATIC
```

The baseline reconciles two architecture reviews against Chromium M153 source
at commit `78e5e45d4bb41035e17ea4da2cc257f496416ac9`. That research revision is an
evidence reference, not canonical candidate state; `state/upstream.json` remains
the only project-state authority.

## Evidence vocabulary

These labels describe individual architecture claims. They do not replace the
ordered project qualification levels in `docs/QUALIFICATION.md`.

- **DOCUMENTED:** stated by an applicable primary specification or upstream
  Chromium documentation.
- **IMPLEMENTATION-DERIVED:** observed directly in source at the named exact
  Chromium SHA.
- **INFERRED:** a reasoned conclusion that has not been demonstrated in the
  intended runtime.
- **EXPERIMENTAL:** a Securium design choice awaiting implementation evidence.
- **QUALIFIED:** demonstrated by the applicable Securium qualification gate for
  an exact revision, platform, configuration, and retained evidence.

Agreement between reviews does not make a claim `QUALIFIED`.

## Reconciled candidate

```text
browser-level protected-profile registry
        |
protected profile selected by stable early identity
        |
unlock orchestrator
        |
external slot authorization
        |
recover random per-profile PEK
        |
optional separately-qualified App-Bound envelope requirement
        |
SecureProfileCryptoContext
        |
single Securium KeyProvider
        |
profile-owned OSCryptAsync / Encryptor
        |
explicitly classified profile-sensitive Chromium consumers
```

Ordinary profiles continue to use the upstream browser-global
`g_browser_process->os_crypt_async()` and its normal provider behavior.

The random 256-bit Profile Encryption Key (PEK) is the protected profile's
Chromium encryption key. Securium should not add a second encryption layer to
each Chromium value. External provider slots protect the PEK, and Chromium's
existing `Encryptor` protects only the explicitly inventoried OSCrypt surface.

This is not whole-profile encryption. History, ordinary Autofill fields, web
storage, IndexedDB, profile metadata, and other non-OSCrypt stores remain
outside the claim unless separately inventoried and qualified.

## Locked lifecycle and early identity

M153 `OSCryptAsync` records a `kTemporarilyUnavailable` provider entry, finishes
initialization, and caches the resulting Encryptor. Later `GetInstance()` calls
return that cached object rather than automatically querying the provider again.
This is **IMPLEMENTATION-DERIVED**.

Therefore the experimental lifecycle is:

```text
PROTECTED_LOCKED
        |
unlock orchestrator
        |
recover PEK
        |
construct SecureProfileCryptoContext
        |
construct profile OSCryptAsync
        |
SecureProfileKeyProvider immediately supplies the PEK
        |
initialize protected profile runtime
```

**Locked is a Securium profile-lifecycle state, not an unavailable state inside
an already-initialized `OSCryptAsync`.** Cancellation destroys the pending
protected-profile construction. Foundation 1 must not use a completed
temporarily-unavailable provider as a reusable lock/unlock transition.

M153 also supplies browser-global OSCrypt while constructing profile preference
and tracked-preference infrastructure before `ProfileImpl::DoFinalInit()`. This
is **IMPLEMENTATION-DERIVED** and moves the unlock boundary earlier than the
initial review assumed. A browser-level structural registry must identify a
protected profile before full protected `ProfileImpl` construction.

The routing contract must not be frozen around `Profile*`. Foundation 1 may
resolve by stable profile path or identity, `ProfileKey`, or another early
identity, with later `Profile*` convenience access layered on top.

## Provider composition

A protected profile's runtime `OSCryptAsync` has one normal provider:

```text
SecureProfileKeyProvider -> authorized PEK
```

It does not include DPAPI, Chromium App-Bound, FIDO, Hello, or recovery as
parallel OSCrypt providers. Upstream provider precedence means preference, not
mandatory success; adding a higher-precedence Securium provider to the global
set would permit an unintended lower-provider fallback.

FIDO, Windows, and recovery mechanisms are Securium key slots used before the
Chromium-facing provider is constructed. An unwrap failure must not create a
replacement PEK.

### App-Bound

App-Bound remains a possible additional `AND` requirement only for packaging
and elevation-service configurations that are separately qualified. M153's
`AppBoundEncryptionProviderWin` can regenerate its managed key after some
permanent retrieval failures. That is incompatible with Securium's
no-replacement invariant, so it must not be the Securium PEK provider.

The candidate direction is to apply the lower-level App-Bound encrypt/decrypt
primitive to the Securium slot envelope and persist any upstream-requested
re-encryption failure-atomically. The security claim is limited to the
application/path/isolation properties actually demonstrated for Securium's
eventual installation. It is not described as authentication of a signed
Securium executable.

## FIDO candidate hierarchy

```text
credential
        |
UV-associated WebAuthn PRF or CTAP hmac-secret-derived secret
        |
Securium domain-separated KDF
        |
KEK
        |
AEAD unwrap
        |
random profile PEK
```

WebAuthn `prf` and CTAP `hmac-secret` are related protocol mechanisms, not
interchangeable names. A future native `device/fido` adapter acts closer to a
CTAP client and must specify credential/RP namespace, UV and presence rules,
credential persistence, PRF input and domain separation, cancellation, and
PIN/UV retry semantics. The exact protocol remains Foundation 2 work.

The random PEK remains independent of any one provider. Multiple authorized
slots may wrap the same PEK without re-encrypting Chromium data.

## Windows candidate status

```text
TPM-backed CNG: plausible
exact Hello/per-unlock primitive: unresolved
```

No Windows provider or signature-derived shortcut is selected. TPM key
non-exportability does not by itself prove a Windows Hello verification prompt
for every unwrap.

## Consumer inventory

At every adopted exact Chromium SHA, qualification must mechanically enumerate
relevant OSCrypt acquisitions and classify each one as:

```text
browser-global
profile-sensitive -> route
feature-gated profile-sensitive -> route and test when active
migration-only
irrelevant
```

The retained artifact must include source path and symbol, classification,
rationale, feature/configuration conditions, intended route, and applicable
test. A changed or newly introduced profile-relevant acquisition that remains
unclassified blocks adoption. Consumers must be classified, not blindly routed.

The M153 research inventory includes early preference/tracked-preference
infrastructure, profile and account password stores, WebData, password reuse,
normal persistent cookies, extension cookies, Sync, GCM, WebAuthn enclave
state, session/tab restore, bookmarks, history embeddings, and page-content
storage paths. This is a research seed, not a complete qualification artifact.

Session/restore requires configuration-sensitive wording. M153 contains an
OSCrypt-backed encrypted session backend and global OSCrypt acquisitions, while
the reviewed source default is disabled/clear-only. Deployment or Variations
state may differ. Session/restore therefore stays in the recurring inventory,
and Securium may claim protection only for configurations actually qualified.

## Runtime boundary

Foundation 1 and v1 use startup unlock followed by effective profile/browser
teardown to return to locked state. Discarding the root PEK does not revoke
Encryptors, decrypted database values, cookies, tokens, caches, IPC copies, or
other runtime material. Runtime relock remains deferred until full profile
runtime teardown and revocation can be demonstrated.

The narrow target property is:

> Possession of copied profile files alone is insufficient to recover the
> explicitly qualified OSCrypt-covered secrets of a protected profile.

It does not protect an unlocked browser from compromised trusted processes,
elevated compromise, a malicious update, or stores outside the qualified
inventory.

## Evidence baseline

The following M153 observations are inputs to the experiment, not Securium
runtime evidence:

| Claim | Status |
| --- | --- |
| Chrome owns a browser-global `OSCryptAsync` and supports pluggable providers | DOCUMENTED |
| Temporary-unavailable can complete initialization with a cached Encryptor | IMPLEMENTATION-DERIVED |
| Profile preference construction receives global OSCrypt before final initialization | IMPLEMENTATION-DERIVED |
| Profile/account password, WebData, normal cookie, and extension-cookie paths acquire global OSCrypt | IMPLEMENTATION-DERIVED |
| An independently owned `OSCryptAsync` can be constructed | IMPLEMENTATION-DERIVED class shape |
| Simultaneous profile-owned instances are safe throughout Chrome lifecycle | EXPERIMENTAL |
| App-Bound lower-level primitives can envelope arbitrary Securium slot bytes | INFERRED from API shape; EXPERIMENTAL in Securium packaging |
| M153 includes session encryption infrastructure with a reviewed clear/disabled source default | IMPLEMENTATION-DERIVED |
| TPM-backed CNG can hold non-exportable key material | DOCUMENTED |
| A selected Hello primitive supplies the required per-unlock semantics | EXPERIMENTAL and unresolved |

Primary evidence links are pinned where possible:

- [M153 OSCryptAsync implementation](https://chromium.googlesource.com/chromium/src/+/78e5e45d4bb41035e17ea4da2cc257f496416ac9/components/os_crypt/async/browser/os_crypt_async.cc)
- [M153 ProfileImpl preference construction](https://chromium.googlesource.com/chromium/src/+/78e5e45d4bb41035e17ea4da2cc257f496416ac9/chrome/browser/profiles/profile_impl.cc)
- [M153 App-Bound provider](https://chromium.googlesource.com/chromium/src/+/78e5e45d4bb41035e17ea4da2cc257f496416ac9/chrome/browser/os_crypt/app_bound_encryption_provider_win.cc)
- [M153 profile password store](https://chromium.googlesource.com/chromium/src/+/78e5e45d4bb41035e17ea4da2cc257f496416ac9/chrome/browser/password_manager/factories/profile_password_store_factory.cc)
- [M153 account password store](https://chromium.googlesource.com/chromium/src/+/78e5e45d4bb41035e17ea4da2cc257f496416ac9/chrome/browser/password_manager/factories/account_password_store_factory.cc)
- [M153 profile network context](https://chromium.googlesource.com/chromium/src/+/78e5e45d4bb41035e17ea4da2cc257f496416ac9/chrome/browser/net/profile_network_context_service.cc)
- [M153 extension cookie store](https://chromium.googlesource.com/chromium/src/+/78e5e45d4bb41035e17ea4da2cc257f496416ac9/chrome/browser/extensions/chrome_extension_cookies.cc)

## Unresolved assumptions

- Chrome lifecycle safely supports one profile-owned `OSCryptAsync` per active
  protected profile.
- A stable early profile identity can route every required acquisition before
  full `ProfileImpl` construction.
- Network-service restart and all relevant storage partitions can rebind the
  correct profile Encryptor without reacquiring the global instance.
- OTR/incognito inheritance and profile destruction can avoid stale context
  reuse.
- The exact-SHA consumer inventory can be made mechanically complete enough to
  block silent boundary regressions.
- Eventual FIDO, Windows, App-Bound, recovery, and migration designs satisfy
  their separate security and failure requirements.

`docs/SECURE_PROFILE_FOUNDATION_1.md` defines the next experiment that may test
the routing and lifecycle assumptions. It does not implement them.
