# Security Model

This document establishes scope and provisional invariants. It does not approve
a key provider, cryptographic protocol, migration design, or implementation.
Those require a separate architecture and threat-model review before coding.

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

These are requirements, not implementation claims. Their precise meaning,
platform behavior, recovery model, cryptographic choices, and test oracles must
be established by a dedicated design review. Any change affecting these
semantics requires explicit security review even if patches apply and tests pass.
