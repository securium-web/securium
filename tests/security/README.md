# Security Tests (Future)

This directory will contain tests that explicitly exercise approved security
invariants, including fail-closed behavior and migration safety. No security
test or security qualification exists yet. Evidence will require reviewed test
design, execution against built artifacts, retained results, and human review
of security-semantic changes.

Foundation 1 negative cases will exercise no-fallback, corrupt/unavailable/wrong
synthetic PEK state, cross-profile ciphertext isolation, and no replacement-key
generation. Passing them proves only the experiment's routing and lifecycle
boundary, not external-provider or product security qualification.
