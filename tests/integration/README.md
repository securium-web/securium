# Integration Tests (Future)

This directory will contain tests of the patched Chromium tree and its
integration with downstream-owned source. No integration harness or passing
gate exists yet. Evidence will require clean patch application to the pinned
SHA, a real Chromium build, and execution against the intended platform and
configuration; repository-static results do not satisfy this gate.

The first planned integration suite is the two-profile synthetic crypto-routing
matrix in `docs/SECURE_PROFILE_FOUNDATION_1.md`, including early construction,
consumer routing, network-service restart, storage partitions, OTR behavior,
and destruction/recreation.
