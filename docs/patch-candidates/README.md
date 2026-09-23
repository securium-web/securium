# Compose candidate provenance

The reviewed candidate has been adopted as the sole canonical patch:
[`0001-guard-compose-build-dependencies.patch`](../../patches/0001-guard-compose-build-dependencies.patch).
Do not maintain a candidate copy here.

The original candidate SHA-256 was
`a65e75367eef5fb7dbbb7a1b2416d80453428267fe4daeef4923bfd28257ee53`.
Adoption added rationale/provenance before the unchanged Git diff. The diff
still touches four files, with 30 insertions and 9 deletions.

The earlier two-file trial stopped on Glic's mixed interactive-test dependency.
Explicit review then authorized guarding only the Compose-dependent scenario,
not dropping its mixed source file or unrelated Glic coverage. Prior candidate
GN passed with Compose disabled (34,049 targets), and an enabled control passed
(34,081 targets); neither was compilation or runtime evidence.

See [the canonical qualification record](../CHROMIUM_154_QUALIFICATION.md)
for independent review, clean exact-SHA reproduction, strict engine evidence,
current build status and retained artifacts. The source-policy investigation
remains in [COMPOSE_POLICY_REVIEW.md](../COMPOSE_POLICY_REVIEW.md).
