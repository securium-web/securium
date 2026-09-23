# Privacy Foundation 1B verification

The current exact-SHA result is in
[CHROMIUM_154_QUALIFICATION.md](CHROMIUM_154_QUALIFICATION.md). The intended
manifest remains canonical policy; per-revision verification evidence is
separate, so a successful run does not silently approve a future Chromium SHA.

## Collection and completion

`scripts/verify_build_policy.py` consumes a real qualification request and
checks exact Git HEAD, source identity, process and saved Windows credential/
compiler-injection environments. It creates a fresh output directory, runs
`gn gen --fail-on-unused-args`, and compares the declared/current argument
inventory to every manifest requirement. Missing arguments, type-sensitive
mismatches and nonempty forbidden overrides fail. Unexpected values and raw
command output are not recorded, to avoid leaking accidental credentials.

Without `--patch-evidence`, the Chromium root must be clean. With that option,
the collector requires genuine successful PATCH-APPLY evidence and checks the
resulting integration diff, file hashes and untracked content. It never writes
candidate, qualified or released state.

Example on the established Windows worker:

```powershell
python scripts/verify_build_policy.py `
  --request D:/Sandbox/Codex/Securium/Artifacts/request.json `
  --source D:/Sandbox/Codex/Securium/Qualification/Compose-001/integration `
  --gn D:/Sandbox/Codex/Securium/Qualification/Compose-001/integration/buildtools/win/gn.exe `
  --patch-evidence D:/Sandbox/Codex/Securium/Qualification/Compose-001/evidence.json `
  --output-name SecuriumWinX64 `
  --evidence D:/Sandbox/Codex/Securium/Qualification/Compose-001/build-policy.json
```

Use new evidence/output names on a retry. Exit 1 is failure; exit 2 and
`INCOMPLETE` mean the argument inventory matched but semantic/generated-target
completion remains separate. `verify_foundation_1b.py` then checks the reviewed
exact revision, unchanged real integration, current arguments, generated
buildflag headers, effective credential defines and Compose product graph
exclusion. Its PASS is scoped to the Windows x64 build, never runtime behavior.

Generate the six policy headers through the existing build system before the
completion check; header generation is not Chromium C++ compilation. The
completion script takes `--build-evidence`, `--patch-evidence` and a new
`--evidence` filename. It accepts only the explicitly reviewed Chromium SHA.
Source interpretation and unset-credential semantics are documented in the
current qualification record. Future browser launch overrides remain a
separate, fail-closed runtime requirement.

## Historical attempts and decisions

Retained artifacts are under `D:\Sandbox\Codex\Securium\Artifacts`; useful
small copies are in ignored local `artifacts/`. These historical failures
are not current gate results.

| Attempt | Observed result / resolution |
| --- | --- |
| 001 | Exact root inspection, but GN/toolchain missing; no generation. |
| Setup | User installed VS 2026 and SDK; depot_tools bootstrapped on D:. An updater test-package Defender block was later resolved by the user; no exclusion or dependency omission was introduced. Full sync and hooks then passed. |
| 002–003 | GN stopped on Lens backend assertion with desktop Lens disabled. |
| Lens trial | Guarding one test edge exposed production tab/Glic/shared consumers. Trial reversed; broad refactoring stopped for product review. |
| Lens decision | User explicitly allowed compiled/shared Lens under disclosed USER_INITIATED service policy. Removed only the required Lens compile-out setting. Silent/background context transmission remains prohibited. |
| 004 | Canonical revised settings reached the independent Compose assertion through context-menu dependencies. |
| Two-file Compose trial | Four missing GN guards reached Glic's mixed interactive-test helper. Work stopped at the C++/test review boundary. |
| Reviewed four-file candidate | User authorized guarding only the Compose-dependent Glic scenario. Canonical false-value GN and an enabled control both passed. No compilation/runtime claim followed. |
| Real adoption | Clean exact-SHA worktree and canonical strict patch engine passed; see the current qualification record for subsequent gates. |

The Compose source investigation is preserved in
[COMPOSE_POLICY_REVIEW.md](COMPOSE_POLICY_REVIEW.md). Candidate provenance is in
[patch-candidates/README.md](patch-candidates/README.md); the patch itself exists
only in `patches/`.

Environment checks cover the verifier process and saved environments for the
worker user and machine. They do not certify other accounts, future changes,
Gaia configuration, command-line or feature overrides. Root cleanliness alone
also does not certify DEPS/CIPD content; retain sync/hydration and dependency
identity evidence separately. Neither GN nor compilation qualifies Lens,
Compose, Safe Browsing, updater or credential behavior at runtime.
