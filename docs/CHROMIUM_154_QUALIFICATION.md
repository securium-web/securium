# Chromium 154 qualification record

Baseline: Chromium **154.0.8037.58**,
`a654841425914cbb703a2931e07b70a83aedbafd`. Worker: `dockerbox` / HostPC;
all source, integration, caches and build outputs are on D: under
`D:\Sandbox\Codex\Securium`. This record does not qualify a release.

## Patch review and adoption

`patches/0001-guard-compose-build-dependencies.patch` is the only canonical
copy. SHA-256: `222dfbfeb05c018be9f0816d6b6683cd753ee6675576b4a54269236f690822cf`.
Ordered-series name digest:
`b50b2589f6aa8b6934c68cb96d6cdaaa309a8f3d167a6a69baea570e3c5c405f`.
Content identity also requires the per-patch digest; the series-name digest
alone does not identify patch bytes.

Independent source/diff review passed. The diff is unchanged from the reviewed
candidate (four files, 30 insertions and 9 deletions); only its explanatory
preamble/name changed. Context-menu implementation/test dependencies and
settings implementation follow existing `enable_compose` conventions. Their
C++ consumers already have Compose guards. No runtime functionality is edited.
Glic's dependency is in its test-only interactive target: the sole helper use
is `ComposeEnabling::ScopedEnableComposeForTesting()` in
`RefreshSettingsAfterAcceptingFRE`. This keeps AI Settings visible before Glic
FRE. Only that scenario, its include and two identifiers receive
`BUILDFLAG(ENABLE_COMPOSE)` guards. The mixed source and seven other tests
remain unchanged, including upstream's already-disabled test. No production
Glic dependency was found by the exact-source search. No privacy policy changed.

## Real PATCH-APPLY

**PASS**, `synthetic=false`, `engine_validation=REAL_CHROMIUM`.
The prior candidate was reverse-checked and reversed; the official-origin root
was clean at the exact requested SHA. The real adapter created a clean detached
worktree, materialized the empty downstream source set and used the existing
engine's strict check/application sequence. No recovery, three-way or reject
mode was used. The original source remained clean.

Worker evidence: `Qualification/Compose-001/evidence.json`; local retained copy:
`artifacts/real-patch-apply-001.json`. Integration:
`Qualification/Compose-001/integration`. Run: 2026-09-23
09:15:23–09:17:58 UTC. Upstream tree:
`63b6339af403b6f8dc70fe2d4613f91f1c04f43a`.
Integration diff digest:
`7b57e53737bb7c09568e65e8fe803028ae316c3589fb9907bb95b7521634d7ac`.

## Build-policy interpretation

All ten canonical settings remain required. Lens may be compiled under its
separately approved `USER_TRIGGERED_SERVICE` / `USER_INITIATED` policy; no Lens
compile-out argument is supplied. Disclosure and absence of background context
transmission remain unqualified runtime requirements. Compose remains false.

At this exact SHA, empty GN credential strings omit the key defines from
`google_apis:google_apis`. With official keys and Chrome branding false,
`default_api_keys-inc.cc` uses `DefaultApiKeys::kUnsetApiToken` (`dummytoken`)
for unset keys/client tokens, and empty strings for default OAuth fallbacks.
`ApiKeyCache::HasAPIKeyConfigured()` rejects the sentinel. This is absence of
a supplied global credential, not a claim that every in-memory field is empty.
No credential policy is relaxed. `api_key_cache.cc` still permits unbranded
environment, Gaia configuration, command-line and feature overrides; those
must be detected/rejected in future launch/runtime qualification. The build
gate checks its process and saved user/machine environments without recording
secret values. It does not certify future launches.

`verify_foundation_1b.py` only accepts this reviewed SHA, matching real patch
and GN evidence, current effective arguments, generated policy headers, absent
global credential defines and the Compose product target exclusion. A new SHA
requires renewed semantic review. Shared Compose component helpers and Mojo
interfaces are classified separately from the excluded browser implementation
and UI; their presence is not full product inclusion or proof of no traffic.

## Current execution status

**GN PASS; Foundation 1B build-only PASS. First COMPILE attempt FAIL.**
Original output: `Qualification/Compose-001/integration/out/SecuriumWinX64`.
`build-policy.json` records the successful GN command and ten matching values;
`foundation-1b-final.json` completes the generated-header/target/source review
and binds the canonical patch bytes to the integrated series. The
six requested header actions passed (seven actions including module-map
generation), without compiling Chromium. Credential defines are absent and
process/current-user/machine environments contain no nonempty overrides.

The complete target inventory and recursive `//chrome:chrome` closure exclude
Compose browser implementation, views, WebUI and resources. Retained support
includes component manager/configuration/metrics/utilities/features/HaTS and
common/component Mojo bindings. No unrelated Glic or Lens targets are removed.
Inventory digest: `2fb67d6445fcf2df1f5cf48c4cfb9254dc53d8c30f63963c7878a50056df84f8`;
production closure: `8462d8b524542e5295b3663fc25fec8c8ebe374097137ab4a52d7bb8e2c2324f`.

Dependency hydration completed without overwriting existing integration files
or copying the old output directory; patch diff and hashes still match. All
155 processed Git dependency HEADs match the recorded successful sync inventory.
`dependency-verification.json` binds it to sync digest
`b7f919a36dc6abbe84d39449729a801bc74a383201ae353ab09e4c45bb6b2a38`.
CIPD/GCS packages were copied from that sync; this is not an independent
cryptographic re-attestation of every ignored dependency byte. The worker had
176.3 GiB free afterward. Existing source and caches were preserved.

Manifest digest: `945dd4e0a6d2dbd9564acb34e42d98a08917874bd2798adf263e0872056ee108`.
Effective configuration: Windows x64, release component build, symbol level 0;
Compose/RLZ/updater/update-notifications/Chrome-branding/official-keys false;
Safe Browsing mode 1; API key/default OAuth ID/secret empty. Lens uses upstream
defaults. `use_siso=true`, `use_remoteexec=false`.

Toolchain inventory: VS Build Tools 2026 `18.10.12217.157` (display `18.10.2`),
MSVC `14.51.36231`, ATL/MFC present, Windows SDK `10.0.28000.2526`
(directory `10.0.28000.0`), debugging tools `10.0.26100.6584`, depot_tools
`fec3a9ed6127f4a8357bb60bd474a7309ab46108`, GN `2540 (150a9d6ba0aa)`.

All 105 offline static tests and repository validation passed on the worker.
Canonical candidate/qualified/released state is unchanged. No TEST, RUNTIME,
network, security or release qualification follows from these results.

## First compile execution

Started **2026-09-23 09:29:09 UTC** from Securium commit
`d4c0f76dc18656c6c866d8c0d605445247963e1c` (repository tree
`d0b8ac90ceb80962179b6769ef372365f5211b2b`). That exact snapshot passed all
105 offline tests and repository/build/network validators before launch.
The normal push to `origin/main` succeeded and
[hosted static CI passed](https://github.com/securium-web/securium/actions/runs/35843226591).

Command from the disposable integration root:

```text
D:\Sandbox\Codex\Securium\Tools\depot_tools\autoninja.bat -C out/SecuriumWinX64 -j 4 chrome
```

Autoninja resolved this to Siso offline execution with `-local_jobs=4`.
Chromium's bundled Clang is the C/C++ compiler: `24.0.0git`, LLVM revision
`9fca3cf47d011a0af295d4252d70f16f8693d6a2`; VS/MSVC and the SDK supply the
Windows toolchain environment/headers/libraries. Actual Clang module and Rust
compilation processes were observed. No completed Chromium build is claimed.

Worker `Qualification/Compose-001/compile.json` records source commit, patch
digests, manifest/effective settings, toolchain, command, PID, timestamps and
eventual exit status/duration. `compile.log` retains compiler/linker output.
The first attempt ended **2026-09-23 09:36:52 UTC**, exit 1, after **463.250
seconds** (7 minutes 43 seconds). Siso recorded 5,978 completed steps and one
failed action; it did not finish the Chromium target.
Follow-up documentation commits do not change the recorded build input commit.

## Windows path-length failure and narrow correction

The failing action was
`//third_party/blink/renderer/bindings:generate_bindings_union`. Bundled Python
raised `FileNotFoundError` while opening a generated header for writing through
`web_idl/file_io.py:45`. Its parent directory existed, but the absolute path
was 265 characters and the worker's `LongPathsEnabled` setting was zero.
The filename ends in
`v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h`.
This is a Windows build-path limitation, not a Compose/Glic source dependency
or compiler/linker diagnostic. No production source, patch, privacy setting,
test expectation or machine-wide registry setting was changed.

The existing output directory was moved within the same verified task-owned
`out/` parent to `out/S`, reducing the failing path to 253 characters and
preserving all incremental files. The original failure evidence/log and a copy
of the failed command remain in `Qualification/Compose-001/`. Build-policy
collection now supports explicit `--reuse-output` only for an unchanged real
integration and identical canonical arguments. GN generation/effective-value
comparison is rerun, not skipped, and new evidence files preserve prior results.
GN and Foundation 1B passed again in `build-policy-002.json` and
`foundation-1b-002.json`; unchanged patch integration hashes were checked before
and after. The focused Blink union retry **passed in 25.84 seconds** (eight
actions), including the previously failing header, without changing its source.
Its log is `blink-union-retry.log`. All 107 offline static tests and existing
repository/build/network validators passed after the collector reuse change.

Next task: resume the incremental compile with `autoninja -C out/S -j 4 chrome`.
Collect its result and inspect any further compiler/linker failure. Narrow
Compose/build-policy corrections must rerun the affected gates; unrelated
production, privacy or test-boundary changes require review. Do not advance
TEST, runtime, secure-profile, packaging or release work from this run.
