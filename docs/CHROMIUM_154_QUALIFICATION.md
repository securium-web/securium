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

**GN PASS; Foundation 1B build-only PASS. COMPILE not yet started.**
Fresh output: `Qualification/Compose-001/integration/out/SecuriumWinX64`.
`build-policy.json` records the successful GN command and ten matching values;
`foundation-1b.json` completes the generated-header/target/source review. The
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
