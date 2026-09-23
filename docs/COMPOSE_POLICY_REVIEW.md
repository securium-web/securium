# Compose boundary review

Status: `STATIC`; source-derived findings and diagnostic GN evidence only.
No runtime behavior, service enforcement, compilation or release is qualified.
This historical investigation preceded the subsequently authorized build-guard
repair. See `CHROMIUM_154_QUALIFICATION.md` for its adoption and current results;
the Compose runtime/privacy decision remains unchanged.

## Revision and decision

The checked-out SHA is `a654841425914cbb703a2931e07b70a83aedbafd`.
Its `chrome/VERSION` is **154.0.8037.58**, not M153. These findings must not be
represented as M153 findings. The root checkout remained clean throughout.

**Do not yet revise the canonical Compose exclusion or grant Compose a blanket
USER_INITIATED allowance.** An existing buildflag boundary is incompletely
respected by the desktop graph. Unlike Lens, inspected Compose consumers do
not establish a need to retain Compose implementation as unrelated shared
infrastructure. A small graph repair may be practical, but it has not been
implemented or proved sufficient. Independently, compiled Compose has remote
execution, navigation-hint and logging paths with different triggers. Runtime
gates need separate enforcement review before replacing compile-time exclusion.

The user explicitly requested investigation without source changes and a stop
with alternatives when ambiguous. No Chromium patch or canonical manifest/
service-policy change was made during this review.

## Exact failure and consumers

`components/compose/features.gni:7` defaults `enable_compose` to true for macOS,
Windows, Linux and ChromeOS. `chrome/browser/compose/BUILD.gn:8` asserts it.
With the canonical false value, GN reaches that assertion through
`chrome/browser/renderer_context_menu/BUILD.gn:122`, an unguarded desktop
dependency on `//chrome/browser/compose`.

Other direct references include the context-menu test-support dependencies at
lines 278/382, Settings at `chrome/browser/ui/webui/settings/BUILD.gn:204`,
Glic interactive tests at `chrome/browser/glic/BUILD.gn:1112`, and WebUI tests.
These must be audited together rather than fixing the first error alone.

The successful diagnostic graph's `gn refs` lists these direct consumers of
`//chrome/browser/compose:compose`:

| Consumer targets | Meaning |
| --- | --- |
| `//chrome/browser:browser`, Compose `:impl` | Compose implementation integration; the browser's dependency is already guarded by `enable_compose` |
| `//chrome/browser/renderer_context_menu:impl`, `:test_support` | Help Me Write menu/client integration and its tests |
| `//chrome/browser/ui:ui`, `//chrome/browser/ui/autofill:impl` | Compose dialog/autofill integration; source build files have Compose conditions |
| `//chrome/browser/ui/webui/compose:compose` | Compose WebUI |
| `//chrome/browser/ui/webui/settings:impl` | Compose eligibility and setting visibility |
| `//chrome/browser/glic:interactive_ui_tests` | Test-only dependency; `glic_settings_util_interactive_uitest.cc:208` uses `ComposeEnabling::ScopedEnableComposeForTesting()` |
| Compose `:browser_tests`, `:unit_tests`, `:test_support`; `//chrome/test:test_support`; WebUI `:browser_tests`, `:interactive_ui_tests` | Compose coverage and mixed test harness integration |

Compose itself depends on shared Optimization Guide, Autofill, content
extraction, identity, segmentation and metrics infrastructure. That direction
does **not** imply those systems need Compose to work. No inspected evidence
justifies disabling those shared systems to remove Compose. Android
`composeplate` matches are a different feature and are excluded from this list.

`render_view_context_menu.cc:1839` already guards its Compose client accessor
with `BUILDFLAG(ENABLE_COMPOSE)`. `settings_ui.cc:388` guards Compose enabling
calls and supplies false values when compiled out. The browser implementation
and Compose proto dependencies are GN-guarded at `chrome/browser/BUILD.gn:3322`
and `:3679`. This supports investigating missing graph guards, but is not proof
that all sources, resources and tests support the false configuration.

**Clean compile-out conclusion:** the argument exists, but false is demonstrably
not a working unmodified Windows desktop graph at this SHA. Other platforms or
revisions are not established. No alternative clean desktop compile-out switch
was established by this investigation.

## Execution, data and activation

`components/compose/core/browser/compose_features.cc:12` enables the Compose
runtime feature by default, as well as eligibility, inner-text collection and
proactive nudges. AX snapshot and automatic submission default off. Defaults
and field-trial parameters are not immutable privacy controls.

`ComposeEnabling::CheckEnabling` (`compose_enabling.cc:206`) checks required
services, eligibility and Compose runtime features, supported country,
sign-in/token health, and Optimization Guide user eligibility. Thus merely
compiling the code does not unconditionally execute a remote request. However,
compiled code permits activities beyond an explicitly submitted generation
request when the relevant gates are satisfied.

The generation path is `ComposeSession::Compose` / rewrite -> `MakeRequest`
-> `RequestWithSession` -> `ExecuteModelWithLogging(kCompose)`
(`compose_session.cc:415`, `:483`, `:523`, `:546`). Requests merge context with
input. The model fetcher's Compose annotation describes input text, title,
URL and page content sent to a Google-owned service
(`model_execution_fetcher_impl.cc:78`). Compose requires an access token
(`:596`); the fetcher uses POST, an authorization header and omitted cookies
(`:698-724`). Empty global API credentials are not proof these OAuth paths are
disabled, nor approval to provide credentials for them.

`MaybeRefreshPageContext` only proceeds past the first-run and MSBB checks
before collecting inner text/AX data (`compose_session.cc:1080-1107`).
Collection is local until a remote sink receives the merged request: do not
describe every collection as an upload. An optional auto-submit setting can
invoke Compose for selected text when the dialog opens. Disabling inner-text
and AX collection is not equivalent to suppressing all context: URL and title
are still populated in `TryContinueComposeWithContext` (`:1177-1200`).

## Activity without a fresh Compose invocation

1. **Navigation hints:** `ChromeComposeClient` registers the `COMPOSE`
   optimization type when eligible (`chrome_compose_client.cc:186-195`),
   without requiring a Compose invocation. The shared hints manager handles
   navigation and can fetch hosts/URLs for registered optimization types
   (`components/optimization_guide/core/hints/hints_manager.cc:1814-1912`),
   subject to its own eligibility/cache/network gates. This establishes a
   conditional pre-invocation URL-disclosure path, not a guarantee of a request
   on every navigation. `CanApplyOptimization` alone is not proof of a network
   request. Shared hints traffic needs attribution; blocking all Optimization
   Guide traffic would affect unrelated services.
2. **Proactive suggestions/training:** field activity can trigger nudges;
   country, page, MSBB, hints and preference checks apply
   (`compose_enabling.cc:273-371`). `proactive_nudge_tracker.cc:583-597` sends
   derived engagement training labels and a UKM source ID to segmentation.
   This call is not itself evidence of remote transmission; downstream
   telemetry sinks and consent need further tracing. Any resulting remote
   reporting remains subject to Securium's existing metrics denial.
3. **Quality logs:** session destruction and history replacement upload retained
   model-quality entries (`compose_session.cc:362-395`, `:751-760`), without a
   separate send-logs gesture. Upload is conditional: metrics consent, feature
   logging enablement and enterprise logging permission are checked in
   `chrome_model_quality_logs_uploader_service.cc:77-110`.
   `kComposeMqlsLogging` defaults enabled (`feature_registration.cc:75`).
   A generation action must not be treated as blanket permission for later
   diagnostic/training uploads.

No unattended generation of arbitrary page content was proved in this review.
Equally, UI eligibility/default-off behavior cannot establish that all native
service sinks are blocked in every launch configuration.

## Independent controls and limitations

| Control | What source supports | Limitation |
| --- | --- | --- |
| `HelpMeWriteSettings=2` | Upstream enterprise policy disallows Help Me Write; Compose enabling consults Optimization Guide eligibility | Must verify durable enforcement, existing sessions and every sink; not applied here |
| `HelpMeWriteSettings=1` | Allows feature use without model-improvement logging | Still permits remote execution/context; not a complete user-action boundary |
| `Compose` / `ComposeEligible` runtime features | Block normal Compose eligibility/UI and its initial hints registration | Mutable features, not a durable downstream sink policy |
| Proactive-nudge feature/preferences | Control proactive UI paths | Do not independently remove generation, hints or quality logging |
| `ComposeInnerText`, `ComposeAXSnapshot` | Separate context collection controls | URL/title persist; input/output remain sensitive |
| `ComposeAutoSubmit` | Controls automatic generation on selected text when opening a session | Explicit operation scope still needs definition |
| `ComposeMqlsLogging`, metrics consent, enterprise logging permission | Gate model-quality upload | Developer/dogfood logging override exists in `model_execution_features_controller.cc:134-143`; ordinary defaults alone are insufficient |
| Global Optimization Guide execution switch | Blocks requests checked by `ComposeSession::MakeRequest` | Too broad as a Compose-only policy; shared features may be affected |

The policy definition is
`components/policy/resources/templates/policy_definitions/GenerativeAI/HelpMeWriteSettings.yaml`.
Its values distinguish allow-with-model-improvement (0), allow-without-logging
(1), and disable (2). Model execution and model-quality logging are distinct
service boundaries. The model execution manager is generic; its inspected
`ExecuteModel` path does not independently establish a Compose user gesture.

## Ranked alternatives

1. **Investigate a small compile-out graph repair first.** Preserve the current
   false policy and existing C++ guards; condition only Compose-specific GN
   dependencies and corresponding tests. Retain all unrelated tests/features.
   This is not a supported clean configuration today, and no repair is
   authorized as completed or proven by this report. Validate both flag values,
   target sources/resources, affected compilation and tests before adopting it.
2. **Keep compiled, deny Compose functionality through upstream controls.**
   Desktop default plus a durably enforced Compose-specific disable policy is
   a plausible lower-maintenance product boundary. Prove hints, sessions and
   logging cannot evade it before removing the build requirement. Preserve
   shared Optimization Guide and Autofill functionality.
3. **Small downstream service hook if upstream controls are insufficient.**
   Separate `kCompose` execution permission, Compose hint registration and
   Compose quality-log upload. Deny before context reaches a network sink and
   require operation-scoped authorization if remote generation is later
   approved. Do not disable all shared model execution or hints.
4. **Broad refactoring:** not justified by the evidence gathered.

Classifying **only explicit remote generation/rewrite** as
`USER_TRIGGERED_SERVICE` / `USER_INITIATED` could fit Securium's model after a
separate product decision about disclosed input/page context, OAuth and retained
functionality. It cannot cover automatic hints, proactive telemetry or quality
uploads. Those must remain denied/unapproved under existing policy, with any
future Compose records separating them from generation. No Lens decision is
inherited. The current exclusion does not authorize Compose generation yet.

## Diagnostic evidence and remaining gate

On dockerbox, in `D:\Sandbox\Codex\Securium\Chromium\src`, a separate
`out/ComposeBoundaryReview` copied attempt 004's arguments and removed only
`enable_compose=false`. No source was edited. `gn gen --fail-on-unused-args`
exited 0: **34,081 targets from 5,024 files in 11,061 ms**. `gn args` confirmed
the effective default `enable_compose=true` from `features.gni:7`; `gn refs`
produced the direct consumers above. The first inspection command lacked the
worker's local-toolchain environment and failed; rerunning with the same
environment as generation succeeded. This was an inspection setup error, not
a different build result.

Logs: worker `Artifacts/compose-boundary-review.log` and
`Artifacts/compose-direct-consumers.log`; copies retained in local `artifacts/`.
This is a diagnostic alternative, **not** canonical Foundation 1B success.
Canonical attempt 004 remains failed. No compile/test process was launched.
The unresolved choice is whether to repair the small compile-out boundary or
replace it with a proven durable runtime denial. Source evidence does not yet
justify changing the manifest merely because the alternative GN run succeeds.

Source references above are relative to the
[exact pinned Chromium tree](https://chromium.googlesource.com/chromium/src/+/a654841425914cbb703a2931e07b70a83aedbafd/).
