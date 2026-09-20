# Chromium Stable Candidate Detection

This component detects metadata only. It does not download Chromium, apply
patches, compile, test, qualify, sign, or release anything.

## Upstream contract

The live fetcher uses ChromiumDash's official public release endpoint:

```text
https://chromiumdash.appspot.com/fetch_releases
  ?channel=Stable
  &platform=Windows
  &num=1
  &offset=0
```

Chromium's own
[build recipe wrapper](https://chromium.googlesource.com/chromium/tools/build/+/HEAD/recipes/recipe_modules/chromiumdash/api.py)
exposes this endpoint for platform/channel release queries, and
[Chromium source tooling](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/tools/get_asan_chrome/get_asan_chrome.py)
uses it for channel metadata. The detector requires a JSON array containing
exactly one object with:

- `channel` equal to `Stable`;
- `platform` equal to `Windows`;
- `version` as a four-component Chrome release version; and
- `hashes.chromium` as a lowercase 40-character Chromium Git SHA.

Other ChromiumDash fields are tolerated but do not define candidate identity.
The API's Chrome release `version` is stored as `chrome_version`; it is not
renamed to a Chromium SHA or treated as source identity. `hashes.chromium` is
stored separately as `chromium_sha` and is the primary revision identity.

The query deliberately asks the service for one current record. Historical
responses can contain overlapping Stable milestones, and Securium does not
invent a highest-version selection rule. Zero records, multiple records,
unexpected envelopes, wrong platform/channel values, malformed versions, and
invalid SHAs are `INVALID_UPSTREAM`.

## Processing boundary

```text
live fetch or offline fixture
            |
            v
      parse + validate
            |
            v
 unqualified candidate
            |
            v
 compare with local state
            |
            +--> read-only report (default)
            |
            +--> atomic candidate-only write (--write-candidate)
```

All parsing, comparison, state, and CLI tests use committed fixtures and require
no network. Required GitHub pull-request validation never calls ChromiumDash.

## Decisions

| Decision | Meaning | Qualification required | Dispatch a new job |
| --- | --- | --- | --- |
| `NEW_CANDIDATE` | Version/SHA is new and non-regressive | Yes | Yes |
| `NO_CHANGE` | Same unqualified candidate is already recorded | Yes | No |
| `CANDIDATE_ALREADY_QUALIFIED` | Exact version/SHA is qualified | No | No |
| `CANDIDATE_ALREADY_RELEASED` | Exact version/SHA is released | No | No |
| `UPSTREAM_REGRESSION` | Detected version is older than local state | Undetermined; stop | No |
| `UPSTREAM_CONFLICT` | A known SHA maps to a different version | Undetermined; stop | No |
| `INVALID_UPSTREAM` | Response cannot be understood safely | Undetermined; stop | No |
| `FETCH_FAILED` | Network or HTTP retrieval failed | Undetermined; stop | No |
| `INVALID_STATE` | Local state is malformed or unsupported | Undetermined; stop | No |
| `STATE_WRITE_FAILED` | Atomic candidate update did not complete | Undetermined; stop | No |

A same-version/different-SHA response is `NEW_CANDIDATE`; a new SHA always
requires qualification. `NO_CHANGE` means no duplicate dispatch and no state
mutation, not that an unqualified revision became qualified.

## CLI and exit codes

```text
python scripts/chromium_update.py check [--json]
    [--offline-fixture PATH] [--state PATH] [--write-candidate]
```

- Exit `0`: a valid normal decision, including `NEW_CANDIDATE`.
- Exit `2`: fetch, input, state, write, regression, or conflict failure.

Human output labels the qualified revision, detected candidate, decision, and
qualification requirement. JSON output is sorted and versioned. Candidate
reports omit wall-clock detection time so an identical response and state have
stable semantic output. `detected_at` is written only on an actual candidate
change and never refreshed by an unchanged poll.

For `NEW_CANDIDATE`, JSON output includes a `qualification_request` conforming
to `state/qualification-request.schema.json`. It is a request for future work,
not qualification evidence.

The synthetic patch engine consumes this exact contract and rejects unsupported
versions, unknown fields, malformed versions, and invalid SHAs. Consumption of
the request authorizes only a disposable synthetic run; it does not authorize a
write to candidate, qualified, or released state.

## Atomicity and authority

Before a write, the detector re-reads state to detect concurrent changes,
copies the complete document, changes only `candidate`, validates the proposal,
and verifies `qualified` and `released` are unchanged. It writes and flushes a
same-directory temporary file before atomic replacement. Any earlier failure
performs no write; replacement failure preserves the previous target.

The detector has no operation that promotes `qualified` or `released`. Those
records belong to future qualification and release authorities respectively.
Metadata detection may never advance security qualification.
