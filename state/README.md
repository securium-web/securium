# Upstream State

`upstream.json` is the canonical project state. Its schema version 1 has three
independent nullable records:

```json
{
  "schema_version": 1,
  "candidate": null,
  "qualified": null,
  "released": null
}
```

`upstream.example.json` shows populated illustrative records. Its values are
synthetic and make no qualification claim.

## Records and authority

- `candidate` identifies detected Windows Stable metadata with
  `chrome_version`, exact `chromium_sha`, `detected_at`, and the fixed marker
  `qualification: UNQUALIFIED`. Only the detector may update it.
- `qualified` identifies the exact revision and evidence level accepted by a
  future qualification pipeline. The detector cannot update it.
- `released` identifies the exact qualified revision promoted by a future
  release pipeline and its downstream release version. Neither detection nor
  qualification may update it.

Therefore `DETECTED != QUALIFIED` and `QUALIFIED != RELEASED`. The current
canonical file contains no candidate, qualified revision, or release.

Candidate identity is based on the exact Chromium SHA together with its Chrome
version mapping, not `detected_at`. A repeated identical detection performs no
write and retains the original timestamp. A same-version/different-SHA response
is a new candidate requiring qualification. An older-than-local response or a
SHA associated with a different version is reported and not written.

## Failure semantics

Candidate writes validate the upstream response and complete local state first,
write a temporary file in this directory, flush it, and atomically replace
`upstream.json`. A concurrent state change, malformed input, unsupported schema,
validation failure, network failure, or replacement failure leaves the prior
state in place. Candidate replacement copies and verifies `qualified` and
`released` unchanged.

`qualification-request.schema.json` defines the minimal handoff contract for a
future builder: schema version, previous qualified version/SHA or null, and the
new candidate version/SHA. It intentionally contains no build or security
evidence. See `docs/CANDIDATE_DETECTION.md` for CLI and decision semantics.
