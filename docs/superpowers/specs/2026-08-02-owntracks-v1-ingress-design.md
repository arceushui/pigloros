# OwnTracks V1 Gateway Ingress Design

## Scope

This design implements the route-specific V1 slice enabled by Accepted
ADR-056. It adds the loopback-only `POST /v1/bridges/owntracks` adapter for
the existing ADR-026 `geo.location` Event contract. It does not change the
Event payload, add `geo.cell`, migrate data, widen generic append, or activate
a non-loopback deployment.

## Architecture

The Gateway HTTP adapter remains a transport and minimization module. A new
private OwnTracks ingress capability is the single seam that authenticates an
active enrollment, obtains its current authorization state, applies the
per-binding rate policy, derives opaque dedup inputs, and invokes the existing
core geographic-admission transaction. The adapter never reads the verifier,
owner key, enrollment fence, Timeline, or EntityId.

```text
loopback HTTP request
  -> bounded body collection
  -> zero-byte compatibility no-op OR strict V1 parse/minimize
  -> private ingress capability
       -> constant-time verifier check
       -> ephemeral opaque binding rate state
       -> current enrollment fence + opaque dedup inputs
       -> existing atomic geo.location admission
  -> 200 [] only after accepted/duplicate
  -> Gateway next-tick notice only after accepted commit
```

The capability has one request interface: bounded Basic handle/secret plus the
already-minimized existing V1 `geo.location` canonical bytes. Its result is a
bounded outcome classification; it never returns the verifier, binding key,
fence, owner key, raw credentials, Timeline, EntityId, Event ID, or sequence.

## Request processing

1. The loopback router alone registers `POST /v1/bridges/owntracks`; the
   spectator/non-loopback router never registers it.
2. The handler reads the request with `axum::body::to_bytes(body, 65_536)`.
   A body that exceeds 65,536 bytes, including chunked input, returns `413`;
   no complete raw body is retained after any success or error path.
3. A zero-byte body returns `200 []` without requiring `Content-Type` or
   Basic credentials and never calls the limiter or store. This is the only
   unauthenticated compatibility no-op.
4. Every nonempty body requires `Content-Type: application/json` and HTTP
   Basic credentials. The parser accepts only one JSON object with
   `_type: "location"`, finite WGS84 latitude/longitude, and integer `tst`.
   It extracts only those allow-listed fields and discards all extra telemetry
   before the minimized value is constructed; an unsupported `_type` or an
   invalid required field is rejected.
5. The adapter creates only the existing canonical V1 `geo.location` payload:
   0.1-degree cells, 15-minute source-time bucket, schema/policy V1, and
   bounded flags. Exact coordinates, source timestamps, raw JSON, headers,
   topics, and device labels do not cross the capability seam.
6. The private capability constant-time verifies the stored keyed verifier,
   derives an owner-keyed opaque binding key, applies the fixed one request per
   second with burst five limit using bounded process-local state, resolves the
   current enrollment fence, and commits through the existing atomic admission
   transaction. The opaque limiter key and rate state are neither returned,
   persisted, logged, nor exposed to the HTTP adapter.

## HTTP outcomes

| Condition | Status | Response |
| --- | --- | --- |
| zero-byte no-op, durable accepted, or durable duplicate | `200` | `[]` |
| malformed JSON or invalid Basic syntax | `400` or `401` respectively | stable bounded error code |
| missing/invalid credential | `401` | stable bounded error code |
| inactive, revoked, withdrawn, mismatched enrollment, or durable conflict | `403` | stable bounded error code |
| body over 65,536 bytes | `413` | stable bounded error code |
| non-JSON media type | `415` | stable bounded error code |
| unsupported OwnTracks message or invalid location semantics | `422` | stable bounded error code |
| authenticated binding over rate allowance | `429` | bounded error code and `Retry-After` |
| store saturation, unavailable admission, or unknown durable outcome | `503` | stable bounded error code |

The external response never reveals whether a binding exists beyond the
accepted Basic taxonomy, and never contains a credential, verifier, owner key,
raw body, location, cell, source time, Timeline, EntityId, Event ID, sequence,
or snapshot identity. No request logging, tracing, metrics, or journal entry
may include those values.

## Authority and concurrency

The private ingress capability and the existing geographic admission run on
the Gateway's dedicated store executor. Authentication, rate decision, current
enrollment resolution, and the admission commit are serialized by that owner;
the existing SQLite transaction revalidates the current fence inside the
commit. Revocation wins over every later request. Only a definite accepted
outcome publishes the Gateway event notice, so projections observe it on the
next scheduler tick; duplicates publish no notice.

## Tests and acceptance

Tests cover loopback-only registration; exact 64 KiB body enforcement including
chunked input; zero-byte no-op; content type; Basic syntax and invalid
credentials; valid location minimization; malformed/unsupported/semantic
failures; accepted/duplicate/conflict/denied/unavailable/unknown mapping;
rate burst and recovery; revocation; next-tick notice; source-level proof that
no generic append, `geo.cell`, public route, raw-body persistence, or secret
logging path exists. The actual changed path must achieve exact 100% line and
region coverage under the repository's non-privileged quality run, followed by
independent review and a fresh activation approval.

## Non-goals

- Same-LAN/public activation, TLS termination, or deployment configuration.
- MQTT, encrypted OwnTracks payloads, UI, remote pairing, export, or metrics
  backend.
- New Event schemas, H3, `geo.cell`, data migration, backfill, dual-write,
  upcasting, or historic conversion.
