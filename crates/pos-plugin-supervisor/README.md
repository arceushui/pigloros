# pos-plugin-supervisor

The community Plugin worker supervisor and host-pass integration. It launches a fresh worker
subprocess for each Component invocation; the worker runs the Component in Wasmtime. This Local
relaxation does not compose the Sandbox Provider's admission, network isolation or kernel readback
boundary.

## Pass outcome records

`CommunityPluginSubjectOutcomeV1` records one Plugin's result in one host pass.
`CommunityPluginSubjectOutcomeV1::assemble(entry, tick, mode, receipt)` builds it from the entry's
`MemberPassV1` and, when the member's Driver launched, its invocation receipt. The caller finds
the receipt with `CommunityPluginHandleV1::receipt_for()` for the entry's `invocation_id`. It
passes no receipt when that ID is absent; `assemble` does not compare IDs.

The result vocabulary is closed: `Staged`, `Committed`, `Refused`, `Trapped`, `Failed`, `NotRun`
or `Discarded`. Refused and failed results include a closed error and class name; a refusal may
also include its trust or revocation basis. The record carries the content-validation result and
execution-profile digest. It makes no claim of signature validity: a release that fails the gate
is `Refused`, and nothing else in the record says it was verified.

The EAI1/EAO1 subject adapter is `apps/pos-plugin-conformance-adapter`.

Results are Local-relaxation engineering evidence, not hosted conformance.

The adapter reads one EAI1 attempt, runs the payload's sub-cases through this crate's supervisor
and the real `pos-plugin-worker`, and writes one EAO1 observation. Its README describes the wire
behavior. Profile acceptance tests are in
`apps/pos-plugin-worker/tests/conformance_adapter_public.rs`.

Build `pos-plugin-worker` into the adapter binary's directory so the adapter can resolve it next
to its executable.
