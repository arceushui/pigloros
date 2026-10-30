# Replay profile requirements

The evaluator must replay the public Event sequence under the selected
ExecutionProfile and reproduce the exact ordered output, state transition,
failure coordinate, and deterministic-budget outcome. Replay must not consult
wall-clock time, undeclared network input, hidden state, or implementation-
private helpers.

## Provider contract 2.0.0 (ADR-062 Revision 8 slice R4)

Provider `pigloros.fixture.replay-conformance@2.0.0` has no reader or alias for
1.0.0. A subject adapter executes an attempt only when the BLAKE3 of its schema
member is the digest pinned for its family and one auxiliary member is the
family's `RCS1` composite: `["RCS1", 1, [[digest32, bytes], ...]]`, each entry
addressed by the BLAKE3 of its bytes.

The payload is RFC 8785 JSON with schema `pigloros.replay-conformance.case.v2`:
`{"schema", "family", "subcases"}`, one to sixteen sub-cases. A sub-case holds:

- `id`, `fixture_id` (the W8H1 entry it carries, or null) and `title`;
- `class`: `RecordedReplay`, `ProfileRecomputation`, `CrossProfileConformance`
  or `LiveUnverified`;
- `profiles`: one EPF1 id, or two (Local, then Air-Gapped) for
  `CrossProfileConformance`; the adapter's host installs
  `deterministic-local-v1`, `deterministic-air-gapped-v1`, `replay-v1`
  (`RecordedReplay` only) and `live-local-v1` (`LiveUnverified` only);
- `manifest`: the manifest fields the fixture owns (format version, seed,
  `resource_limit` in Events, network flag, declared ReplayClaim, the input,
  closure, evaluator, room, scheduler and budget digests, the request digest and
  the report limit); the host binds the EPF1 and TPS1 digests, the class and the
  execution mode;
- `closure`: the BLAKE3 of the primary member (the exported Timeline of a
  `RecordedReplay`, the subject of a recomputation) and of the licence; null is
  a missing member;
- `export_evaluation` (`RecordedReplay` only): the ADR-060 transition rule and
  state of the export;
- `ticks` (recomputation only): the frozen number of Ticks;
- `expected_stream`: the expected authoritative stream (Events, the one
  Projection checkpoint at tick 0 and the typed failure, if any);
- `expect`: the expected leg of each profile: outcome, ReplayClaim,
  authoritative result digest, first error code and coordinate, and first
  divergence.

An exported Timeline member is the serde CBOR form of `TimelineExport`. A
subject member is the JSON document `pigloros.replay-conformance.subject.v1`:
one entity, one Event type, the payloads its Driver emits at each Tick and an
optional typed failure at one Tick.

## Digests and closure binding

Every digest is the `PiglorOS.RecordedReplay*.v1` scheme of the ADR-062
Revision 8 note "Recorded Replay Digests". The closure members bind the
request's `artifact_closure_digest`: BLAKE3 over
`PiglorOS.RecordedReplayClosure.v1`, a zero byte, the member count (2, `u64`
big endian) and each member in role order as its one-byte role and its 32-byte
artifact digest. The roles are 1 (exported Timeline), 2 (recomputation subject)
and 3 (licence); the artifact digest is the BLAKE3 of the member bytes. A
complete member set whose composition is not the request's digest is refused at
`artifact_closure` with `DigestMismatch` (`InvalidManifest`), after any earlier
preflight coordinate.

## Results

A `canonical-output` family outputs its record of every sub-case and leg; a
`namespaced-failure` family returns its family failure when every leg is as
expected, and otherwise `subcase-mismatch`. A payload outside this grammar is
the failure `payload-invalid`.
