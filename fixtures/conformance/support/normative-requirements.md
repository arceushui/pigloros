# CPF1 public conformance requirements

## Authority and lifecycle

CPF1 is the immutable, content-addressed oracle contract for one claim layer.
It contains no aggregate certification flag and no implementation-private
state. `Draft` records may contain open authority handoff slots; `Candidate`
records must contain a non-empty expected result for every mandatory fixture.
Only the closed lifecycle transitions Draft → Candidate → Stable → Retired
are permitted. A Stable record additionally requires two independently
developed implementation reports and an external trusted-root policy.

## Required profile inventory

Each of the seven public profiles declares all seven fixture families:

1. positive canonical output;
2. negative/denied behavior;
3. malformed encoding or schema;
4. deterministic resource exhaustion;
5. deletion or redaction with a weakened ReplayClaim;
6. downgrade/compatibility behavior; and
7. independent-evaluation evidence.

Every fixture binds an exact ExecutionProfile digest, public schema digest,
ordered input members, expected canonical bytes/digest or typed failure,
VerificationOutcome, ReplayClaim, redaction state, deterministic CPU/memory/
event/output/storage/step/time/watchdog bounds, default-deny capability policy,
licence, notices, SBOM, source/build/publication provenance, limitations, and
compatibility digest. Missing bounds or provenance are invalid, not unlimited.
The family source records are layer-neutral; each profile materializes one
descriptor per supported deterministic ExecutionProfile so Local and
Air-Gapped bundles do not reuse the wrong profile identity.

## Bundle parity and authority

Local and Air-Gapped bundles contain byte-identical authoritative expected
results. Air-Gapped capability policy must deny network access. Member paths,
sizes, BLAKE3 digests, canonical ordering, archive nesting, expansion, and
total-resource limits are checked before a member is loaded.

The #172 inventory is a separate authority handoff. Its declared SHA-256
inventory digest is checked against the actual inventory bytes; each concrete
fixture and expected-result digest is checked with BLAKE3 before Candidate.
The ADR-059 matrix must contain the canonical 12 row IDs, four variants, four
modes, 192 ordered case identities, and explicit equality declarations. Every
Candidate coordinate carries an exact JSON expected-result record and its own
BLAKE3 digest; a separate authority-result digest must match the inventory
entry named by that coordinate. Open matrix or authority slots never count as
a passing result.

## Public evaluation boundary

Materialization and verification consume public fixture bytes only. They must
not call the implementation under test, private Rust modules, a live service,
or hidden expected output as an oracle. Publication is immutable and addressed
by its source inventory digest; corrections publish a replacement digest and
retain the old record and impact information.
