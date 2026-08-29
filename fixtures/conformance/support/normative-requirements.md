# CPF1 public conformance requirements

## Authority and lifecycle

CPF1 is the immutable, content-addressed oracle contract for one claim layer.
It contains no aggregate certification flag and no implementation-private
state. `Draft` records may contain open authority handoff slots; `Candidate`
records must contain a non-empty expected result for every mandatory fixture.
Only the closed lifecycle transitions Draft → Candidate → Stable → Retired
are permitted. A Stable record additionally requires two independently
developed implementation reports and an external trusted-root policy.

Every CPF1 record carries a nonzero BLAKE3 digest of the exact canonical
`authority/execution-matrix.json` member. The digest binds the matrix into
every claim-layer profile without claiming that any matrix case executed.

## Required profile inventory

Each of the seven public profiles declares all seven fixture families:

1. positive canonical output;
2. denied behavior with no state change;
3. malformed encoding or schema;
4. deterministic resource exhaustion;
5. deletion/redaction with a weakened ReplayClaim;
6. downgrade authorization without fallback; and
7. independent-evaluation evidence.

Every fixture binds an exact provider key, fixture-family schema and payload
descriptor, ExecutionProfile digest, strict output/failure/divergence oracle,
VerificationOutcome, ReplayClaim, redaction state, deterministic memory/CPU/
host-call/event/output/storage/step/time budget, separate operational watchdog,
default-deny capability policy, licence, notices, SBOM, source/build/publication
provenance, and limitations. Missing bounds or provenance are invalid, not
unlimited. Only downgrade fixtures carry trust-policy, release-admission, and
provider-transition bindings; no implementation digest authorizes a downgrade.
Each profile binds the full FPR1 provider-registry artifact and the exact
provider key required by its claim layer. Every FPP1 provider package is data
only and supplies exactly one schema for each of the seven families. Each
profile materializes one descriptor per supported deterministic
ExecutionProfile so Local and Air-Gapped bundles do not reuse the wrong profile
identity.

## Bundle parity and authority

Local and Air-Gapped bundles contain byte-identical authoritative expected
results. Air-Gapped capability policy must deny network access. Member paths,
sizes, BLAKE3 digests, canonical ordering, archive nesting, expansion, and
total-resource limits are checked before a member is loaded.

The #172 inventory is a separate authority handoff. Its declared SHA-256
inventory digest is checked against the actual inventory bytes; concrete
fixture and expected-result bytes are supplied by the owning evidence workflow
before Candidate.
The ADR-059 matrix must contain the canonical 12 row IDs, four variants, four
modes, 192 ordered case identities, and explicit equality declarations. Every
Candidate coordinate carries an exact JSON expected-result record and its own
BLAKE3 digest; a separate authority-result digest must match the inventory
entry named by that coordinate. Open matrix or authority slots never count as
a passing result.

## Public evaluation boundary

Materialization and verification consume public fixture bytes only. They must
not call the implementation under test, private Rust modules, a live service,
or hidden expected output as an oracle. Draft packaging is immutable per output
directory and addressed by its source inventory digest. Candidate publication,
correction, and retention records are supplied by the #198 governance
workflow.
