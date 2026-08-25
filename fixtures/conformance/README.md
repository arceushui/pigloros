# Public conformance fixture sources

These files are the public, deterministic inputs and expected-result records
for the seven CPF1 claim layers. Each directory under `profiles/` is a
separate public profile manifest and binds exactly one claim layer to all seven
required fixture families: positive, negative, malformed, resource, deletion,
downgrade, and independent evaluation. They contain no implementation-private
state, credentials, or signing material.

The immutable bundle boundary in `pos-conformance` accepts these bytes from a
caller, recomputes each BLAKE3 content address, binds the CPF1 profile digest,
and signs only the canonical manifest. Local and Air-Gapped manifests must be
materialized separately with the same expected-result records; the Air-Gapped
profile capability policy remains network-deny.

The scenario names intentionally cover positive, negative, malformed, resource
limit, deletion, downgrade, and independent-evaluation cases. A profile
manifest lists every family explicitly; no profile is represented by a single
input/result pair.

`SHA256SUMS` is the independent byte inventory for all seven profile manifests,
seven input records, seven expected-result records, the ADR-059 matrix, and
seven required support artifacts. The #172 authority inventory is retained as
a Draft handoff with pending slots; no authority bytes are checked in or
bundled until the concrete handoff arrives.
The hosted verifier independently checks every available public digest before
bundle materialization.

The support directory contains the normative specification, schema, licence,
notice, SBOM, provenance, and limitations members that every immutable bundle
manifest must declare.

The Draft `matrix/adr-059-complete.json` records all twelve accepted
non-interference rows and their 192 required Local/Air-Gapped/Replay/Fork
variant cases. `expected-authority/inventory.json` records the eleven #172
handoff vectors as pending Draft slots with no asserted fixture or
expected-result digest. The matrix and authority inventory remain Draft until
the downstream authority/non-interference work supplies concrete bytes,
expected results, and independent review.

Every emitted Draft Local/Air-Gapped bundle includes the pending authority
inventory and the Draft execution matrix, but not nonexistent authority
fixture/result members. Candidate bundles are enabled only after the inventory
becomes Candidate and all concrete authority members are independently
verified. Materialized bytes are retained below `published/<git-sha>/`; that
directory is immutable per source revision and includes its own `SHA256SUMS`.
