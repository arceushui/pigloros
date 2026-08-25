# Public conformance fixture sources

These files are the public, deterministic inputs and expected-result records
for the seven CPF1 claim layers. Each directory under `profiles/` is a
separate public profile manifest and binds exactly one claim layer to its
input/expected-result pair. They contain no implementation-private state,
credentials, or signing material.

The immutable bundle boundary in `pos-conformance` accepts these bytes from a
caller, recomputes each BLAKE3 content address, binds the CPF1 profile digest,
and signs only the canonical manifest. Local and Air-Gapped manifests must be
materialized separately with the same expected-result records; the Air-Gapped
profile capability policy remains network-deny.

The scenario names intentionally cover positive, negative, malformed, resource
limit, deletion, downgrade, and independent-evaluation cases.

`SHA256SUMS` is the independent byte inventory for all seven profile manifests,
seven input records, seven expected-result records, the #172 authority fixture
and result bytes, the ADR-059 matrix, and seven required support artifacts.
The hosted verifier checks this inventory and independently recomputes every
authority BLAKE3-256 digest before bundle materialization.

The support directory contains the normative specification, schema, licence,
notice, SBOM, provenance, and limitations members that every immutable bundle
manifest must declare.

The Draft `matrix/adr-059-complete.json` records all twelve accepted
non-interference rows and their 192 required Local/Air-Gapped/Replay/Fork
variant cases. `expected-authority/inventory.json` records the eleven #172
handoff vectors with checked-in public fixture bytes and expected-result bytes;
each entry carries an independently recomputed BLAKE3-256 digest. The matrix
remains Draft because its 192 cases are an execution inventory owned by the
downstream authority/non-interference work, while the authority handoff slots
are complete enough for Candidate publication.

Every emitted Draft or Candidate Local/Air-Gapped bundle includes those raw
authority artifacts under their typed member roles. The profile-bound
provenance record fixes their paths and the authority inventory SHA-256, while
the signed member manifest fixes their BLAKE3 addresses. Materialized bytes are
retained below `published/<git-sha>/`; that directory is immutable per source
revision and includes its own `SHA256SUMS`.
