# Public conformance fixture sources

These files are the public, deterministic inputs and expected-result records
for the seven CPF1 claim layers. They contain no implementation-private state,
credentials, or signing material.

The immutable bundle boundary in `pos-conformance` accepts these bytes from a
caller, recomputes each BLAKE3 content address, binds the CPF1 profile digest,
and signs only the canonical manifest. Local and Air-Gapped manifests must be
materialized separately with the same expected-result records; the Air-Gapped
profile capability policy remains network-deny.

The scenario names intentionally cover positive, negative, malformed, resource
limit, deletion, downgrade, and independent-evaluation cases.

`SHA256SUMS` is the independent byte inventory for all seven input records,
seven expected-result records, and seven required support artifacts. The
verification script checks this inventory before bundle materialization.

The support directory contains the normative specification, schema, licence,
notice, SBOM, provenance, and limitations members that every immutable bundle
manifest must declare.
