# Retained materialized conformance publications

Each materialization is written below this directory at the SHA-256 address of
the checked-in `fixtures/conformance/SHA256SUMS` source inventory:

```text
fixtures/conformance/published/<source-inventory-sha256>/
```

The materializer refuses to overwrite an existing publication directory. A
publication contains all seven claim layers and the lifecycle permitted by
the checked-in authority inventory, with paired Local/Air-Gapped manifests
and signed CFB1 archives plus `SHA256SUMS`, the checked-in source inventory as
`SOURCE-SHA256SUMS`, and a `SOURCE-BINDING` record containing that source
address and revision. The materializer refuses to overwrite an existing
source-addressed publication.

Published archives are signed with `PIGLOROS_CONFORMANCE_SIGNING_KEY`, supplied
only by the materialization environment. The repository contains no publication
private key; the archive's public verification key and signature remain part of
the immutable CFB1 bytes.

GitHub Actions artifacts are a temporary transport copy and are not the
retention authority. A release or externally managed immutable object store
must retain every source-addressed publication for at least 24 months and the
latest two Stable major versions, whichever is longer. The source and output
SHA256SUMS files make that handoff verifiable.

The release owner must copy the complete source-addressed directory, verify
both SHA256SUMS inventories after transfer, and record the immutable object
store or release URL before treating publication as durable. GitHub Actions
retention alone is never sufficient: the seven-day pull-request artifact and
the ninety-day trusted artifact are recovery aids only. If no durable store
and retention record exists, the publication remains an internal Draft
artifact and must not be represented as Stable evidence.

The bundled SBOM is scoped to this data-only publication. It deliberately
does not claim to enumerate the CI runner, Rust workspace, or materializer
toolchain; those are checked independently by repository CI and are not
shipped inside the CFB1 archive.

Candidate authority records are bundled as typed immutable members only after
the inventory reaches Candidate with concrete bytes and digests. Until then,
the ADR-059 matrix and #172 inventory remain Draft; their unexecuted slots do
not count as conformance evidence.
