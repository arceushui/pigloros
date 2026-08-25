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

Candidate authority records are bundled as typed immutable members only after
the inventory reaches Candidate with concrete bytes and digests. Until then,
the ADR-059 matrix and #172 inventory remain Draft; their unexecuted slots do
not count as conformance evidence.
