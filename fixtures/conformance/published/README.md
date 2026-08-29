# Draft materialized conformance bundles

Each materialization is written below this directory at the SHA-256 address of
the checked-in `fixtures/conformance/SHA256SUMS` source inventory:

```text
fixtures/conformance/published/<source-inventory-sha256>/
```

The Draft materializer emits all seven claim layers with paired
Local/Air-Gapped manifests and signed CFB1 archives. These are CI transport
artifacts only; the materializer refuses to overwrite an existing output
directory but does not claim that the output is a retained Candidate
publication. Candidate publication is a later #198 governance operation.

Published archives are signed with `PIGLOROS_CONFORMANCE_SIGNING_KEY`, supplied
only by the materialization environment. The repository contains no publication
private key; the archive's public verification key and signature remain part of
the immutable CFB1 bytes.

GitHub Actions artifacts are a temporary transport copy and are not the
retention authority. Candidate publication and any release-retention policy
are owned by the #198 governance workflow. The source inventory and each
materialized tree's output `SHA256SUMS` make the Draft handoff verifiable
without turning it into a release. The output inventory covers every other
file in the materialized tree and therefore does not recursively list itself.

The bundled SBOM is scoped to this data-only publication. It deliberately
does not claim to enumerate the CI runner, Rust workspace, or materializer
toolchain; those are checked independently by repository CI and are not
shipped inside the CFB1 archive.

No authority fixture/result records are bundled while the inventory is Draft.
The 192-coordinate execution records and Candidate governance artifacts must
come from their owning workflows (#193 and #198), not from this Draft
packaging job.
