# Retained materialized conformance publications

Each materialization is written below this directory at the SHA-256 address of
the checked-in `fixtures/conformance/SHA256SUMS` source inventory:

```text
fixtures/conformance/published/<source-inventory-sha256>/
```

The materializer refuses to overwrite an existing publication directory. A
publication contains all seven claim layers, both Draft and Candidate CPF1
profiles, and paired Local/Air-Gapped manifests and signed CFB1 archives plus
`SHA256SUMS`, the checked-in source inventory as `SOURCE-SHA256SUMS`, and a
`SOURCE-BINDING` record containing that source address and revision. The
materializer refuses to overwrite an existing source-addressed publication.

Published archives are signed with `PIGLOROS_CONFORMANCE_SIGNING_KEY`, supplied
only by the materialization environment. The repository contains no publication
private key; the archive's public verification key and signature remain part of
the immutable CFB1 bytes.

Candidate authority records are bundled as typed immutable members. The
ADR-059 matrix is also present as a Draft execution inventory: its 192
descriptors remain unexecuted and have no expected-result digests until an
executor records them.
