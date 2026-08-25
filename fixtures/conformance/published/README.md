# Retained materialized conformance publications

Each materialization is written below this directory at the immutable Git
revision that selected its source artifacts:

```text
fixtures/conformance/published/<git-sha>/
```

The materializer refuses to overwrite an existing publication directory. A
publication contains all seven claim layers, both Draft and Candidate CPF1
profiles, and paired Local/Air-Gapped manifests and signed CFB1 archives plus
`SHA256SUMS`. The hosted workflow uploads that exact retained path under the
matching `conformance-bundles-<git-sha>` artifact name.

Candidate authority records are bundled as typed immutable members. The
ADR-059 matrix is also present as a Draft execution inventory: its 192
descriptors remain unexecuted and have no expected-result digests until an
executor records them.
