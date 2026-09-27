# ADR-425 draft — local OCI ReleaseSource and crash-safe publication

**Status:** Draft for independent review; separate acceptance required | **Wave:** 8 | **Deciders:** core team | **Date:** 2026-09-27

Related: #425 · #401 · [[ADR-061_Sandboxed_Community_Plugin_Runtime_and_Decentralized_Artifact_Trust]] · [[ADR-065_KeyRegistry_Authorized_Signing_After_Destruction]]

---

## Status and decision boundary

ADR-061 revision 10 is **Accepted**, including its complete `PluginReleaseSigning` amendment. It selects OCI packaging and makes #425 an independently accepted prerequisite: the #425 contract must name the source-neutral boundary, final identity, collision rule, durable publication ordering, recovery, and cleanup. This local review draft supplies that missing decision for independent review. It does not amend ADR-061, and production code remains unauthorized until this exact publication contract is accepted.

The decision covers obtaining and publishing an immutable, unadmitted Plugin release bundle. It excludes PMF1 semantics, release signing, KeyRegistry operations, trust admission, activation, HTTPS discovery, and remote OCI discovery. #401 maps the verified bundle to its separate BLAKE3 `release_digest`; #423 and #424 own trust and admission.

## Evidence and alternatives

| Option | Fit | Rejection or trade-off |
|---|---|---|
| **A. OCI artifact manifest, per-release immutable layout, one durable root index (selected)** | OCI descriptors bind media type, size, and content digest; the OCI layout supplies `oci-layout` and `index.json`. [S1][S2][S3] | A small PiglorOS root index is required because OCI does not define a crash-safe publish transaction. |
| B. One shared OCI layout that copies blobs then mutates its index | Deduplicates blobs. | A crash can leave shared blobs without a durable owner; garbage collection and collision rules would be a separate first-release decision. |
| C. Tar archive plus sidecar checksum | One file is simple to transfer. | It creates a second source format and loses the OCI descriptor graph selected by ADR-061. |

OCI requires `oci-layout` and `index.json`; descriptors carry required media type, byte count, and digest, and a byte-count mismatch is untrusted. [S1][S2] OCI artifact guidance permits a non-runnable artifact manifest with an empty config and artifact-specific type. [S3] JCS gives JSON an invariant UTF-8 representation with deterministic property sorting. [S4] `fsync` persists file data and metadata, while directory entries require a directory sync. [S5] `renameat2(RENAME_NOREPLACE)` provides an exclusive no-replace final-name transition on supported local filesystems. [S6]

## Proposed decision

### Transport identity and bounded port

The transport identity is the exact OCI manifest descriptor:

```text
BundleAddressV1 {
  media_type = "application/vnd.oci.image.manifest.v1+json"
  digest = "sha256:<64 lowercase hex>"
  size = u64
}
```

It is immutable transport identity, not PMF1's BLAKE3 `release_digest`; it contains no tag, URL, or local path. Root-manifest bytes are limited to 64 KiB. A closure contains at most 359 stored blobs, counting the root manifest, the empty config, and every layer. Each blob is at most 32 MiB and the sum of all 359 stored blobs is at most 64 MiB. The inherited PMF1 and WIT limits remain 1 MiB and 4 MiB.

```text
ReleaseSourceV1::read_verified(BundleAddressV1)
  -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1>
```

`VerifiedReleaseBundleV1` contains the root-manifest blob and an immutable digest-ordered collection of the empty config and every layer blob. Its constructor is private to the verifier. The port verifies the root descriptor, parses only bounded OCI JSON, then verifies the byte count and SHA-256 of the root blob, config blob, and every layer blob before returning. It rejects non-JCS bytes, duplicate JSON object members, unknown object keys, duplicate descriptors, non-SHA-256 descriptors, URLs, embedded data, a subject, malformed JSON, descriptor/media-type mismatch, absent blob, excess bounds, symlinks, and unreferenced local-adapter blobs.

Closed errors are `InvalidAddress`, `NotFound`, `BoundsExceeded`, `InvalidLayout`, `InvalidDescriptor`, `DigestMismatch`, `SizeMismatch`, `DuplicateMember`, `UnsupportedMediaType`, `Uncommitted`, `Collision`, `Io`, `Sync`, `LockUnavailable`, and `RecoveryRequired`. They disclose no filesystem paths. A failure yields no partial bundle. The port never parses PMF1 or decides signing, trust, admission, or activation.

### Exact OCI artifact closure

The root manifest and `index.json` use RFC 8785 JCS UTF-8 bytes with no trailing newline. Parsing first rejects duplicate object members, then re-canonicalizes and requires a byte-for-byte match. The root object has exactly `artifactType`, `config`, `layers`, `mediaType`, and `schemaVersion`; values are respectively `application/vnd.pigloros.plugin.release.v1`, the exact config descriptor below, the ordered layer array, `application/vnd.oci.image.manifest.v1+json`, and integer `2`. No other root key is accepted.

The config descriptor object has exactly `digest`, `mediaType`, and `size`, and is OCI's exact empty JSON descriptor: media type `application/vnd.oci.empty.v1+json`, bytes `{}`, size 2, SHA-256 `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`. Every layer descriptor has exactly `annotations`, `digest`, `mediaType`, and `size`; `annotations` has exactly one key, `org.pigloros.plugin.member`; digest is lower-case `sha256:<64 hex>`; and size is a positive integer. Neither descriptor may carry `data`, `urls`, `artifactType`, `platform`, or an unknown key.

The annotation value is one of `pmf1`, `component`, `wit`, `provenance`, `sbom`, `schema/<64 lower-case hex>`, `licence/<64 lower-case hex>`, or `migration-fixture/<64 lower-case hex>`. For every repeated role, its suffix must exactly equal the descriptor digest's hex portion. Layer order is one `pmf1`, one `component`, one `wit`, zero or more `schema`, one `provenance`, one `sbom`, one or more `licence`, then zero or more `migration-fixture`; repeated roles sort by their raw SHA-256 digest. Two layer descriptors may not share a digest, even if their role differs.

| Role | Media type | Cardinality |
|---|---|---:|
| `pmf1` | `application/vnd.pigloros.plugin.manifest.v1+cbor` | 1 |
| `component` | `application/vnd.pigloros.plugin.component.v1+wasm` | 1 |
| `wit` | `application/vnd.pigloros.plugin.wit.v1+tar` | 1 |
| `schema` | `application/vnd.pigloros.plugin.schema.v1+json` | 0–256 |
| `provenance` | `application/vnd.in-toto+json` | 1 |
| `sbom` | `application/spdx+json` | 1 |
| `licence` | `text/plain; charset=utf-8` | 1–32 |
| `migration-fixture` | `application/vnd.pigloros.plugin.migration-fixture.v1+cbor` | 0–64 |

The source validates this closure mechanically. #401's PMF1 codec must contain an ordered descriptor tuple `(member, media_type, size, sha256_digest)` for every layer and reject any tuple set that does not exactly equal this ordered OCI layer list; PMF1's inner BLAKE3 values then bind the named bytes. Thus local, HTTPS, and registry adapters can return the same transport closure while PMF1 retains its semantic identity. Full-capacity vectors contain 359 stored blobs: one root, one config, and 357 layers (`1 + 1 + 1 + 256 + 1 + 1 + 32 + 64`). Tests reject 360 blobs, 65 MiB total, and every role maximum plus one.

### Local layout and commit ordering

```text
<root>/
  published.json                 # sole durable discovery/commit index
  .publisher.lock                # root-owned advisory lock file
  .published.<32-hex>.next       # owned private next-index file
  releases/<sha256-hex>/
    READY                         # recovery evidence, never a discovery entry
    oci-layout
    index.json
    blobs/sha256/<digest-hex>
  releases/.<sha256-hex>.staging.<nonce>/
```

`oci-layout` is exactly `{"imageLayoutVersion":"1.0.0"}\n`. `index.json` is RFC 8785 JCS JSON with exactly one manifest descriptor:

```json
{"manifests":[{"digest":"sha256:<64 lowercase hex>","mediaType":"application/vnd.oci.image.manifest.v1+json","size":<u64>}],"schemaVersion":2}
```

`READY` consists of these ASCII bytes and one final LF:

```text
pigloros-local-oci-ready-v1
sha256:<64 lowercase hex>
<decimal manifest size>
```

`published.json` is at most 64 KiB and RFC 8785 JCS JSON in this exact shape, with at most 256 digest-lexicographically sorted unique addresses. Its root has exactly `addresses` and `version`; each address has exactly `digest`, `mediaType`, and `size`; duplicate JSON keys, unknown keys, duplicate addresses, non-JCS bytes, and an address that is not a `BundleAddressV1` are rejected:

```json
{"addresses":[{"digest":"sha256:<64 lowercase hex>","mediaType":"application/vnd.oci.image.manifest.v1+json","size":<u64>}],"version":1}
```

The initialized store creates and syncs the empty index `{"addresses":[],"version":1}` before it accepts reads or writes. It is the sole durable discovery index. A reader accepts a release only when the index entry, final directory, `READY`, and entire revalidated closure agree. `READY` is recovery evidence only. Publishing a 257th address returns `BoundsExceeded`; V1 has no implicit retention or deletion. Reads inspect one requested indexed address, while recovery scans at most 256 index addresses and at most 258 `releases/` entries (256 final directories, one staging directory, and one quarantine directory). Any larger directory set fails closed as `BoundsExceeded`.

The store root is selected by a trusted local operator and must already exist as a directory owned by the effective UID with mode exactly `0700`, on a local filesystem that supports the required calls. Initialization uses the root directory file descriptor, creates `releases/` with mode `0700`, creates `.publisher.lock` as a root-owned regular `0600` file, and creates the empty index as a root-owned regular `0600` file; it fsyncs each file then the affected directory. All later traversal is relative to retained directory file descriptors through `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, uses `O_NOFOLLOW`, and verifies regular-file/directory type, effective-UID ownership, and mode before use. [S7] An unavailable syscall, unsafe root, changed owner/mode, symlink, mount crossing, or non-local filesystem is `InvalidLayout`.

Readers hold `flock(LOCK_SH)` on `.publisher.lock` for the complete index-to-closure verification. Publishers and recovery hold `flock(LOCK_EX)` for their complete operation. [S8] The lock is an ordering device only; root privacy and descriptor-relative no-follow traversal are the security boundary. `flock` errors or a non-private root are `LockUnavailable` or `InvalidLayout` rather than a fallback.

Under one exclusive store-root writer lock, the publisher accepts and revalidates only `VerifiedReleaseBundleV1`, then performs this sequence on one local filesystem:

```text
validate closure
  -> private staging under releases/
  -> write and fsync the matching private OWNER marker
  -> write the root manifest blob, empty config blob, every layer blob, oci-layout, index.json; fsync every file
  -> fsync directories from blobs/ through staging root
  -> write and fsync READY; fsync staging root
  -> renameat2(NOREPLACE) staging -> releases/<manifest-sha256>
  -> fsync releases/
  -> create .published.<32-hex>.next with O_CREAT|O_EXCL|O_NOFOLLOW and mode 0600
  -> write and fsync the bounded next published.json
  -> atomically rename next index -> published.json
  -> fsync <root>/
```

The adapter refuses a target lacking same-filesystem staging, an exclusive writer lock, directory synchronization, `openat2` resolution controls, or `RENAME_NOREPLACE`. It never falls back to copy-and-delete, overwrite rename, or an unsynchronized success. The private next-index name is retained in process memory and is owned only when it matches `.published.<32 lower-case hex>.next`, is a regular `0600` file owned by the effective UID, and is reached through the retained root directory FD. Recovery removes only an owned next-index file after a root-directory fsync; any other matching artifact is quarantined and causes `RecoveryRequired`.

The index rename is the visibility linearization point. A pre-rename write/sync/rename error returns `Sync` and recovery either removes the owned next index or completes a validated final-but-unindexed release. An error from the root-directory fsync after index rename returns `OutcomeUnknown(address)`, never `Sync`: the address may already be visible after the writer releases its lock. The caller must invoke `recover(address)` before retrying. Recovery revalidates the final directory and index under the exclusive lock, fsyncs the root directory, and returns exactly `Committed(address)`, `Unpublished(address)`, or `RecoveryRequired`; retrying the same verified bundle after `Committed` is idempotent success, while `Unpublished` restarts publication. No reader can observe an intermediate index through this adapter because it holds the shared lock; a reader after an `OutcomeUnknown` accepts only the normal fully revalidated committed state.

### Collision, recovery, and fault injection

The final path is derived only from the lower-case root manifest SHA-256. A staging directory is named `.<sha256-hex>.staging.<32 lower-case hex>` and contains root-owned regular `0600` `OWNER` bytes `pigloros-local-oci-staging-v1\n<32 lower-case hex>\n`; the suffix and `OWNER` nonce must match. On an existing final path, the publisher revalidates it and reports idempotent success only when `READY`, `index.json`, root descriptor, and every closure byte match the requested verified bundle. Any mismatch, missing marker, malformed member, or index disagreement is `Collision` or `RecoveryRequired`; it is never overwritten.

Recovery holds the same lock before reads or writes:

1. Remove an owned staging directory only after descriptor-relative no-follow traversal confirms its name grammar, `OWNER` nonce match, effective-UID ownership, `0700` directory mode, regular `0600` owner marker, and absence from `published.json`; fsync `releases/` after removal. A name-shaped directory lacking this proof is quarantined and returns `RecoveryRequired`.
2. Revalidate each final `READY` directory absent from the root index. Add a complete one through the durable index protocol; quarantine an incomplete one and return `RecoveryRequired`.
3. Revalidate every indexed final directory. A missing, changed, malformed, or unready release fails the entire source closed as `RecoveryRequired`.
4. Remove an owned next-index file as defined above and fsync the root; a malformed or unowned next-index file is quarantined and returns `RecoveryRequired`.

No automatic deletion occurs for a once-ready final directory that no longer validates. V1 has no garbage collection or shared-blob deduplication.

Production exposes only `ReleaseSourceV1`, `LocalOciPublisherV1::publish`, and `recover`. Tests may use private `PublicationFaultPointV1` to fail initialization file/directory creation or sync, blob write, blob sync, directory sync, `OWNER` write/sync, `READY` write/sync, final rename, `releases/` sync, next-index create/write/sync, index rename, root sync, or recovery cleanup sync. It cannot alter production inputs or be externally enabled.

Public-seam evidence must prove: initialized empty-index read; roundtrip; missing/mutated member rejection; JCS re-canonicalization, duplicate JSON key, unknown key, annotation grammar, PMF1 tuple, and role/cardinality rejection; all full-capacity boundaries; index byte/address/recovery-scan limits; equivalent collision idempotency; non-equivalent collision refusal; staging and next-index invisibility; final-ready-but-unindexed recovery; indexed missing/mutated release fail-closed; `OutcomeUnknown` recovery to committed or unpublished; unsafe root, lock, symlink, mount, owner, and mode rejection; and each injected failure leaves no discoverable partial release.

## Consequences and non-goals

The local adapter is Linux-local and requires Linux 5.6+ `openat2` resolution controls. Network filesystems, Windows, registry durability, tags, mutable aliases, shared blob storage, garbage collection, rollback, PMF1 codec/signature, KeyRegistry, trust admission, installer, and activation require separate accepted work. A verified OCI closure is inspectable only; it never admits, activates, or executes a Plugin.

## Sources

- **[S1] OCI Image Layout Specification, image-spec v1.1.1.** Open Containers Initiative, 2025-03-03, accessed 2026-09-27. https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md — required layout files and content-addressed blobs.
- **[S2] OCI Content Descriptors, image-spec v1.1.1.** Open Containers Initiative, 2025-03-03, accessed 2026-09-27. https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md — descriptor media type, size, digest, and verification.
- **[S3] OCI Image Manifest Specification, artifact guidance, image-spec v1.1.1.** Open Containers Initiative, 2025-03-03, accessed 2026-09-27. https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md — artifact manifest, empty config, artifact type, and descriptor layers.
- **[S4] RFC 8785, JSON Canonicalization Scheme.** RFC Editor, 2020-06, accessed 2026-09-27. https://www.rfc-editor.org/rfc/rfc8785.html — invariant JSON representation, deterministic property ordering, and UTF-8 generation.
- **[S5] fsync(2).** Linux man-pages project, POSIX.1-2024, accessed 2026-09-27. https://man7.org/linux/man-pages/man2/fsync.2.html — file durability and directory synchronization.
- **[S6] rename(2).** Linux man-pages project, accessed 2026-09-27. https://man7.org/linux/man-pages/man2/rename.2.html — atomic rename and `RENAME_NOREPLACE` semantics.
- **[S7] openat2(2).** Linux man-pages project, Linux 5.6+, accessed 2026-09-27. https://man7.org/linux/man-pages/man2/openat2.2.html — descriptor-relative resolution and `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV` controls.
- **[S8] flock(2).** Linux man-pages project, accessed 2026-09-27. https://man7.org/linux/man-pages/man2/flock.2.html — shared/exclusive advisory locks and their open-file-description lifetime.
