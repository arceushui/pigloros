# ADR-425 draft — local OCI ReleaseSource and crash-safe publication

**Status:** Draft for independent review; **not accepted** | **Wave:** 8 | **Deciders:** core team | **Date:** 2026-09-27

Related: #425 · #401 · [[ADR-061_Sandboxed_Community_Plugin_Runtime_and_Decentralized_Artifact_Trust]] · [[ADR-065_KeyRegistry_Authorized_Signing_After_Destruction]]

---

## Status and decision boundary

ADR-061 revision 8 remains **Under Review** for `PluginReleaseSigning` amendment revision 2. Its accepted prior decisions select OCI packaging, while the revision says #425's *accepted* contract must still name the source-neutral boundary, final identity, collision rule, durable publication ordering, recovery, and cleanup. This local review draft fills that decision gap. It neither amends nor accepts ADR-061 and does not authorize production code.

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

It is immutable transport identity, not PMF1's BLAKE3 `release_digest`; it contains no tag, URL, or local path. Manifest bytes are limited to 64 KiB. The closure has at most 256 blobs, each at most 32 MiB and at most 64 MiB total. The inherited PMF1 and WIT limits remain 1 MiB and 4 MiB.

```text
ReleaseSourceV1::read_verified(BundleAddressV1)
  -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1>
```

`VerifiedReleaseBundleV1` contains exact root-manifest bytes and an immutable digest-ordered collection of every descriptor-referenced blob. Its constructor is private to the verifier. The port verifies the root descriptor, parses only bounded OCI JSON, then verifies every referenced blob's byte count and SHA-256 before returning. It rejects unknown manifest fields, duplicate descriptors, non-SHA-256 descriptors, URLs, embedded data, a subject, malformed JSON, descriptor/media-type mismatch, absent blob, excess bounds, symlinks, and unreferenced local-adapter blobs.

Closed errors are `InvalidAddress`, `NotFound`, `BoundsExceeded`, `InvalidLayout`, `InvalidDescriptor`, `DigestMismatch`, `SizeMismatch`, `DuplicateMember`, `UnsupportedMediaType`, `Uncommitted`, `Collision`, `Io`, `Sync`, `LockUnavailable`, and `RecoveryRequired`. They disclose no filesystem paths. A failure yields no partial bundle. The port never parses PMF1 or decides signing, trust, admission, or activation.

### Exact OCI artifact closure

The root manifest and `index.json` use RFC 8785 JCS UTF-8 bytes, with no trailing newline. The root has `schemaVersion: 2`, media type `application/vnd.oci.image.manifest.v1+json`, and artifact type `application/vnd.pigloros.plugin.release.v1`. Its config is OCI's exact empty JSON descriptor: media type `application/vnd.oci.empty.v1+json`, bytes `{}`, size 2, SHA-256 `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`. It has no `subject`, URLs, embedded data, platform, or annotations except `org.pigloros.plugin.member` on every layer descriptor.

Layer order is one `pmf1`, one `component`, one `wit`, zero or more `schema`, one `provenance`, one `sbom`, one or more `licence`, then zero or more `migration-fixture`. Repeated roles sort by raw SHA-256 digest.

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

The source validates this closure mechanically. #401 later validates that PMF1 descriptor fields and inner BLAKE3 values name exactly these bytes. Thus local, HTTPS, and registry adapters can return the same transport closure while PMF1 retains its semantic identity.

### Local layout and commit ordering

```text
<root>/
  published.json                 # sole durable discovery/commit index
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

`published.json` is RFC 8785 JCS JSON in this exact shape, with `addresses` digest-lexicographically sorted and unique:

```json
{"addresses":[{"digest":"sha256:<64 lowercase hex>","mediaType":"application/vnd.oci.image.manifest.v1+json","size":<u64>}],"version":1}
```

It is the sole durable discovery index. A reader accepts a release only when the index entry, final directory, `READY`, and entire revalidated closure agree. `READY` is recovery evidence only.

Under one exclusive store-root writer lock, the publisher accepts and revalidates only `VerifiedReleaseBundleV1`, then performs this sequence on one local filesystem:

```text
validate closure
  -> private staging under releases/
  -> write every blob, oci-layout, index.json; fsync every file
  -> fsync directories from blobs/ through staging root
  -> write and fsync READY; fsync staging root
  -> renameat2(NOREPLACE) staging -> releases/<manifest-sha256>
  -> fsync releases/
  -> write and fsync private next published.json
  -> atomically rename next index -> published.json
  -> fsync <root>/
```

The adapter refuses a target lacking same-filesystem staging, an exclusive writer lock, directory synchronization, or `RENAME_NOREPLACE`. It never falls back to copy-and-delete, overwrite rename, or an unsynchronized success. An error after a durable operation is `Sync` or `RecoveryRequired`; recovery is required before another publish. Success returns only after the root-directory sync.

### Collision, recovery, and fault injection

The final path is derived only from the lower-case root manifest SHA-256. On an existing path, the publisher revalidates it and reports idempotent success only when `READY`, `index.json`, root descriptor, and every closure byte match the requested verified bundle. Any mismatch, missing marker, malformed member, or index disagreement is `Collision` or `RecoveryRequired`; it is never overwritten.

Recovery holds the same lock before reads or writes:

1. Remove an owned staging directory only after confirming it remains below `releases/`, follows the staging name, has no symlink, and is absent from `published.json`.
2. Revalidate each final `READY` directory absent from the root index. Add a complete one through the durable index protocol; quarantine an incomplete one and return `RecoveryRequired`.
3. Revalidate every indexed final directory. A missing, changed, malformed, or unready release fails the entire source closed as `RecoveryRequired`.

No automatic deletion occurs for a once-ready final directory that no longer validates. V1 has no garbage collection or shared-blob deduplication.

Production exposes only `ReleaseSourceV1`, `LocalOciPublisherV1::publish`, and `recover`. Tests may use private `PublicationFaultPointV1` to fail one blob write, blob sync, directory sync, `READY` write/sync, final rename, `releases/` sync, next-index write/sync, index rename, or root sync. It cannot alter production inputs or be externally enabled.

Public-seam evidence must prove: roundtrip; missing/mutated member rejection; bounds and role/cardinality rejection; equivalent collision idempotency; non-equivalent collision refusal; staging invisibility; final-ready-but-unindexed recovery; indexed missing/mutated release fail-closed; and each injected failure leaves no discoverable partial release.

## Consequences and non-goals

The local adapter is Linux-local. Network filesystems, Windows, registry durability, tags, mutable aliases, shared blob storage, garbage collection, rollback, PMF1 codec/signature, KeyRegistry, trust admission, installer, and activation require separate accepted work. A verified OCI closure is inspectable only; it never admits, activates, or executes a Plugin.

## Sources

- **[S1] OCI Image Layout Specification, image-spec v1.1.1.** Open Containers Initiative, 2025-03-03, accessed 2026-09-27. https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md — required layout files and content-addressed blobs.
- **[S2] OCI Content Descriptors, image-spec v1.1.1.** Open Containers Initiative, 2025-03-03, accessed 2026-09-27. https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md — descriptor media type, size, digest, and verification.
- **[S3] OCI Image Manifest Specification, artifact guidance, image-spec v1.1.1.** Open Containers Initiative, 2025-03-03, accessed 2026-09-27. https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md — artifact manifest, empty config, artifact type, and descriptor layers.
- **[S4] RFC 8785, JSON Canonicalization Scheme.** RFC Editor, 2020-06, accessed 2026-09-27. https://www.rfc-editor.org/rfc/rfc8785.html — invariant JSON representation, deterministic property ordering, and UTF-8 generation.
- **[S5] fsync(2).** Linux man-pages project, POSIX.1-2024, accessed 2026-09-27. https://man7.org/linux/man-pages/man2/fsync.2.html — file durability and directory synchronization.
- **[S6] rename(2).** Linux man-pages project, accessed 2026-09-27. https://man7.org/linux/man-pages/man2/rename.2.html — atomic rename and `RENAME_NOREPLACE` semantics.
