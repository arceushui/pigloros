**Status:** Proposed | **Wave:** 8 | **Deciders:** core team | **Date:** 2026-09-28 | **Revision:** 4

Related: #400 · #201 · #292 · [[ADR-041_Scenario_Room_Configuration_and_Reproducible_Fork_Inputs]] · [[ADR-065_KeyRegistry_Authorized_Signing_After_Destruction]] · [[ADR-091_Subject_Key_Custody_and_Historical_Decryption]] · [[ADR-060_Subject_Erasure_and_Replay_Claim_Degradation]]

---

## Context

Accepted ADR-041 section 6 requires a signed `ReproManifest` for every
human-subject Fork. It requires the room revision descriptor hash, parent
Timeline logical head, Tick Boundary sequence, Plugin composition hash, and
intervention Event sequence. It calls for the Fork creator's ADR-039 subject
key. [S6] Accepted ADR-065 has since separated the
`SubjectAttributionSigning` role from `SubjectDataEncryption` and rejected the
former subject-data-key signature shape. Its generic non-Timeline Ed25519
preimage already binds exact owner, role, epoch, and complete canonical payload
bytes; it retains public verification after destruction. [S7] ADR-091 replaced
ADR-039's impossible credential-private-byte key derivation and keeps subject
encryption material inside a trusted owner adapter. [S8]

The current `pos-core::ReproManifest` is an unversioned experiment record with
`HashMap` plugin versions and no signer, signature, or required Fork provenance
fields. `pos-experiment` produces it and `pos-cli experiment verify` checks its
head hash only. `pos-conformance::ReproManifestV1` is a different strict
reproduction artifact. Neither is an ADR-041 signed Fork manifest. [S9]

**Decision question:** What exact first production record should
`SubjectAttributionSigning` sign so that a human-subject Fork has an
independently verifiable `ReproManifest` without claiming that the subject
consented merely because the Fork creator signed it?

This proposal addresses one artifact and its signature/publication contract.
It amends ADR-041 section 6's signer and byte contract. It does not change the
consent gate, `SubjectDataEncryption` custody, or Timeline integrity signing.

## Decision drivers

- Satisfy ADR-041's actual Fork provenance fields and mandatory human-subject
  signature; do not relabel the legacy experiment manifest. [S6, S9]
- Bind the authenticated Fork creator to the exact parent/Fork Timelines,
  revision, cut, composition, interventions, and final Fork head.
- Keep creator attribution distinct from subject consent: attribution relates
  an entity to an agent, while an activity's association with an agent is a
  separate provenance relation. [S1]
- Reuse ADR-065's role-separated active signing and retained historical
  verification, including its destruction/signing ordering. [S7]
- Make independent verification deterministic and fail closed for absent,
  malformed, modified, or noncanonical records. [S2, S3, S4]
- Avoid self-referential Timeline hashes and post-hoc signatures that imply
  an old unsigned artifact was originally authorized. [S7]

## Evidence and alternatives

| Option | Functional and replay fit | Security, compatibility, and cost | Decision |
|---|---|---|---|
| A. Versioned Fork manifest in deterministic CBOR, signed with ADR-065 `SubjectAttributionSigning` | Carries ADR-041's fields and exact binary identifiers; CBOR can enforce one deterministic byte form. [S2, S6, S7] | Reuses the existing Ed25519 and registry roles, but requires a new strict codec, trusted creator binding, and durable publication. [S5, S7, S9] | **Proposed.** |
| B. Versioned Fork manifest in JCS JSON, signed with ADR-065 `SubjectAttributionSigning` | Also yields reproducible signature bytes and is close to ADR-041's JCS descriptor hash. [S3, S6, S7] | JCS uses I-JSON numbers; full `u64` Timeline sequences need an explicit string mapping, and the project would maintain both JSON and CBOR canonical contracts. [S3, S9] | Viable; reject for this binary record. |
| C. COSE_Sign1 over a deterministic CBOR Fork manifest | Standard one-signer envelope with protected headers and a defined `Sig_structure`. [S2, S4] | Its signature input differs from ADR-065's normative owner/role/epoch preimage. Adopting it needs another ADR-065 amendment and strict protected-header policy; a generic COSE signature alone does not bind the project owner role. [S4, S7] | Viable after a separate amendment; reject for V1. |

Consent grants and human actions are distinct possible first attribution
artifacts. A grant would depend on the proposed `consent.granted.v2` and #399;
an action needs its own actor/subject claim and public action protocol. Neither
closes ADR-041's existing signed Fork-manifest requirement. This is a project
scope inference from the inspected code and tickets, not a standards claim.
Signing the existing unversioned `ReproManifest` is rejected: it lacks the
required fields and canonical byte contract. [S6, S9]

## Proposed decision

**Project recommendation (inference from S1-S9):** make the first
`SubjectAttributionSigning` production artifact a creator-attributed
`ForkReproManifestV1` for human-subject Forks. The registered key owner is the
authenticated Fork creator's `OwnerIdV1`, obtained by the trusted host at Fork
admission, never from a manifest field or unauthenticated client text. The
signature says that this creator issued the exact Fork manifest. It does **not**
say that each human subject signed, approved, or consented; the existing consent
and Replay access gates remain independent. This replaces only ADR-041 section
6's use of the Fork creator's ADR-039 subject key. [S1, S6, S7, S8]

### Exact V1 bytes

`ForkReproManifestV1` is one definite-length CBOR array, encoded with RFC
8949 core deterministic requirements, no tags, no maps, no floating-point
values, and no trailing bytes. Its wire length is at most 16,384 bytes.
`TimelineId` values are exact 16-byte ULIDs; hash fields are exact 32-byte
values. Unsigned integers use the shortest CBOR form. The ordered intervention
list has at most 1,024 strictly increasing logical Timeline sequence values.
All listed intervention sequences must be greater than the parent cut and at
most the Fork logical head. Zero is valid for an empty parent cut or initial
Tick Boundary. Unknown version, noncanonical encoding, wrong width, duplicate
or out-of-order intervention, excess length, and any extra field are rejected.
The bounds are project policy; the deterministic encoding rule comes from
RFC 8949. CDDL's bounded occurrence and `.size` operators express the array
and byte-length limits below. [S2, S6, S10]

```cddl
fork-repro-manifest-v1 = [
  "FRM1",                      ; position 0: format marker
  1,                           ; 1: version
  bstr .size 16,               ; 2: parent TimelineId
  bstr .size 16,               ; 3: Fork TimelineId
  bstr .size 32,               ; 4: trusted ForkAdmissionRecordV1 digest
  bstr .size 32,               ; 5: room revision descriptor_hash
  uint,                        ; 6: parent logical_head at Fork cut
  bstr .size 32,               ; 7: parent chain hash at that logical_head
  uint,                        ; 8: post-fold Tick Boundary seq
  bstr .size 32,               ; 9: plugin_composition_hash
  [0*1024 uint],               ; 10: complete intervention Event logical seq set
  uint,                        ; 11: final Fork logical_head
  bstr .size 32                ; 12: final Fork chain head hash
]

signed-fork-repro-manifest-v1 = [
  "FSM1",                      ; position 0: signed-record marker
  1,                           ; 1: version
  tstr .size (1..128),         ; 2: exact creator OwnerIdV1 UTF-8 bytes
  1,                           ; 3: SubjectAttributionSigning role code
  1..18446744073709551615,    ; 4: positive signing epoch
  bstr .size (1..16384),      ; 5: complete canonical fork-repro-manifest-v1 bytes
  bstr .size 64                ; 6: Ed25519 signature
]
```

The outer record is also deterministic CBOR, at most 16,640 bytes. Its role is
exactly code `1`, and the signer identity is exactly
`KeyIdentityV1 { owner_id: creator, role: SubjectAttributionSigning, epoch }`.
The signature input is ADR-065's existing generic role-bound preimage over the
**complete inner canonical bytes**; there is no new hash-to-sign, COSE
`Sig_structure`, payload-only fallback, or signature over the outer record.
The outer creator `OwnerIdV1` must equal the trusted Fork-provenance creator.
The record identifier, when needed by an artifact store, is
`BLAKE3(ASCII("pigloros/fork-signed-manifest/v1") || complete_outer_bytes)`.
That identifier is not inside either signed array, preventing a self-edge.
[S2, S5, S7]

### Fork admission authority and creator provenance

`ForkAdmissionRecordV1` is the durable host authority for the creator relation;
the signed wrapper is not allowed to establish that relation by referring to
itself. Its exact deterministic-CBOR records are:

```cddl
principal-owner-binding-v1 = [
  "POB1",                      ; 0: marker
  1,                           ; 1: version
  bstr .size 32,               ; 2: stable operation_id
  bstr .size 32,               ; 3: PrincipalRefV1 canonical-byte digest
  tstr .size (1..128),         ; 4: exact OwnerIdV1 UTF-8 bytes
  authority-origin-v1          ; 5: trust anchor
]
authority-origin-v1 = [1] / [2, bstr .size 32]
                               ; local / #202 verified-envelope digest
fork-admission-record-v1 = [
  "FAR1",                      ; 0: marker
  1,                           ; 1: version
  bstr .size 32,               ; 2: stable operation_id
  bstr .size 32,               ; 3: principal-owner-binding digest
  tstr .size (1..128),         ; 4: creator OwnerIdV1
  bstr .size 16,               ; 5: parent TimelineId
  bstr .size 16,               ; 6: child Fork TimelineId
  bstr .size 32,               ; 7: room revision descriptor_hash
  uint,                        ; 8: parent logical head / cut
  bstr .size 32,               ; 9: parent chain hash at cut
  uint,                        ; 10: completed Fold Cursor
  uint,                        ; 11: post-fold Tick Boundary seq
  bstr .size 32,               ; 12: plugin_composition_hash
  0 / 1,                       ; 13: attribution_required
  authority-origin-v1          ; 14: trust anchor
]
```

Both use the strict deterministic-CBOR rules above and are bounded to 320 and
768 bytes respectively. The principal digest is
`BLAKE3(ASCII("pigloros/principal-ref/v1") || PrincipalRefV1::encode())`.
Binding and admission digests use domains
`pigloros/principal-owner-binding/v1` and `pigloros/fork-admission/v1`, followed
by complete canonical bytes. Operation IDs and digests are nonzero 32-byte
values. Imported origin code 2 is invalid until #202 authenticates its envelope.

`PrincipalOwnerAuthorityPortV1::resolve_authenticated` consumes a still-valid
`AuthenticatedPrincipalResultV1`, validates its adapter, expiry, assurance and
binding digest, and returns the one immutable locally committed binding for
that exact Principal. Neither caller nor manifest supplies the Owner. One
Principal digest maps to exactly one Owner; one Owner may have several
Principals. Rebinding, deletion, and conflicting import reject. An operation-ID
retry succeeds only if every canonical binding byte matches.

The trusted host constructs the admission from that binding. A client cannot
submit or replace it. `attribution_required` comes from trusted protected
history and consent state; no raw token or subject identifier is retained.
There is exactly one admission per child and operation ID. Exact retry returns
the existing child/record; reuse with unequal canonical fields is `Conflict`.
Committed records are immutable while the Fork exists.

The record's digest is
`BLAKE3(ASCII("pigloros/fork-admission/v1") || canonical_record_bytes)` and is
field 4 of `ForkReproManifestV1`. The authoritative store provides a
`ForkAdmissionAuthorityPortV1` read that returns the exact immutable record by
child Fork ID. Verification trusts only a locally committed record or a record
accepted through the future #202 identity-preserving verified-import boundary.
A caller-supplied record, a structurally imported record, a digest without its
record, or a second record for the same child fails closed. The wrapper creator
must equal the admission creator, and every duplicated manifest field must
equal its admission-record value.

`ForkAdmissionAuthorityPortV1::create_fork_admitted` is the sole V1
human-subject Fork creation operation. Its request carries the operation ID,
authenticated-principal result, expected parent ID, expected completed Fold
Cursor and post-fold Tick Boundary, descriptor/composition hashes,
attribution policy, and child name. It carries no child ID, Owner, parent
head/hash, or record bytes. In one write transaction the adapter resolves the
Principal-to-Owner binding, rereads parent head/hash, allocates and creates the
child metadata, encodes and inserts admission, then commits. Child and
admission become visible together; failure rolls both back.

The admission transaction has one boundary invariant:

```text
parent logical_head at cut
  == completed Fold Cursor
  == post-fold Tick Boundary sequence
  == durable parent logical_head observed while creating the child
```

The equality may be zero only for an empty parent. The host passes the
completed in-memory values captured after a contiguous fold; the adapter
compares them under the creation transaction. Fork admission is rejected
if pending Events exist beyond the Fold Cursor, the captured range is not
contiguous, the parent head changes before commit, or the child metadata does
not name that exact parent/cut. The admitted composition and room revision are
captured under the same boundary. This specializes the current experiment
host behavior, where `ExperimentSession::fork` selects
`boundary.folded_through` and separately reads the durable head; V1 requires
equality rather than permitting those observations to diverge.

### Complete intervention provenance

An intervention Event is an external input classified as an intervention by
the admitted room revision. Event type text alone is not authority. Exact
records are:

```cddl
event-origin-record-v1 = [
  "EOR1",                      ; 0: marker
  1,                           ; 1: version
  bstr .size 16,               ; 2: Fork TimelineId
  uint,                        ; 3: logical sequence
  bstr .size 16,               ; 4: EventId
  0 / 1,                       ; 5: host-internal / external input
  0 / 1,                       ; 6: non-intervention / intervention
  bstr .size 32,               ; 7: classifier revision digest
  bstr .size 32                ; 8: Fork-admission digest
]
fork-intervention-admission-v1 = [
  "FIA1",                      ; 0: marker
  1,                           ; 1: version
  bstr .size 32,               ; 2: external-input operation_id
  bstr .size 16,               ; 3: Fork TimelineId
  uint,                        ; 4: logical sequence
  bstr .size 16,               ; 5: EventId
  bstr .size 32,               ; 6: payload hash
  bstr .size 32,               ; 7: room revision descriptor_hash
  bstr .size 32,               ; 8: classifier revision digest
  bstr .size 32                ; 9: Fork-admission digest
]
```

They are strict deterministic-CBOR arrays bounded to 384 and 512 bytes; their
digest domains are `pigloros/event-origin/v1` and
`pigloros/fork-intervention-admission/v1`. The classifier is total over every
host append and returns exactly `(origin, intervention)`: internal must be
`(0,0)` and external is `(1,0)` or `(1,1)`; `(0,1)` rejects. Its revision
digest binds the complete admitted table of external ingress routes and schemas
for the room revision. Unknown routes/schemas reject before Event construction.

`ForkEventAppendAuthorityPortV1::append_classified` is the sole append path for
an admitted Fork. Generic append, driver output, and structural import sit
below this host port and cannot directly append to such a Fork. In one
transaction it rereads admission/classifier, classifies the trusted source
descriptor, allocates sequence, appends the Event, and inserts exactly one
origin record. For `(1,1)` it also inserts exactly one intervention admission;
otherwise that row is forbidden. All commit or roll back together. Exact
operation-ID retry requires source, draft, classification, and every record
byte to match; otherwise it conflicts.

The manifest producer reads the complete stitched logical range
`(parent_cut, final_fork_head]` and requires exactly one matching origin record
for every child-segment Event. It rejects absent/duplicate/orphan origin rows,
impossible class pairs, classifier/admission mismatches, and intervention-row
presence not exactly equivalent to `(1,1)`. Each `(1,1)` record must match
Event ID, payload hash, descriptor, classifier, Fork, sequence and admission.
The producer encodes all such sequences in increasing order and rejects rows
outside the suffix or more than 1,024 interventions. Verification repeats this
total derivation and requires byte-exact equality to field 10. Omitted,
inserted, reordered, duplicated, relabelled, or unclassified external input
fails closed. Import remains unavailable until #202 verifies both authorities.

The three authority writes return only committed receipts:
`ForkAdmissionReceiptV1 { child_id, admission_digest }`,
`ForkAppendReceiptV1 { event_id, logical_seq, origin_digest,
intervention_digest: Option<Hash> }`, and the publication receipt below.
Their closed error set distinguishes `InvalidRequest`, `Unauthenticated`,
`PrincipalOwnerConflict`, `StaleFoldBoundary`, `ParentChanged`,
`ClassifierRejected`, `SequenceOrHeadChanged`, `RegistryChanged`,
`SigningFailed`, `Conflict`, `CorruptAuthority`, and `StorageIndeterminate`.
Validation errors precede durable mutation; compare failures precede inserts;
commit/rollback uncertainty is `StorageIndeterminate`. Recovery always uses the
stable operation ID and returns a receipt only after byte-exact revalidation;
`Absent` may be retried, `Committed` is returned, and partial/conflicting state
is `CorruptAuthority` and is never repaired by a second write.

### Producer, verifier, and ordering

```text
authenticated Fork creator + consent gate
        -> trusted Fork admission / creator OwnerIdV1 binding
        -> versioned provenance producer / exact Fork head
        -> KeyRegistry SubjectAttributionSigning callback
        -> atomic signed-manifest artifact publication
        -> Replay verifier + separate consent/access/erasure checks
```

The producer obtains the admission record and every duplicated admission field
through `ForkAdmissionAuthorityPortV1`, then obtains the final Fork head, chain
hash, Events, and intervention admissions from the same authoritative durable
adapter. It does not accept any manifest field from the caller. The final head
is captured after the included run and must still match at publication commit.
[S6, S9]

The durable adapter exposes one purpose-specific
`ForkManifestPublicationPortV1::commit_authorized` operation. The caller gives
it a stable publication operation ID, child Fork ID, expected final head, exact
creator signing identity, private-material fingerprint, derived public key,
and an expected durable registry snapshot. It does not give it manifest
provenance fields or signed bytes.

`commit_authorized` owns the transaction and callback. Under the same
serialization domain used by registration, rotation, and destruction, it:

1. rejects zero epoch and any role other than exactly
   `SubjectAttributionSigning`, then begins a write transaction and acquires
   the registry/rotation/destruction serialization lock;
2. loads the durable `KeyRegistryStateV1`, requires it to equal the expected
   snapshot, validates the complete registry state, and performs ADR-065's
   full active signing authorization against the supplied exact
   `KeyIdentityV1`, private-material digest, and public key: the identity record
   must exist; no tombstone may exist; no pending-destruction entry may exist;
   the active index for `(owner_id, SubjectAttributionSigning)` must equal that
   exact identity and epoch; and the record's `Some(private_material_digest)`
   and `Some(public_verification_key)` must exactly equal the supplied values;
3. only after every authorization check succeeds, constructs one
   `HeldRegistryAuthorizationV1` from that validated active record and immutable
   in-memory snapshot; then loads and validates the immutable Fork admission,
   exact final head and chain
   hash, and complete intervention set;
4. invokes exactly once a synchronous, non-escaping
   `FnOnce(&HeldRegistryAuthorizationV1, &[u8]) -> Result<[u8; 64], SignError>`
   with the held authorization and complete canonical inner bytes;
5. the callback signs ADR-065's exact preimage for the held identity and
   returns only the signature;
6. validates the outer bytes and inserts the immutable artifact, its record ID,
   and a unique `(Fork TimelineId, final logical_head)` binding; and
7. commits before returning only a publication receipt containing the record
   ID. The caller reads committed bytes through a separate receipt-bound read.

`HeldRegistryAuthorizationV1` exposes only identity, public key,
private-material digest, and immutable snapshot digest. It has no store handle
and cannot escape, clone, or become a bearer token. Signing constructs the
ADR-065 preimage in memory. It MUST NOT call `sign_for_registered_role`,
`with_signing_authorization`, `load_key_registry`, or any SQLite/store method
while the publisher lock/transaction is held.

Any failure in steps 1 or 2 returns before inner-byte construction and MUST
NOT construct the held authorization or invoke the callback. The exact closed
registry precedence is ADR-065/current `KeyRegistryStateV1`: `InvalidEpoch`,
then `SigningRoleRequired`; malformed/unavailable or unequal expected durable
snapshot (`RegistryUnavailable` or `RegistryChanged`); `NotFound`; `Destroyed`;
`DestructionPending`; `InactiveKey` for a missing or unequal active identity;
then `SigningKeyMismatch` for either material-digest or public-key inequality.
The publisher does not collapse these into `SigningFailed`. A callback error is
`SigningFailed` only after active authorization succeeded.

No signature or uncommitted bytes escape on callback, validation, insertion,
or commit failure. Rollback leaves no artifact or binding. The operation ID is
idempotent only when creator identity, admission digest, final Fork head/hash,
inner bytes, outer bytes, record ID, and binding all match exactly; any partial,
missing, or conflicting state fails closed. Recovery looks up that stable
operation ID and returns the existing receipt only after revalidating every
binding. It never signs again to repair an ambiguous result.

The exact registry errors above precede head/provenance errors; those precede
callback `SigningFailed`; signing precedes outer validation/insertion;
commit/rollback errors are last and never become success. Recovery states are exactly `Absent`,
`Committed(receipt)`, or `CorruptOrConflicting`; there is no durable `Pending`
because operation, binding, and artifact share one transaction. An
indeterminate commit is recovered by operation-ID lookup and full validation.

This is a new purpose-specific orchestration seam modeled on the current
`EventStore::append_signed_authorized` pattern. Calling current
`sign_for_registered_role` inside or before publication is forbidden: inside
would re-enter the registry/store boundary and before would end authorization
before commit. If destruction wins the shared
serialization boundary first, publication never invokes the callback; if the
publication transaction commits first, later destruction retains its public
verification material. [S7]

The public boundary vectors are normative:

| Vector | Durable registry state / request | Result and callback count |
|---|---|---|
| Authorized | exact active creator + role 1 + positive epoch + matching material digest/public key; no tombstone or pending destruction | committed receipt; callback exactly once |
| Zero epoch | otherwise valid, epoch 0 | `InvalidEpoch`; 0 |
| Wrong role | positive epoch, any role other than `SubjectAttributionSigning` | `SigningRoleRequired`; 0 |
| Snapshot changed/malformed | durable snapshot unequal to expected, unavailable, or invalid | `RegistryChanged` or `RegistryUnavailable`; 0 |
| Missing identity | valid snapshot with no exact identity record | `NotFound`; 0 |
| Tombstoned | exact record and tombstone present | `Destroyed`; 0 |
| Destruction pending | exact record and pending-destruction entry present | `DestructionPending`; 0 |
| Stale/inactive | exact record exists but active index is absent or names another epoch | `InactiveKey`; 0 |
| Material mismatch | active record private-material digest differs | `SigningKeyMismatch`; 0 |
| Public-key mismatch | active record public verification key differs | `SigningKeyMismatch`; 0 |
| Post-authorization provenance conflict | authorization valid; admission/head/intervention recheck fails | matching provenance error; 0 |
| Signer failure | authorization and provenance valid; callback fails | `SigningFailed`; 1, rollback |
| Destruction wins lock | pending/destruction state committed before publisher acquires the boundary | `DestructionPending` or `Destroyed`; 0 |
| Publication wins lock | publisher acquires boundary first and commits | committed receipt; callback exactly once; later destruction retains verification key |

The signed manifest is a sidecar artifact, **outside the Fork Timeline whose
head hash it records**. Appending it to that Fork would make the signed head
self-referential. A later Fork Event requires a new manifest with a new final
head; an old manifest remains an immutable statement about its former head.
The durable publisher must bind a single Fork/head to the exact record ID and
reject conflicting replacement. A separate audit Timeline may reference the
record ID after publication without altering the signed Fork head.

Verification first strictly parses and re-encodes both arrays to the exact
input bytes, then resolves the exact `ForkAdmissionRecordV1` from the trusted
authority port and checks its digest, creator, child, parent, cut, boundary,
composition, and attribution policy. It then checks role and epoch, retained
public key, and ADR-065 role signature. It validates the parent and final chain
hashes against the authoritative stored Timelines and recomputes the complete
intervention vector as specified above. A bare mathematically
valid signature does not establish consent, pre-destruction authorized
issuance, or the truth of unverified provenance fields. Human-subject status
comes from trusted subject/consent state, never from an unsigned or
self-declared flag. [S1, S6, S7]

For a human-subject Fork, a missing, malformed, untrusted, or mismatched signed
manifest aborts Replay **before execution**. The ADR-041 Replay grant and
consent token are checked separately; erasure can still weaken ReplayClaim
without invalidating the historical mathematics of a retained signature.
Non-human-subject Forks may omit the signature as ADR-041 already permits, but
the descriptor and parent-head checks still apply. Trusted identity-preserving
import of an external Timeline remains closed until #202 supplies the
normative Timeline envelope verifier; a structurally imported Event is not
authenticated evidence. [S6, S7]

## Consequences and risks

- **Attribution scope:** the signer is the creator, not necessarily the data
  subject. The UI/API must not phrase this as subject endorsement. If a future
  product needs each subject's signed approval, decide a separate consent
  signature protocol. [S1]
- **Availability:** a creator without a live registered
  `SubjectAttributionSigning` key cannot publish a human-subject Fork manifest.
  Failing closed is required; no subject-encryption-key fallback. [S6, S7]
- **Privacy:** the wrapper exposes creator owner and Fork linkage. Keep any
  subject identifiers, raw consent tokens, personal fields, and protected
  payloads out of the manifest. Access to the artifact follows the Fork's
  visibility and Replay grants; a signature is not permission to export.
- **Replay:** old authorized signatures remain verifiable after key destruction
  through retained public material; destruction stops new signing and may
  separately degrade data access or ReplayClaim. [S7]
- **Operational and supply chain:** the selected path reuses the repository's
  CBOR, BLAKE3, and Ed25519 implementations; it adds a strict codec, a
  provenance producer, and a durable sidecar artifact publisher, with no new
  external key service or signing dependency. COSE would add a distinct
  signature-input policy and parser surface. [S2, S4, S5, S7]

## Migration and rollout

1. Split the principal-to-Owner binding and Fork admission authority, total
   classified append/intervention authority, manifest producer, and atomic
   artifact publication prerequisite into their own ticket/PRs under #400. That work must
   not claim a signed human-subject artifact until this ADR is accepted.
2. In #400's separate role-specific PR, bind an authenticated creator owner,
   register/rotate the `SubjectAttributionSigning` key, sign through the held
   registry callback, publish atomically, and verify with retained public
   material. Host-side tests must cover wrong owner/role/epoch/material,
   altered fields, copied material, stale/destroyed signing, historical
   verification, creator/admission mismatch, incomplete intervention sets,
   head/Fold-Cursor divergence, exact retry/conflict/recovery,
   missing consent/grant, rotation/destruction races, and failed commit with no
   trusted record. Run Cargo tests, mutation and the 99%
   line/region coverage gate in GitHub Actions only.
3. Existing unversioned experiment manifests remain readable for their former
   non-human workflow but are never upgraded post hoc to a signed
   human-subject claim. Human-subject Replay requires the new record after
   rollout; unknown versions fail closed. A format or signer-claim change
   requires a new ADR. [S6, S7, S9]

This proposal does not assert that current Gateway authentication, Scenario
Room admission, Fork provenance, or durable sidecar publication already exists.
The producer and trusted creator binding are activation prerequisites; they
must be implemented and independently reviewed before #400 can be resolved.

## Non-goals

- Subject consent or encryption, subject approval signatures, and WebAuthn
  credential-private-byte access.
- Timeline integrity signatures, Plugin release signatures, and export
  recipient encryption.
- COSE compatibility, unsigned human-subject fallback, legacy
  `ReproManifest` signing, or retroactive attestation of old unsigned Forks.
- Treating a signature as proof that external Timeline data is authentic
  before #202's verifier.

## Sources

- **[S1]** W3C, [PROV-DM: The PROV Data Model](https://www.w3.org/TR/prov-dm/), Recommendation, 2013-04-30; accessed 2026-09-27. Supports the distinction between entity attribution and activity association, which informs the limited creator claim.
- **[S2]** IETF, [RFC 8949: Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949.html), Standards Track, 2020-12; accessed 2026-09-27. Supports deterministic CBOR form, shortest representations, definite lengths, and strict byte validation.
- **[S3]** Independent Submission, [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html), Informational, 2020-06; accessed 2026-09-27. Supports JCS as a viable alternative and its I-JSON numeric constraints.
- **[S4]** IETF, [RFC 9052: COSE Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html), Standards Track, 2022-08; accessed 2026-09-27. Supports COSE_Sign1 and its distinct `Sig_structure` signature input.
- **[S5]** IRTF, [RFC 8032: Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032.html), Informational, 2017-01; accessed 2026-09-27. Supports Ed25519 algorithm and verification/test-vector behavior.
- **[S6]** PiglorOS, [ADR-041 Scenario Room Configuration and Reproducible Fork Inputs](https://redmine.piglor.com/projects/pigloros/wiki/ADR-041_Scenario_Room_Configuration_and_Reproducible_Fork_Inputs), accepted wiki v5; accessed 2026-09-27. Supplies the existing Fork provenance and Replay requirements amended here.
- **[S7]** PiglorOS, [ADR-065 KeyRegistry Authorized Signing After Destruction](https://redmine.piglor.com/projects/pigloros/wiki/ADR-065_KeyRegistry_Authorized_Signing_After_Destruction), accepted wiki v17; accessed 2026-09-27. Supplies role separation, exact signing preimage, atomic authorization, error precedence, and retained historical verification.
- **[S8]** PiglorOS, [ADR-091 Subject Key Custody and Historical Decryption](https://redmine.piglor.com/projects/pigloros/wiki/ADR-091_Subject_Key_Custody_and_Historical_Decryption), accepted wiki v3; accessed 2026-09-27. Supplies the replacement of ADR-039 credential-private-byte derivation and the separate subject encryption owner boundary.
- **[S9]** PiglorOS source at `main` b45c65a8: [core manifest](https://github.com/arceushui/pigloros/blob/b45c65a8f9f75c10a8df6da51502479d3587a6de/crates/pos-core/src/manifest.rs), [experiment producer](https://github.com/arceushui/pigloros/blob/b45c65a8f9f75c10a8df6da51502479d3587a6de/apps/pos-experiment/src/lib.rs), [CLI verifier](https://github.com/arceushui/pigloros/blob/b45c65a8f9f75c10a8df6da51502479d3587a6de/apps/pos-cli/src/main.rs), and [conformance manifest](https://github.com/arceushui/pigloros/blob/b45c65a8f9f75c10a8df6da51502479d3587a6de/crates/pos-conformance/src/lib.rs); inspected 2026-09-27. Establishes the current manifest shapes and verification behavior.
- **[S10]** IETF, [RFC 8610: Concise Data Definition Language](https://datatracker.ietf.org/doc/html/rfc8610), Standards Track, 2019-06; accessed 2026-09-27. Supports the CDDL array occurrence and text/byte `.size` constraints used by the proposed schema.
