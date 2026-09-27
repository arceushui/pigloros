# #423 working draft: ADR-061 Plugin trust records (unpublished)

Date: 2026-09-27. This is a local design candidate, not an accepted ADR. The user accepted the complete ADR-061 PluginReleaseSigning amendment from wiki v8; the canonical page is Accepted at wiki v10. That approval leaves this exact trust-record contract to be decided separately. Parent #401 cannot use this candidate for production admission.

## Decision question and ownership

What bounded, versioned evidence lets a public verifier authenticate Plugin publisher keys, exact Plugin ID grants, and key/artifact revocations from an operator-pinned bootstrap root? #423 owns record codecs and stateless chain verification. ADR-058/#424 owns the operator-pinned anchor, durable floors, trusted time source, TPS1 authentication, and activation state. ADR-065 KeyRegistry remains the sole authority for *issuing* publisher role-3 signatures. A root record only says which public key and exact Plugin ID the deployment may trust; it does not copy private material or create another publisher-key registry.

```text
operator-pinned root digest -> PTR1 root chain -> exact publisher key + Plugin ID text
                            -> PRV1 cumulative revocations
                            -> verified evidence for #424
#424 persisted floors + current policy -> #401 install/activation decision
```

## Evidence and alternatives

| Option | Fit and cost |
|---|---|
| A. Use TUF metadata wire format wholesale | TUF defines root/targets/timestamp roles, thresholds, expiry, and rollback defenses [S1]. It would add a second JSON/multi-role metadata stack beside PMF1 and TPS1; no production TUF repository currently exists in PiglorOS. |
| **B. Two strict CBOR records with TUF-style rotation (candidate)** | Reuses PiglorOS deterministic CBOR, BLAKE3, Ed25519 [S2][S3], and the existing operator-policy owner. Requires explicit bytes, tests, and care not to claim the full TUF threat model. |
| C. COSE Sign/Sign1 around a loose trust document | COSE fixes signed-message representation [S4], but application code still must bind key identity and authority [S4]; threshold, continuity, namespaces, and durable floors remain custom. |

Candidate inference: B is the thinnest exact contract that composes with PMF1. Its expiry and chain checks limit stale metadata, but an offline peer cannot detect a withheld newer update until expiry [S1]. Root key compromise above threshold requires an out-of-band rebootstrap [S1].

## Proposed normative shape for review

All records use one definite-length CBOR array. Text is CBOR major type 3 with shortest definite length and valid UTF-8; byte strings are major type 2 with shortest definite length; unsigned integers are major type 0 in the shortest form; negative UTC seconds are major type 1 in the shortest form; and `null` is the single byte `f6`. Maps, tags, floats, simple values other than `null`, indefinite lengths, unknown fields, missing fields, and trailing data are rejected. A decoder must re-encode the typed value and require byte-for-byte equality [S2]. Digests are raw BLAKE3-256 of the *complete* canonical record including signatures. Domain-separated pure Ed25519 signs the exact unsigned-prefix CBOR bytes, not a separately hashed or textual representation [S3]. One wire version only; no fallback. Limits are V1 protocol maxima and must be checked while decoding, before allocating a claimed collection.

For every sorted V1 collection below, comparison is unsigned lexicographic order over the tuple members in their listed order: text compares exact UTF-8 bytes, byte strings compare raw bytes, and integers compare numeric value. Strictly increasing means duplicates are rejected. Fixed byte lengths are validation requirements.

### Plugin ID and exact grant

This candidate preserves Accepted ADR-061 wiki v10's PMF1 V1 Plugin-ID contract unchanged. PMF1 field 2 is canonical UTF-8 text in the ASCII subset `[a-z0-9][a-z0-9._/-]*`, 1–128 bytes: its first byte is a lowercase ASCII letter or digit and every remaining byte is a lowercase ASCII letter, digit, `.`, `_`, `/`, or `-`. PTR1 V1 uses that same grammar and carries the exact text bytes. #423 neither narrows PMF1 V1 to a ULID nor defines a mapping to `pos_core::PluginId`.

PTR1 V1 grants authority only to exact, complete Plugin ID text. Equality is byte-for-byte equality between the validated PMF1 field 2 text and the PTR1 grant field. `/`, `.`, `_`, and `-` are ordinary identifier bytes: they do not create hierarchy, publisher namespaces, prefixes, paths, or glob semantics. One grant never authorizes another ID. A future structural namespace or runtime-ULID binding requires a separately accepted, versioned manifest/trust-record contract; it cannot reinterpret PMF1 V1 or PTR1 V1.

`PluginTrustRootRecordV1/PTR1`: exact 12 fields, maximum 1 MiB:

| # | Field | Candidate rule |
|---:|---|---|
| 0 | magic | text `PTR1` |
| 1 | version | unsigned integer `1` |
| 2 | policy scope | text length 1–128; first byte lowercase ASCII letter or digit; remaining bytes lowercase ASCII letter, digit, `.`, `_`, `/`, or `-` |
| 3 | root version | nonzero unsigned u64 |
| 4–5 | not-before, expires | signed i64 UTC seconds; not-before < expires and `expires - not_before <= 31,622,400` seconds (366 days), evaluated without overflow |
| 6 | previous root digest | `null` only for pinned genesis, otherwise bstr32 |
| 7 | root threshold | unsigned 1..32 and no greater than root-key count |
| 8 | root keys | array length 1..32 of exact `[key_id_bstr32, public_key_bstr32]`, strictly sorted by key ID |
| 9 | publisher keys | array length 0..256 of exact `[owner_id_text, role_code_uint=3, epoch_uint>0, public_key_bstr32]`, strictly sorted by `(owner UTF-8, role, epoch, public key)`; owner is exact `OwnerIdV1` |
| 10 | exact Plugin ID grants | array length 0..256 of exact `[plugin_id_text, owner_id_text]`; Plugin ID text has the accepted PMF1 V1 grammar above; strictly sorted by `(Plugin ID UTF-8 bytes, owner UTF-8 bytes)` |
| 11 | signatures | array length 1..64 of exact `[root_key_id_bstr32, signature_bstr64]`, strictly sorted by root key ID |

`root_key_id = BLAKE3("pigloros/plugin-root-key-id/v1\0" || public_key32)`, with the quoted domain encoded as its exact ASCII bytes including the terminal NUL. Every root-key entry must carry that derived ID. Root key IDs are unique, root public keys are unique, publisher `(owner_id, role_code, epoch)` identities are unique, and publisher public keys are unique as four separate invariants. Every exact Plugin ID occurs in exactly one grant; the grant owner must have at least one publisher-key entry. Across the complete supplied PTR1 history, no root public key may appear as a publisher public key and no publisher public key may appear as a root public key.

The signature message is the exact ASCII bytes `pigloros/plugin-trust-root/v1\0` followed by the canonical definite-length 11-element CBOR array containing fields 0–10. The full-record digest, not the unsigned digest, is used by `previous root digest` and by PRV1. No root-authority private-key lifecycle is implemented in #423.

The bootstrap caller supplies `TrustedPluginRootAnchorV1(policy_scope, exact_genesis_PTR1_digest)` out of band. The first PTR1 must have the same policy scope, a null predecessor, exactly match that digest, and meet its own listed threshold. Every later PTR1 must have the same scope as the anchor and predecessor, root version exactly predecessor version plus one without overflow, and previous digest exactly the predecessor's complete-record digest.

For every later PTR1, the one canonical signature array is evaluated independently against the predecessor root-key set and threshold and against the candidate root-key set and threshold [S1]. A cryptographically valid signature from a key present in both sets may count once toward each independent threshold; a key never counts more than once within either threshold. A signer absent from the union of the two sets, duplicate signer ID, mismatched derived key ID, or invalid signature rejects the record. Genesis signatures must all name genesis root keys and meet the genesis threshold. Only the terminal root must satisfy `not_before <= evaluation_utc_second < expires`; intermediate expired roots may establish continuity [S1]. #424 authenticates the anchor source, persists the admitted terminal version/digest floor, and rejects rollback.

`PluginRevocationRecordV1/PRV1`: exact 12 fields, maximum 1 MiB:

| # | Field | Candidate rule |
|---:|---|---|
| 0 | magic | text `PRV1` |
| 1 | version | unsigned integer `1` |
| 2 | policy scope | text equal byte-for-byte to the PTR1 anchor scope |
| 3 | policy epoch | nonzero unsigned u64, strictly increasing in the PRV1 chain |
| 4–5 | not-before, expires | signed i64 UTC seconds with the same interval rule as PTR1 |
| 6 | current root digest | bstr32 naming one PTR1 in the verified root chain |
| 7 | previous revocation digest | `null` only for PRV1 genesis, otherwise bstr32 of the complete prior PRV1 |
| 8 | effective Tick | unsigned u64, nondecreasing across the PRV1 chain |
| 9 | revoked exact keys | array length 0..4096 of exact `[owner_id_text, role_code_uint=3, epoch_uint>0, public_key_bstr32, original_effective_tick_uint, reason_code_uint, replacement_or_null]`, strictly sorted by `(owner UTF-8, role, epoch, public key)` |
| 10 | revoked artifact digests | array length 0..4096 of exact `[digest_bstr32, original_effective_tick_uint, reason_code_uint, replacement_digest_or_null]`, strictly sorted by digest bytes |
| 11 | signatures | array length 1..64 of exact `[root_key_id_bstr32, signature_bstr64]`, strictly sorted by root key ID |

`replacement_or_null` is either `null` or the exact four-element array `[owner_id_text, role_code_uint=3, epoch_uint>0, public_key_bstr32]`; it is informational and never automatically trusted. `replacement_digest_or_null` is `null` or bstr32 and is also informational. Reason codes are closed unsigned integers: 1 compromised, 2 superseded, 3 policy withdrawal, 4 other. Exact-key revocations refer only to a publisher key named by a verified PTR1 in the supplied root history. Content-digest revocations refer to exact PMF1 release digests or any digest-bearing descriptor in that release, never a Plugin ID.

The PRV1 chain has one constant policy scope, exact predecessor-digest linkage, strictly increasing policy epochs, and nondecreasing effective Ticks. The root digest referenced by successive PRV1 records may stay equal or advance through the verified PTR1 sequence, but must never move to an earlier root. Each PRV1 is authorized only by the threshold and root-key set of the exact PTR1 named in its field 6; this includes the first PRV1 that advances to a new root. All signers must belong to that one root-key set, each key counts at most once, and unknown or duplicate signers reject the record. The terminal PRV1 must name the terminal PTR1.

Each revoked-key and revoked-artifact collection is cumulative set inclusion, not positional-prefix inclusion: every entry in the predecessor collection must occur byte-for-byte identically in the successor's sorted collection, even when a new sorted entry is inserted before or between old entries. A new entry is one absent from the predecessor and its `original_effective_tick` must equal the successor record's field 8. An inherited entry's Tick, reason, and replacement cannot change. A revocation applies exactly when `original_effective_tick <= evaluation_tick`; future entries remain authenticated but are not yet effective. The signature message is the exact ASCII bytes `pigloros/plugin-revocation/v1\0` followed by the canonical definite-length 11-element CBOR array containing fields 0–10. Terminal PRV1 must satisfy `not_before <= evaluation_utc_second < expires` and carry all prior revocations. It may be an empty genesis record; missing current revocation evidence fails closed.

V1 deliberately has no compaction operation. Once either cumulative collection contains 4096 entries, a successor that needs another entry is unrepresentable and new Plugin admission and activation for that policy scope fail closed. An implementation must surface `RevocationCapacityExhausted`; it must not omit, summarize, reset, or silently rebootstrap entries. Restoring admission requires a separately accepted new revocation wire version or out-of-band new-scope bootstrap contract that proves and durably commits carry-forward of every still-effective V1 denial before the new scope can admit anything. #424 cannot lower this rule with a local checkpoint.

### Stateless verification result and complete PMF1 projection

Public verifier input is bounded to 64 PTR1 and 256 PRV1 records per call, one operator-pinned anchor, one explicit signed i64 evaluation UTC second, and one explicit u64 evaluation Tick. It outputs an opaque `VerifiedPluginTrustEvidenceV1` that binds all of these exact facts: policy scope, terminal root version/digest, terminal policy epoch/revocation digest, evaluation UTC second, evaluation Tick, terminal validity intervals, and the effective key/artifact revocation sets at that Tick. “Current” in this contract means only “at those bound evaluation coordinates”; the stateless verifier makes no clock, freshness, rollback, or persistence claim about its caller.

The only release query input is `ValidatedPluginManifestProjectionV1`, constructed by #401 after complete canonical PMF1 parsing and digest validation. It contains the BLAKE3-256 digest of the complete canonical PMF1 bytes, the exact validated PMF1 field 2 Plugin ID text, publisher `OwnerIdV1`, role code 3, epoch, not-before/not-after UTC seconds, release digest, and a strictly sorted unique list of every digest-bearing descriptor reachable from PMF1 fields 9–20, including nested migration Component and fixture descriptors. #401 must prove that list complete from the PMF1 structure; callers cannot supply an arbitrary interval or partial digest list. No runtime identifier conversion participates in trust authorization.

The evidence query succeeds only when the terminal PTR1 has exactly one publisher key matching the PMF1 owner/role/epoch identity, exactly one matching exact-Plugin-ID grant to that owner, the manifest interval contains the bound evaluation UTC second, that resolved exact public key is not effectively revoked, and neither the release digest nor any complete descriptor digest is effectively revoked. It returns the resolved public key and a trust-authorization fact bound to the evidence and complete-PMF1-byte digests. #401 then verifies the PMF1 role-bound signature with that returned key. The query does **not** itself verify the PMF1 publisher signature, claim signature issuance authorization, authenticate TPS1, persist high-water state, admit a release, or activate a Plugin. Those remain #401/#424. Safe errors distinguish encoding, bound, digest, signature, threshold, anchor, chain continuity, expiry, Plugin ID grant, unknown key, revocation, capacity exhaustion, and incomplete manifest projection without leaking private material.

### Exact #424 TPS1 and trusted-coordinate bridge

#424 authenticates TPS1's operator signature and predecessor/epoch continuity before using any field. A structurally parsed TPS1 never supplies its own anchor, trusted time, or trusted Tick. For Plugin admission, the authenticated TPS1 `policy_id` must equal the evidence policy scope byte-for-byte and its `epoch` must equal the terminal PRV1 policy epoch. #424 separately stores the operator-pinned PTR1 genesis digest and the admitted terminal PTR1/PRV1 floors; TPS1 root entries do not replace that digest anchor.

For every terminal PTR1 root key, authenticated TPS1 must contain exactly one Plugin root entry whose `key_id` is the ASCII text `ptr1:` followed by lowercase hexadecimal of the 32-byte `root_key_id`, whose `root_version` equals the terminal PTR1 root version, whose algorithm is exactly `Ed25519`, and whose public key equals the PTR1 public key. The set of `ptr1:` entries must equal the terminal PTR1 root-key set; other non-Plugin TPS1 roots may coexist.

The canonical TPS1 string ID for an effective Plugin publisher-key revocation is `pkr1:` followed by lowercase hexadecimal of `BLAKE3("pigloros/plugin-revoked-key-id/v1\0" || canonical_cbor([owner_id_text, 3, epoch_uint, public_key_bstr32]))`. Its length is 69 ASCII bytes and fits the TPS1 V1 identifier bound. At Plugin admission, the set of TPS1 `revoked_key_ids` beginning `pkr1:` must equal the derived IDs of the terminal PRV1 key entries effective at the bound evaluation Tick. TPS1 `revoked_artifact_digests` must contain every terminal PRV1 artifact entry effective at that Tick; it may also contain revocations for other artifact classes, all of which #424 continues to enforce. This is the exact authenticated mapping; raw owner IDs are never packed into the bounded TPS1 string.

TPS1 `offline_valid_through` is accepted by #424 only as exact 20-byte ASCII `YYYY-MM-DDTHH:MM:SSZ`, with a real Gregorian UTC date/time, seconds 00–59, no leap second, fraction, or offset, converted without overflow to a signed UTC second. Plugin admission requires `evaluation_utc_second < offline_valid_through` as well as the PTR1, PRV1, and PMF1 interval checks. The trusted UTC second comes from #424's operator-approved trusted-time source and is fixed for one admission transaction.

TPS1 `effective_timeline_position` and PRV1/evidence Tick are independent coordinates and are never converted or compared as though one were the other. #424 authenticates and durably orders TPS1 by its Timeline-position contract, obtains the host Tick from the Tick Boundary that owns admission/activation, passes that exact Tick to #423, and binds both coordinates in its transaction record. At a Tick Boundary, #424 atomically persists the authenticated TPS1 digest/epoch, evidence terminal digests/floors, evaluation UTC/Tick, release-chain decision, activation state, and activation Event or commits none of them. Same-release idempotency and explicit rollback remain #424 rules and never lower policy/root floors or bypass effective revocation.

Public tests after accepted ADR: golden canonical bytes and every field/type/ordering mutation; wrong role/owner/epoch/key/Plugin ID; duplicate key IDs/public keys/signers; policy-scope mismatch; old-only/new-only/overlapping signer threshold counting; root rotation and PRV1 root transition; bad previous digest/version gap/root regression; expired terminal root/PRV1; replayed or non-cumulative revocation set including sorted interleaving; Tick before/equal/after the effective edge; artifact and nested-descriptor revocation; incomplete PMF1 projection; TPS1 root/key/artifact/scope/epoch/time mismatch; revocation capacity exhaustion; and unpinned genesis. Run Cargo and coverage only in hosted GitHub Actions from the #423 PR per user instruction.

## Remaining question for fresh independent review

The seven journal-10304 blockers remain resolved, and journal 10334's PMF1 compatibility blocker is addressed by preserving the accepted lowercase ASCII Plugin-ID grammar and using byte-identical text in exact PTR1 grants. A fresh reviewer should verify that compatibility correction and decide whether V1's explicit fail-closed 4096-entry lifetime ceiling is an acceptable bounded first contract, or whether the first accepted version must instead include a separately designed authenticated compaction record. No compaction is implied by this candidate, and #424 cannot invent one locally.

## Sources (primary, accessed 2026-09-27)

- [S1] The Update Framework Specification 1.0.36, TUF project, modified 2026-08-05, https://theupdateframework.github.io/specification/latest/ . Root update §5.3 and key migration §6.1 specify threshold continuity, one count per key, sequential root versions, expiry, and out-of-band bootstrap/recovery.
- [S2] RFC 8949, CBOR, IETF, December 2020, https://www.rfc-editor.org/rfc/rfc8949.html . §4.2 permits a protocol-specific deterministic CBOR profile with strict accepted encoding.
- [S3] RFC 8032, EdDSA, IRTF CFRG, January 2017, https://www.rfc-editor.org/rfc/rfc8032.html . Defines pure Ed25519 signatures on exact messages, 32-byte public keys, and 64-byte signatures.
- [S4] RFC 9052, COSE Structures and Process, IETF, August 2022, https://www.rfc-editor.org/rfc/rfc9052.html . §4.4 defines Sig_structure and requires applications to check signer identity/authorization separately.
