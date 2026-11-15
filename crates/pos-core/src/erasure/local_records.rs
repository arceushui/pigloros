//! Canonical records of the single-host erasure authority (ADR-136 §4).
//!
//! Every record is a deterministic-CBOR definite array `[tag, 1, …]` whose
//! content address is the ADR-060 V1 domain-separated BLAKE3 digest under its
//! tag. A decoder accepts only the exact canonical bytes its encoder writes:
//! maps, floats, indefinite items, unknown, missing or trailing fields, and
//! values outside the record's rules are refused.

use ciborium::value::Value;

use super::{
    array, bytes32, decode_limited, digest, domain_digest, encode_limited, evidence::string,
    header, strictly_increasing, text, uint, unsigned, ArtifactDataClassV1, ErasureArtifactClassV1,
    ErasureErrorV1, ErasureInventoryCategoryV1, ErasureReferenceV1,
    ERASURE_MAX_OBLIGATIONS_PER_CATEGORY,
};
use crate::ids::{EntityId, TimelineId};

/// The prefix of the TPS1 root key id that may sign an ELB1 bundle.
pub const ERASURE_BUNDLE_ROOT_PREFIX_V1: &str = "erasure-bundle/";

/// The prefix of the TPS1 key id of an ELB1 signer key.
pub const ERASURE_SIGNER_KEY_PREFIX_V1: &str = "erasure-signer/";

/// The ELP1 attempt window: two protocol positions plus 16,384 obligations.
pub const LOCAL_ERASURE_ATTEMPT_WINDOW_V1: u64 = 2 + 16_384;

/// The largest ELP1 lifetime attempt quota (ADR-136 §4).
pub const LOCAL_ERASURE_MAX_QUOTA_ATTEMPTS_V1: u64 = 4_096;

/// The largest ELP1 store-wide request reserve: the store's request-head cap.
pub const LOCAL_ERASURE_MAX_REQUEST_RESERVE_V1: u64 = super::ERASURE_MAX_INVENTORY_REQUESTS as u64;

const KIB: usize = 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_EXECUTOR_ID_BYTES: usize = 64;
const MAX_OPERATION_BYTES: usize = 64;
const MAX_ACK_CLASS_BYTES: usize = 48;
const MAX_BUNDLE_LIST: usize = 64;
const MAX_CLASSIFICATION_ROWS: usize = 256;
const MAX_AUTO_RETRY: u64 = 16;
const SIGNER_ROLE: u64 = 2;

/// The fields of one fixed-shape array, length-checked once.
fn fixed_array<const N: usize>(value: &Value) -> Result<&[Value; N], ErasureErrorV1> {
    match value {
        Value::Array(items) => items
            .as_slice()
            .try_into()
            .ok()
            .ok_or(ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

/// The fields of one record `[tag, 1, …]` of exactly `N` elements.
fn open<'a, const N: usize>(value: &'a Value, tag: &str) -> Result<&'a [Value; N], ErasureErrorV1> {
    fixed_array::<N>(value).and_then(|fields| header(fields, tag).map(|()| fields))
}

fn list(value: &Value) -> Result<&[Value], ErasureErrorV1> {
    array(value, usize::MAX)
}

fn owned_text(value: &Value) -> Result<String, ErasureErrorV1> {
    string(value).map(str::to_owned)
}

fn owned_bytes(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], ErasureErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .ok()
            .ok_or(ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

const fn truth(value: &Value) -> Result<bool, ErasureErrorV1> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

fn timeline_id(value: &Value) -> Result<TimelineId, ErasureErrorV1> {
    fixed(value).map(|bytes| TimelineId::from_ulid(ulid::Ulid::from_bytes(bytes)))
}

fn bytes_value(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}

fn record(tag: &str, fields: Vec<Value>) -> Value {
    let mut items = vec![text(tag), uint(1)];
    items.extend(fields);
    Value::Array(items)
}

/// Accept a rule only when it holds.
const fn require(rule: bool) -> Result<(), ErasureErrorV1> {
    if rule {
        Ok(())
    } else {
        Err(ErasureErrorV1::ScopeInvalid)
    }
}

/// An ADR-136 acknowledgement class: `^[a-z][a-z0-9-]{0,47}$`.
fn is_ack_class(class: &str) -> bool {
    let bytes = class.as_bytes();
    (1..=MAX_ACK_CLASS_BYTES).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// A TPS1 key id: lowercase letters, digits and `. _ / -`, starting with a
/// letter or digit, at most 128 bytes.
fn is_tps1_key_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=MAX_IDENTIFIER_BYTES).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}

/// One canonical record codec.
trait LocalRecordV1: Sized {
    const TAG: &'static str;
    const MAX_BYTES: usize;

    fn fields(&self) -> Vec<Value>;
    fn read(record: &Value) -> Result<Self, ErasureErrorV1>;

    /// The record's own value rules, checked on both encode and decode.
    fn validate(&self) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

fn encode_record<R: LocalRecordV1>(record_value: &R) -> Result<Vec<u8>, ErasureErrorV1> {
    record_value
        .validate()
        .and_then(|()| encode_limited(&record(R::TAG, record_value.fields()), R::MAX_BYTES))
}

fn decode_record<R: LocalRecordV1>(bytes: &[u8]) -> Result<R, ErasureErrorV1> {
    decode_limited(bytes, R::MAX_BYTES, ERASURE_MAX_OBLIGATIONS_PER_CATEGORY).and_then(|value| {
        R::read(&value).and_then(|decoded| {
            // Only the exact canonical bytes the encoder writes decode, and the
            // encoder applies every record rule.
            encode_record(&decoded).and_then(|canonical| {
                if canonical == bytes {
                    Ok(decoded)
                } else {
                    Err(ErasureErrorV1::InvalidEncoding)
                }
            })
        })
    })
}

fn record_reference<R: LocalRecordV1>(
    record_value: &R,
) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    encode_record(record_value)
        .map(|bytes| ErasureReferenceV1::from_digest(domain_digest(R::TAG, &bytes)))
}

macro_rules! local_record_api {
    ($record:ty) => {
        impl $record {
            /// Encode the canonical record.
            ///
            /// # Errors
            /// Returns a closed error when a field breaks the record's rules or
            /// the record is over its size bound.
            pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
                encode_record(self)
            }

            /// Decode exactly one canonical record.
            ///
            /// # Errors
            /// Returns a closed error for any malformed, non-canonical or
            /// out-of-rule record.
            pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
                decode_record(bytes)
            }

            /// The record's content address, `CA(record)`.
            ///
            /// # Errors
            /// Returns the encoding error of [`Self::to_canonical_cbor`].
            pub fn reference(&self) -> Result<ErasureReferenceV1, ErasureErrorV1> {
                record_reference(self)
            }
        }
    };
}

/// A `KeyIdentityV1` of the role-2 erasure signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureSignerIdentityV1 {
    /// The key-registry owner id, 1 to 128 bytes.
    pub owner_id: Vec<u8>,
    /// The key epoch, at least 1.
    pub epoch: u64,
}

impl LocalErasureSignerIdentityV1 {
    fn value(&self) -> Value {
        Value::Array(vec![
            bytes_value(&self.owner_id),
            uint(SIGNER_ROLE),
            uint(self.epoch),
        ])
    }

    fn read(value: &Value) -> Result<Self, ErasureErrorV1> {
        fixed_array::<3>(value).and_then(|[owner_id, role, epoch]| {
            let owner_id = owned_bytes(owner_id)?;
            let role = unsigned(role)?;
            let epoch = unsigned(epoch)?;
            require(role == SIGNER_ROLE).map(|()| Self { owner_id, epoch })
        })
    }

    fn is_valid(&self) -> bool {
        (1..=MAX_IDENTIFIER_BYTES).contains(&self.owner_id.len()) && self.epoch >= 1
    }
}

/// The TPS1 key id of an ELB1 signer key: `erasure-signer/` plus 64 lowercase
/// hex characters of its Ed25519 public key.
#[must_use]
pub fn local_erasure_signer_key_id_v1(public_key: &[u8; 32]) -> String {
    let mut id = String::with_capacity(ERASURE_SIGNER_KEY_PREFIX_V1.len() + 64);
    id.push_str(ERASURE_SIGNER_KEY_PREFIX_V1);
    crate::lower_hex::append_hex(&mut id, public_key);
    id
}

/// `CA("ELOWN1", [store_identity, category, ack_class])`, the owner of one
/// acknowledgement class on one store.
///
/// # Errors
/// Returns the canonical encoding error.
pub fn local_erasure_owner_ref_v1(
    store_identity: ErasureReferenceV1,
    category: u64,
    ack_class: &str,
) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    encode_limited(
        &Value::Array(vec![
            digest(store_identity),
            uint(category),
            text(ack_class),
        ]),
        KIB,
    )
    .map(|bytes| ErasureReferenceV1::from_digest(domain_digest("ELOWN1", &bytes)))
}

/// `CA("ELCOORD1", [store_identity])`, the coordinator identity of the
/// Local erasure composition of one store.
///
/// It depends only on the write-once store identity, so it stays stable
/// across bundle rotation, as ERS1 coordinator continuity requires.
///
/// # Errors
/// Returns the canonical encoding error.
pub fn local_erasure_coordinator_v1(
    store_identity: ErasureReferenceV1,
) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    encode_limited(&Value::Array(vec![digest(store_identity)]), KIB)
        .map(|bytes| ErasureReferenceV1::from_digest(domain_digest("ELCOORD1", &bytes)))
}

/// One ELB1 owner row: an acknowledgement class served by one owner.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalErasureOwnerRowV1 {
    /// The ADR-060 inventory category code.
    pub category: u64,
    /// The acknowledgement class.
    pub ack_class: String,
    /// [`local_erasure_owner_ref_v1`] of the bundle's store, category and class.
    pub owner_ref: ErasureReferenceV1,
}

/// The deployment-owned executor an ELB1 bundle permits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureExecutionBindingV1 {
    /// The executor identifier, 1 to 64 bytes.
    pub executor_id: String,
    /// The digest of the executor version.
    pub executor_version_digest: ErasureReferenceV1,
}

/// ELB1, the Local erasure authority bundle (ADR-136 §4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureBundleV1 {
    /// The digest of the TPS1 snapshot that admitted the bundle root at
    /// issuance. It is an issuance record, not compared with the installed
    /// TPS1, so a routine TPS1 refresh does not force re-signing the bundle.
    pub tps1: ErasureReferenceV1,
    /// The write-once erasure store identity.
    pub store_identity: ErasureReferenceV1,
    /// The Local Principal authority registry digest.
    pub authority_registry_digest: ErasureReferenceV1,
    /// Host-owned Timelines, strictly increasing, at most 64.
    pub host_timelines: Vec<TimelineId>,
    /// `CA(ELP1)`.
    pub policy: ErasureReferenceV1,
    /// Owner rows, strictly increasing, at most 64, each owner reference
    /// derived from this bundle's store identity.
    pub owners: Vec<LocalErasureOwnerRowV1>,
    /// The permitted executor.
    pub execution_binding: LocalErasureExecutionBindingV1,
    /// The role-2 signer identity.
    pub signer_identity: LocalErasureSignerIdentityV1,
    /// The signer's Ed25519 public key.
    pub signer_public_key: [u8; 32],
    /// `erasure-signer/` plus the hex public key.
    pub signer_key_id: String,
    /// The TPS1 root key id, with the `erasure-bundle/` prefix.
    pub issued_by: String,
    /// The expiry; 0 means valid until TPS1 revokes it. Like TPS1 expiry it
    /// closes new admissions only and never decides an outcome, so it is
    /// enforced at admission (the `LocalErasureAuthorityV1` slice), not at
    /// composition.
    pub expiry: u64,
}

impl LocalErasureBundleV1 {
    fn owner_is_valid(&self, owner: &LocalErasureOwnerRowV1) -> bool {
        ErasureInventoryCategoryV1::from_code(owner.category).is_ok()
            && is_ack_class(&owner.ack_class)
            && local_erasure_owner_ref_v1(self.store_identity, owner.category, &owner.ack_class)
                == Ok(owner.owner_ref)
    }
}

impl LocalRecordV1 for LocalErasureBundleV1 {
    const TAG: &'static str = "ELB1";
    const MAX_BYTES: usize = 64 * KIB;

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.tps1),
            digest(self.store_identity),
            digest(self.authority_registry_digest),
            Value::Array(
                self.host_timelines
                    .iter()
                    .map(|timeline| bytes_value(&timeline.inner().to_bytes()))
                    .collect(),
            ),
            digest(self.policy),
            Value::Array(
                self.owners
                    .iter()
                    .map(|owner| {
                        Value::Array(vec![
                            uint(owner.category),
                            text(&owner.ack_class),
                            digest(owner.owner_ref),
                        ])
                    })
                    .collect(),
            ),
            Value::Array(vec![
                text(&self.execution_binding.executor_id),
                digest(self.execution_binding.executor_version_digest),
            ]),
            self.signer_identity.value(),
            bytes_value(&self.signer_public_key),
            text(&self.signer_key_id),
            text(&self.issued_by),
            uint(self.expiry),
        ]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, tps1, store_identity, registry, host_timelines, policy, owners, binding, signer_identity, signer_public_key, signer_key_id, issued_by, expiry] =
            open::<14>(record, Self::TAG)?;
        let [executor_id, executor_version_digest] = fixed_array::<2>(binding)?;
        Ok(Self {
            tps1: bytes32(tps1)?,
            store_identity: bytes32(store_identity)?,
            authority_registry_digest: bytes32(registry)?,
            host_timelines: list(host_timelines)?
                .iter()
                .map(timeline_id)
                .collect::<Result<Vec<_>, _>>()?,
            policy: bytes32(policy)?,
            owners: list(owners)?
                .iter()
                .map(|value| {
                    fixed_array::<3>(value).and_then(|[category, ack_class, owner_ref]| {
                        Ok(LocalErasureOwnerRowV1 {
                            category: unsigned(category)?,
                            ack_class: owned_text(ack_class)?,
                            owner_ref: bytes32(owner_ref)?,
                        })
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            execution_binding: LocalErasureExecutionBindingV1 {
                executor_id: owned_text(executor_id)?,
                executor_version_digest: bytes32(executor_version_digest)?,
            },
            signer_identity: LocalErasureSignerIdentityV1::read(signer_identity)?,
            signer_public_key: fixed(signer_public_key)?,
            signer_key_id: owned_text(signer_key_id)?,
            issued_by: owned_text(issued_by)?,
            expiry: unsigned(expiry)?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(
            self.host_timelines.len() <= MAX_BUNDLE_LIST
                && strictly_increasing(&self.host_timelines)
                && self.owners.len() <= MAX_BUNDLE_LIST
                && strictly_increasing(&self.owners)
                && self.owners.iter().all(|owner| self.owner_is_valid(owner))
                && (1..=MAX_EXECUTOR_ID_BYTES).contains(&self.execution_binding.executor_id.len())
                && self.signer_identity.is_valid()
                && self.signer_key_id == local_erasure_signer_key_id_v1(&self.signer_public_key)
                && is_tps1_key_id(&self.issued_by)
                && self.issued_by.len() > ERASURE_BUNDLE_ROOT_PREFIX_V1.len()
                && self.issued_by.starts_with(ERASURE_BUNDLE_ROOT_PREFIX_V1),
        )
    }
}

local_record_api!(LocalErasureBundleV1);

/// ELB1S, the administrator signature over `CA(ELB1)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureBundleSignatureV1 {
    /// `CA(ELB1)`.
    pub bundle: ErasureReferenceV1,
    /// Ed25519 over `["ELB1-SIG", 1, CA(ELB1)]`.
    pub admin_signature: [u8; 64],
}

impl LocalRecordV1 for LocalErasureBundleSignatureV1 {
    const TAG: &'static str = "ELB1S";
    const MAX_BYTES: usize = KIB;

    fn fields(&self) -> Vec<Value> {
        vec![digest(self.bundle), bytes_value(&self.admin_signature)]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, bundle, admin_signature] = open::<4>(record, Self::TAG)?;
        Ok(Self {
            bundle: bytes32(bundle)?,
            admin_signature: fixed(admin_signature)?,
        })
    }
}

local_record_api!(LocalErasureBundleSignatureV1);

/// The exact message an `erasure-bundle/` root signs for one ELB1.
///
/// # Errors
/// Returns the canonical encoding error.
pub fn local_erasure_bundle_signing_message_v1(
    bundle: ErasureReferenceV1,
) -> Result<Vec<u8>, ErasureErrorV1> {
    encode_limited(
        &Value::Array(vec![text("ELB1-SIG"), uint(1), digest(bundle)]),
        KIB,
    )
}

/// ELREJ1, the provenance of an authorize-stage rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalErasureRejectionV1 {
    /// The ERQ1 request.
    pub request: ErasureReferenceV1,
    /// `Unauthorized`, `ScopeInvalid` or `PolicyConflict`.
    pub error: ErasureErrorV1,
}

impl LocalRecordV1 for LocalErasureRejectionV1 {
    const TAG: &'static str = "ELREJ1";
    const MAX_BYTES: usize = KIB;

    fn fields(&self) -> Vec<Value> {
        vec![digest(self.request), uint(self.error.code())]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, request, error] = open::<4>(record, Self::TAG)?;
        Ok(Self {
            request: bytes32(request)?,
            error: ErasureErrorV1::from_code(unsigned(error)?)?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(matches!(
            self.error,
            ErasureErrorV1::Unauthorized
                | ErasureErrorV1::ScopeInvalid
                | ErasureErrorV1::PolicyConflict
        ))
    }
}

local_record_api!(LocalErasureRejectionV1);

/// ELTA1, the TPS1 operator-key lookup hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureTrustAnchorV1 {
    /// The digest of the TPS1 snapshot.
    pub tps1: ErasureReferenceV1,
    /// The operator key id, a TPS1 key id.
    pub operator_key_id: String,
    /// The operator's Ed25519 public key.
    pub operator_public_key: [u8; 32],
}

impl LocalRecordV1 for LocalErasureTrustAnchorV1 {
    const TAG: &'static str = "ELTA1";
    const MAX_BYTES: usize = KIB;

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.tps1),
            text(&self.operator_key_id),
            bytes_value(&self.operator_public_key),
        ]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, tps1, operator_key_id, operator_public_key] = open::<5>(record, Self::TAG)?;
        Ok(Self {
            tps1: bytes32(tps1)?,
            operator_key_id: owned_text(operator_key_id)?,
            operator_public_key: fixed(operator_public_key)?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(is_tps1_key_id(&self.operator_key_id))
    }
}

local_record_api!(LocalErasureTrustAnchorV1);

/// One ELP1 classification row.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalErasureClassificationV1 {
    /// The ADR-060 artifact class code.
    pub artifact_class: u64,
    /// The ADR-060 data class.
    pub data_class: ArtifactDataClassV1,
    /// The ADR-060 inventory category code.
    pub category: u64,
    /// The acknowledgement class.
    pub ack_class: String,
}

/// ELP1, the pinned Local erasure policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasurePolicyV1 {
    /// Always-retained data classes, strictly increasing.
    pub retained_classes: Vec<ArtifactDataClassV1>,
    /// Classification rows, strictly increasing, at most 256.
    pub classification: Vec<LocalErasureClassificationV1>,
    /// Automatic retries of a transient result, at most 16.
    pub auto_retry_max: u64,
    /// Lifetime attempt quota, at most [`LOCAL_ERASURE_MAX_QUOTA_ATTEMPTS_V1`].
    pub quota_attempts: u64,
    /// Request heads reserved store-wide, at most
    /// [`LOCAL_ERASURE_MAX_REQUEST_RESERVE_V1`].
    pub store_request_reserve: u64,
    /// Re-prepares per lifecycle step.
    pub max_reprepare: u64,
}

fn data_class(value: &Value) -> Result<ArtifactDataClassV1, ErasureErrorV1> {
    unsigned(value).and_then(ArtifactDataClassV1::from_code)
}

impl LocalRecordV1 for LocalErasurePolicyV1 {
    const TAG: &'static str = "ELP1";
    const MAX_BYTES: usize = 64 * KIB;

    fn fields(&self) -> Vec<Value> {
        vec![
            Value::Array(
                self.retained_classes
                    .iter()
                    .map(|class| uint(u64::from(*class)))
                    .collect(),
            ),
            Value::Array(
                self.classification
                    .iter()
                    .map(|row| {
                        Value::Array(vec![
                            uint(row.artifact_class),
                            uint(u64::from(row.data_class)),
                            uint(row.category),
                            text(&row.ack_class),
                        ])
                    })
                    .collect(),
            ),
            uint(LOCAL_ERASURE_ATTEMPT_WINDOW_V1),
            uint(self.auto_retry_max),
            uint(self.quota_attempts),
            uint(self.store_request_reserve),
            uint(self.max_reprepare),
        ]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, retained, classification, window, auto_retry_max, quota_attempts, store_request_reserve, max_reprepare] =
            open::<9>(record, Self::TAG)?;
        require(unsigned(window)? == LOCAL_ERASURE_ATTEMPT_WINDOW_V1)?;
        Ok(Self {
            retained_classes: list(retained)?
                .iter()
                .map(data_class)
                .collect::<Result<Vec<_>, _>>()?,
            classification: list(classification)?
                .iter()
                .map(|value| {
                    fixed_array::<4>(value).and_then(
                        |[artifact_class, row_data_class, category, ack_class]| {
                            Ok(LocalErasureClassificationV1 {
                                artifact_class: unsigned(artifact_class)?,
                                data_class: data_class(row_data_class)?,
                                category: unsigned(category)?,
                                ack_class: owned_text(ack_class)?,
                            })
                        },
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            auto_retry_max: unsigned(auto_retry_max)?,
            quota_attempts: unsigned(quota_attempts)?,
            store_request_reserve: unsigned(store_request_reserve)?,
            max_reprepare: unsigned(max_reprepare)?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(
            strictly_increasing(&self.retained_classes)
                && self
                    .retained_classes
                    .iter()
                    .all(|class| class.is_always_retained())
                && self.classification.len() <= MAX_CLASSIFICATION_ROWS
                && strictly_increasing(&self.classification)
                && self.classification.iter().all(|row| {
                    ErasureArtifactClassV1::from_code(row.artifact_class).is_ok()
                        && ErasureInventoryCategoryV1::from_code(row.category).is_ok()
                        && is_ack_class(&row.ack_class)
                })
                && self.auto_retry_max <= MAX_AUTO_RETRY
                && self.quota_attempts <= LOCAL_ERASURE_MAX_QUOTA_ATTEMPTS_V1
                && self.store_request_reserve <= LOCAL_ERASURE_MAX_REQUEST_RESERVE_V1,
        )
    }
}

local_record_api!(LocalErasurePolicyV1);

/// ERAZ1, the recomputable authorization of one erasure request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureAuthorizationV1 {
    /// The Local Principal reference.
    pub principal_ref: ErasureReferenceV1,
    /// The acting entity.
    pub actor_entity: EntityId,
    /// The Gateway operation name, 1 to 64 bytes.
    pub operation: String,
    /// The Local Principal authority registry digest.
    pub authority_registry_digest: ErasureReferenceV1,
    /// The root-grant authority chain.
    pub authority_chain: TimelineId,
    /// The bound root-chain head position.
    pub chain_head_position: u64,
    /// The bound revocation epoch.
    pub revocation_epoch: u64,
    /// The ERQ1 request.
    pub erq1_request: ErasureReferenceV1,
}

impl LocalRecordV1 for LocalErasureAuthorizationV1 {
    const TAG: &'static str = "ERAZ1";
    const MAX_BYTES: usize = 4 * KIB;

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.principal_ref),
            bytes_value(&self.actor_entity.inner().to_bytes()),
            text(&self.operation),
            digest(self.authority_registry_digest),
            bytes_value(&self.authority_chain.inner().to_bytes()),
            uint(self.chain_head_position),
            uint(self.revocation_epoch),
            digest(self.erq1_request),
        ]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, principal_ref, actor_entity, operation, registry, authority_chain, chain_head_position, revocation_epoch, erq1_request] =
            open::<10>(record, Self::TAG)?;
        Ok(Self {
            principal_ref: bytes32(principal_ref)?,
            actor_entity: EntityId::from_ulid(ulid::Ulid::from_bytes(fixed(actor_entity)?)),
            operation: owned_text(operation)?,
            authority_registry_digest: bytes32(registry)?,
            authority_chain: timeline_id(authority_chain)?,
            chain_head_position: unsigned(chain_head_position)?,
            revocation_epoch: unsigned(revocation_epoch)?,
            erq1_request: bytes32(erq1_request)?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require((1..=MAX_OPERATION_BYTES).contains(&self.operation.len()))
    }
}

local_record_api!(LocalErasureAuthorizationV1);

/// ELSEL1, the ERQ1 selector: owner-match resolution with existing
/// descendants and future Forks, always requested explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalErasureSelectorV1 {
    /// `CA("ERSUB1", [principal_ref, actor_entity])`.
    pub subject: ErasureReferenceV1,
}

impl LocalRecordV1 for LocalErasureSelectorV1 {
    const TAG: &'static str = "ELSEL1";
    const MAX_BYTES: usize = KIB;

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.subject),
            uint(0),
            Value::Bool(true),
            Value::Bool(true),
        ]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, subject, rule, descendants, future_forks] = open::<6>(record, Self::TAG)?;
        let subject = bytes32(subject)?;
        require(unsigned(rule)? == 0 && truth(descendants)? && truth(future_forks)?)
            .map(|()| Self { subject })
    }
}

local_record_api!(LocalErasureSelectorV1);

/// ELIDEM1, the ERQ1 provenance binding one idempotency key and body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalErasureIdempotencyV1 {
    /// The Idempotency-Key digest.
    pub idempotency_key_digest: ErasureReferenceV1,
    /// `CA("ELBODY1", [scope class code])`.
    pub body_digest: ErasureReferenceV1,
}

impl LocalRecordV1 for LocalErasureIdempotencyV1 {
    const TAG: &'static str = "ELIDEM1";
    const MAX_BYTES: usize = KIB;

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.idempotency_key_digest),
            digest(self.body_digest),
        ]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, idempotency_key_digest, body_digest] = open::<4>(record, Self::TAG)?;
        Ok(Self {
            idempotency_key_digest: bytes32(idempotency_key_digest)?,
            body_digest: bytes32(body_digest)?,
        })
    }
}

local_record_api!(LocalErasureIdempotencyV1);

/// ELO1, one owner result bound to its durable effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalErasureOwnerResultV1 {
    /// The ERQ1 request.
    pub request: ErasureReferenceV1,
    /// The attempt.
    pub attempt: ErasureReferenceV1,
    /// The obligation.
    pub obligation: ErasureReferenceV1,
    /// The destruction command.
    pub command: ErasureReferenceV1,
    /// The owner reference.
    pub owner_ref: ErasureReferenceV1,
    /// `None` for a positive result, else the negative result's closed code.
    pub error: Option<ErasureErrorV1>,
    /// The digest of the committed owner effect.
    pub effect_digest: ErasureReferenceV1,
}

fn owner_result_error(
    outcome: &Value,
    error: &Value,
) -> Result<Option<ErasureErrorV1>, ErasureErrorV1> {
    match (unsigned(outcome)?, error) {
        (0, Value::Null) => Ok(None),
        (1, code) => unsigned(code).and_then(ErasureErrorV1::from_code).map(Some),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

impl LocalRecordV1 for LocalErasureOwnerResultV1 {
    const TAG: &'static str = "ELO1";
    const MAX_BYTES: usize = 4 * KIB;

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.request),
            digest(self.attempt),
            digest(self.obligation),
            digest(self.command),
            digest(self.owner_ref),
            uint(u64::from(self.error.is_some())),
            self.error.map_or(Value::Null, |error| uint(error.code())),
            digest(self.effect_digest),
        ]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, request, attempt, obligation, command, owner_ref, outcome, error, effect_digest] =
            open::<10>(record, Self::TAG)?;
        Ok(Self {
            request: bytes32(request)?,
            attempt: bytes32(attempt)?,
            obligation: bytes32(obligation)?,
            command: bytes32(command)?,
            owner_ref: bytes32(owner_ref)?,
            error: owner_result_error(outcome, error)?,
            effect_digest: bytes32(effect_digest)?,
        })
    }
}

local_record_api!(LocalErasureOwnerResultV1);

/// What an ELS1 signature attests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureSignaturePurposeV1 {
    /// The ERFA1-AUTH freeze authorization body.
    FreezeAuthorization,
    /// One ELO1 owner result.
    OwnerResult,
    /// One ERCB1 receipt body.
    ReceiptBody,
}

impl From<LocalErasureSignaturePurposeV1> for u64 {
    fn from(purpose: LocalErasureSignaturePurposeV1) -> Self {
        match purpose {
            LocalErasureSignaturePurposeV1::FreezeAuthorization => 0,
            LocalErasureSignaturePurposeV1::OwnerResult => 1,
            LocalErasureSignaturePurposeV1::ReceiptBody => 2,
        }
    }
}

impl LocalErasureSignaturePurposeV1 {
    /// Decode one ELS1 purpose code.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::InvalidEncoding`] for an unknown code.
    pub const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::FreezeAuthorization),
            1 => Ok(Self::OwnerResult),
            2 => Ok(Self::ReceiptBody),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// ELS1, one role-2 signature over a re-derived digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureSignatureV1 {
    /// What the signature attests.
    pub purpose: LocalErasureSignaturePurposeV1,
    /// The signed digest.
    pub signed_digest: ErasureReferenceV1,
    /// The signer.
    pub signer_identity: LocalErasureSignerIdentityV1,
    /// Ed25519 over [`local_erasure_signature_message_v1`].
    pub signature: [u8; 64],
}

impl LocalRecordV1 for LocalErasureSignatureV1 {
    const TAG: &'static str = "ELS1";
    const MAX_BYTES: usize = KIB;

    fn fields(&self) -> Vec<Value> {
        vec![
            uint(u64::from(self.purpose)),
            digest(self.signed_digest),
            self.signer_identity.value(),
            bytes_value(&self.signature),
        ]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, purpose, signed_digest, signer_identity, signature] =
            open::<6>(record, Self::TAG)?;
        Ok(Self {
            purpose: unsigned(purpose).and_then(LocalErasureSignaturePurposeV1::from_code)?,
            signed_digest: bytes32(signed_digest)?,
            signer_identity: LocalErasureSignerIdentityV1::read(signer_identity)?,
            signature: fixed(signature)?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(self.signer_identity.is_valid())
    }
}

local_record_api!(LocalErasureSignatureV1);

/// The exact role-framed message an ELS1 signer signs:
/// `["ELS1-SIG", 1, purpose, signed_digest]`.
///
/// # Errors
/// Returns the canonical encoding error.
pub fn local_erasure_signature_message_v1(
    purpose: LocalErasureSignaturePurposeV1,
    signed_digest: ErasureReferenceV1,
) -> Result<Vec<u8>, ErasureErrorV1> {
    encode_limited(
        &Value::Array(vec![
            text("ELS1-SIG"),
            uint(1),
            uint(u64::from(purpose)),
            digest(signed_digest),
        ]),
        KIB,
    )
}

/// ELD1, an ERC1 retained disclosure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureDisclosureV1 {
    /// The disclosed acknowledgement class.
    pub ack_class: String,
    /// `CA(ELP1)`.
    pub policy: ErasureReferenceV1,
}

impl LocalRecordV1 for LocalErasureDisclosureV1 {
    const TAG: &'static str = "ELD1";
    const MAX_BYTES: usize = KIB;

    fn fields(&self) -> Vec<Value> {
        vec![text(&self.ack_class), digest(self.policy)]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, ack_class, policy] = open::<4>(record, Self::TAG)?;
        Ok(Self {
            ack_class: owned_text(ack_class)?,
            policy: bytes32(policy)?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(is_ack_class(&self.ack_class))
    }
}

local_record_api!(LocalErasureDisclosureV1);

/// ELLR1, the ERSC1 lineage rule: every Fork whose `fork_point` ancestry
/// reaches an ERSC1 Timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalErasureLineageRuleV1 {
    /// The erasure subject.
    pub subject: ErasureReferenceV1,
}

impl LocalRecordV1 for LocalErasureLineageRuleV1 {
    const TAG: &'static str = "ELLR1";
    const MAX_BYTES: usize = KIB;

    fn fields(&self) -> Vec<Value> {
        vec![digest(self.subject), uint(0)]
    }

    fn read(record: &Value) -> Result<Self, ErasureErrorV1> {
        let [_, _, subject, rule] = open::<4>(record, Self::TAG)?;
        let subject = bytes32(subject)?;
        require(unsigned(rule)? == 0).map(|()| Self { subject })
    }
}

local_record_api!(LocalErasureLineageRuleV1);

/// ERCB1, the purpose-2 signing preimage of one receipt.
///
/// It is `["ERCB1", 1, erc1_body]`, where `erc1_body` is the canonical ERC1
/// array without its `receipt_digest` and `signature` elements, every other
/// element kept in ERC1 order. It is acyclic: the ELS1 over it is what
/// ERC1's signature names.
///
/// The input receipt's `signature` and `receipt_digest` are ignored, so a
/// signer can pass placeholders for both before the ELS1 exists.
///
/// # Errors
/// Returns the canonical encoding error.
pub fn local_erasure_receipt_body_v1(
    receipt: &super::ErasureReceiptV1,
) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut body = super::evidence::receipt_fields(&receipt.0);
    body.remove(super::evidence::RECEIPT_SIGNATURE_FIELD);
    body.remove(super::evidence::RECEIPT_DIGEST_FIELD);
    encode_limited(
        &record("ERCB1", vec![Value::Array(body)]),
        super::ERASURE_RECEIPT_MAX_BYTES,
    )
}

/// `CA(ERCB1)` of one receipt, the digest an ELS1 receipt-body signature
/// signs.
///
/// # Errors
/// Returns the canonical encoding error.
pub fn local_erasure_receipt_body_reference_v1(
    receipt: &super::ErasureReceiptV1,
) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    local_erasure_receipt_body_v1(receipt)
        .map(|bytes| ErasureReferenceV1::from_digest(domain_digest("ERCB1", &bytes)))
}
