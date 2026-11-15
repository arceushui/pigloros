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
    exact_array, header, strictly_increasing, text, uint, unsigned, ErasureArtifactClassV1,
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

const KIB: usize = 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_EXECUTOR_ID_BYTES: usize = 64;
const MAX_OPERATION_BYTES: usize = 64;
const MAX_ACK_CLASS_BYTES: usize = 48;
const MAX_BUNDLE_LIST: usize = 64;
const MAX_CLASSIFICATION_ROWS: usize = 256;
const MAX_AUTO_RETRY: u64 = 16;
const SIGNER_ROLE: u64 = 2;
const RETAINED_CLASS_CODES: std::ops::RangeInclusive<u64> = 2..=4;
const MAX_DATA_CLASS_CODE: u64 = 4;

/// Sequential reader over the fields of one decoded record.
struct Fields<'a>(std::slice::Iter<'a, Value>);

impl<'a> Fields<'a> {
    fn open(value: &'a Value, tag: &str, count: usize) -> Result<Self, ErasureErrorV1> {
        exact_array(value, count).and_then(|fields| {
            header(fields, tag).map(|()| Self(fields.get(2..).unwrap_or_default().iter()))
        })
    }

    fn next(&mut self) -> Result<&'a Value, ErasureErrorV1> {
        self.0.next().ok_or(ErasureErrorV1::InvalidEncoding)
    }

    fn digest(&mut self) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        self.next().and_then(bytes32)
    }

    fn uint(&mut self) -> Result<u64, ErasureErrorV1> {
        self.next().and_then(unsigned)
    }

    fn text(&mut self, max: usize) -> Result<String, ErasureErrorV1> {
        self.next().and_then(|value| bounded_text(value, max))
    }

    fn bytes(&mut self, min: usize, max: usize) -> Result<Vec<u8>, ErasureErrorV1> {
        self.next().and_then(|value| bounded_bytes(value, min, max))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ErasureErrorV1> {
        self.next().and_then(fixed)
    }

    fn truth(&mut self) -> Result<bool, ErasureErrorV1> {
        self.next().and_then(|value| match value {
            Value::Bool(value) => Ok(*value),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        })
    }

    fn array(&mut self, max: usize) -> Result<&'a [Value], ErasureErrorV1> {
        self.next().and_then(|value| array(value, max))
    }
}

fn bounded_text(value: &Value, max: usize) -> Result<String, ErasureErrorV1> {
    string(value).and_then(|text| {
        if text.len() <= max {
            Ok(text.to_owned())
        } else {
            Err(ErasureErrorV1::ScopeInvalid)
        }
    })
}

fn bounded_bytes(value: &Value, min: usize, max: usize) -> Result<Vec<u8>, ErasureErrorV1> {
    match value {
        Value::Bytes(bytes) if (min..=max).contains(&bytes.len()) => Ok(bytes.clone()),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], ErasureErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
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

/// One canonical record codec.
trait LocalRecordV1: Sized {
    const TAG: &'static str;
    const MAX_BYTES: usize;

    fn fields(&self) -> Vec<Value>;
    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1>;
    fn field_count() -> usize;

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
        Fields::open(&value, R::TAG, R::field_count() + 2)
            .and_then(|mut fields| R::read(&mut fields))
            .and_then(|decoded| {
                // Only the exact canonical bytes the encoder writes decode.
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
    /// The key-registry owner id, at most 128 bytes.
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
        exact_array(value, 3).and_then(|fields| {
            let mut fields = Fields(fields.iter());
            let owner_id = fields.bytes(1, MAX_IDENTIFIER_BYTES)?;
            let role = fields.uint()?;
            let epoch = fields.uint()?;
            require(role == SIGNER_ROLE && epoch >= 1).map(|()| Self { owner_id, epoch })
        })
    }
}

/// The TPS1 key id of an ELB1 signer key: `erasure-signer/` plus 64 lowercase
/// hex characters of its Ed25519 public key.
#[must_use]
pub fn local_erasure_signer_key_id_v1(public_key: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(ERASURE_SIGNER_KEY_PREFIX_V1.len() + 64);
    id.push_str(ERASURE_SIGNER_KEY_PREFIX_V1);
    for byte in public_key {
        id.push(char::from(HEX[usize::from(byte >> 4)]));
        id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    id
}

/// One ELB1 owner row: an acknowledgement class served by one owner.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalErasureOwnerRowV1 {
    /// The ADR-060 inventory category code.
    pub category: u64,
    /// The acknowledgement class.
    pub ack_class: String,
    /// `CA("ELOWN1", [store_identity, category, ack_class])`.
    pub owner_ref: ErasureReferenceV1,
}

/// The deployment-owned executor an ELB1 bundle permits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureExecutionBindingV1 {
    /// The executor identifier, at most 64 bytes.
    pub executor_id: String,
    /// The digest of the executor version.
    pub executor_version_digest: ErasureReferenceV1,
}

/// ELB1, the Local erasure authority bundle (ADR-136 §4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureBundleV1 {
    /// The digest of the TPS1 snapshot that admits the bundle root.
    pub tps1: ErasureReferenceV1,
    /// The write-once erasure store identity.
    pub store_identity: ErasureReferenceV1,
    /// The Local Principal authority registry digest.
    pub authority_registry_digest: ErasureReferenceV1,
    /// Host-owned Timelines, strictly increasing, at most 64.
    pub host_timelines: Vec<TimelineId>,
    /// `CA(ELP1)`.
    pub policy: ErasureReferenceV1,
    /// Owner rows, strictly increasing, at most 64.
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
    /// The expiry; 0 means valid until TPS1 revokes it.
    pub expiry: u64,
}

impl LocalRecordV1 for LocalErasureBundleV1 {
    const TAG: &'static str = "ELB1";
    const MAX_BYTES: usize = 64 * KIB;

    fn field_count() -> usize {
        12
    }

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

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        let tps1 = fields.digest()?;
        let store_identity = fields.digest()?;
        let authority_registry_digest = fields.digest()?;
        let host_timelines = fields
            .array(MAX_BUNDLE_LIST)?
            .iter()
            .map(|value| {
                fixed(value).map(|bytes| TimelineId::from_ulid(ulid::Ulid::from_bytes(bytes)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let policy = fields.digest()?;
        let owners = fields
            .array(MAX_BUNDLE_LIST)?
            .iter()
            .map(|value| {
                exact_array(value, 3).and_then(|row| {
                    let mut row = Fields(row.iter());
                    Ok(LocalErasureOwnerRowV1 {
                        category: row.uint()?,
                        ack_class: row.text(MAX_ACK_CLASS_BYTES)?,
                        owner_ref: row.digest()?,
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let binding = exact_array(fields.next()?, 2)?;
        let mut binding = Fields(binding.iter());
        let execution_binding = LocalErasureExecutionBindingV1 {
            executor_id: binding.text(MAX_EXECUTOR_ID_BYTES)?,
            executor_version_digest: binding.digest()?,
        };
        let signer_identity = LocalErasureSignerIdentityV1::read(fields.next()?)?;
        let signer_public_key = fields.fixed()?;
        Ok(Self {
            tps1,
            store_identity,
            authority_registry_digest,
            host_timelines,
            policy,
            owners,
            execution_binding,
            signer_identity,
            signer_public_key,
            signer_key_id: fields.text(MAX_IDENTIFIER_BYTES)?,
            issued_by: fields.text(MAX_IDENTIFIER_BYTES)?,
            expiry: fields.uint()?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(
            self.host_timelines.len() <= MAX_BUNDLE_LIST
                && strictly_increasing(&self.host_timelines)
                && self.owners.len() <= MAX_BUNDLE_LIST
                && strictly_increasing(&self.owners)
                && self.owners.iter().all(|owner| {
                    ErasureInventoryCategoryV1::from_code(owner.category).is_ok()
                        && is_ack_class(&owner.ack_class)
                })
                && !self.execution_binding.executor_id.is_empty()
                && self.execution_binding.executor_id.len() <= MAX_EXECUTOR_ID_BYTES
                && !self.signer_identity.owner_id.is_empty()
                && self.signer_identity.owner_id.len() <= MAX_IDENTIFIER_BYTES
                && self.signer_identity.epoch >= 1
                && self.signer_key_id == local_erasure_signer_key_id_v1(&self.signer_public_key)
                && self.issued_by.len() <= MAX_IDENTIFIER_BYTES
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

    fn field_count() -> usize {
        2
    }

    fn fields(&self) -> Vec<Value> {
        vec![digest(self.bundle), bytes_value(&self.admin_signature)]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        Ok(Self {
            bundle: fields.digest()?,
            admin_signature: fields.fixed()?,
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

    fn field_count() -> usize {
        2
    }

    fn fields(&self) -> Vec<Value> {
        vec![digest(self.request), uint(self.error as u64)]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        let request = fields.digest()?;
        let error = ErasureErrorV1::from_code(fields.uint()?)?;
        Ok(Self { request, error })
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
    /// The operator key id, at most 128 bytes.
    pub operator_key_id: String,
    /// The operator's Ed25519 public key.
    pub operator_public_key: [u8; 32],
}

impl LocalRecordV1 for LocalErasureTrustAnchorV1 {
    const TAG: &'static str = "ELTA1";
    const MAX_BYTES: usize = KIB;

    fn field_count() -> usize {
        3
    }

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.tps1),
            text(&self.operator_key_id),
            bytes_value(&self.operator_public_key),
        ]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        Ok(Self {
            tps1: fields.digest()?,
            operator_key_id: fields.text(MAX_IDENTIFIER_BYTES)?,
            operator_public_key: fields.fixed()?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(!self.operator_key_id.is_empty())
    }
}

local_record_api!(LocalErasureTrustAnchorV1);

/// One ELP1 classification row.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalErasureClassificationV1 {
    /// The ADR-060 artifact class code.
    pub artifact_class: u64,
    /// The ADR-060 data class code, 0 to 4.
    pub data_class: u64,
    /// The ADR-060 inventory category code.
    pub category: u64,
    /// The acknowledgement class.
    pub ack_class: String,
}

/// ELP1, the pinned Local erasure policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasurePolicyV1 {
    /// Always-retained data class codes, a strictly increasing subset of 2..=4.
    pub retained_classes: Vec<u64>,
    /// Classification rows, strictly increasing, at most 256.
    pub classification: Vec<LocalErasureClassificationV1>,
    /// Automatic retries of a transient result, at most 16.
    pub auto_retry_max: u64,
    /// Lifetime attempt quota, at most 4,096.
    pub quota_attempts: u64,
    /// Request heads reserved store-wide.
    pub store_request_reserve: u64,
    /// Re-prepares per lifecycle step.
    pub max_reprepare: u64,
}

impl LocalRecordV1 for LocalErasurePolicyV1 {
    const TAG: &'static str = "ELP1";
    const MAX_BYTES: usize = 64 * KIB;

    fn field_count() -> usize {
        7
    }

    fn fields(&self) -> Vec<Value> {
        vec![
            Value::Array(self.retained_classes.iter().copied().map(uint).collect()),
            Value::Array(
                self.classification
                    .iter()
                    .map(|row| {
                        Value::Array(vec![
                            uint(row.artifact_class),
                            uint(row.data_class),
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

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        let retained_classes = fields
            .array(3)?
            .iter()
            .map(unsigned)
            .collect::<Result<Vec<_>, _>>()?;
        let classification = fields
            .array(MAX_CLASSIFICATION_ROWS)?
            .iter()
            .map(|value| {
                exact_array(value, 4).and_then(|row| {
                    let mut row = Fields(row.iter());
                    Ok(LocalErasureClassificationV1 {
                        artifact_class: row.uint()?,
                        data_class: row.uint()?,
                        category: row.uint()?,
                        ack_class: row.text(MAX_ACK_CLASS_BYTES)?,
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        require(fields.uint()? == LOCAL_ERASURE_ATTEMPT_WINDOW_V1)?;
        Ok(Self {
            retained_classes,
            classification,
            auto_retry_max: fields.uint()?,
            quota_attempts: fields.uint()?,
            store_request_reserve: fields.uint()?,
            max_reprepare: fields.uint()?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(
            strictly_increasing(&self.retained_classes)
                && self
                    .retained_classes
                    .iter()
                    .all(|class| RETAINED_CLASS_CODES.contains(class))
                && self.classification.len() <= MAX_CLASSIFICATION_ROWS
                && strictly_increasing(&self.classification)
                && self.classification.iter().all(|row| {
                    ErasureArtifactClassV1::from_code(row.artifact_class).is_ok()
                        && row.data_class <= MAX_DATA_CLASS_CODE
                        && ErasureInventoryCategoryV1::from_code(row.category).is_ok()
                        && is_ack_class(&row.ack_class)
                })
                && self.auto_retry_max <= MAX_AUTO_RETRY
                && self.quota_attempts <= ERASURE_MAX_OBLIGATIONS_PER_CATEGORY as u64,
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
    /// The Gateway operation name, at most 64 bytes.
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

    fn field_count() -> usize {
        8
    }

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

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        Ok(Self {
            principal_ref: fields.digest()?,
            actor_entity: EntityId::from_ulid(ulid::Ulid::from_bytes(fields.fixed()?)),
            operation: fields.text(MAX_OPERATION_BYTES)?,
            authority_registry_digest: fields.digest()?,
            authority_chain: TimelineId::from_ulid(ulid::Ulid::from_bytes(fields.fixed()?)),
            chain_head_position: fields.uint()?,
            revocation_epoch: fields.uint()?,
            erq1_request: fields.digest()?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(!self.operation.is_empty() && self.operation.len() <= MAX_OPERATION_BYTES)
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

    fn field_count() -> usize {
        4
    }

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.subject),
            uint(0),
            Value::Bool(true),
            Value::Bool(true),
        ]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        let subject = fields.digest()?;
        let rule = fields.uint()?;
        let descendants = fields.truth()?;
        let future_forks = fields.truth()?;
        require(rule == 0 && descendants && future_forks).map(|()| Self { subject })
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

    fn field_count() -> usize {
        2
    }

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.idempotency_key_digest),
            digest(self.body_digest),
        ]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        Ok(Self {
            idempotency_key_digest: fields.digest()?,
            body_digest: fields.digest()?,
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

impl LocalRecordV1 for LocalErasureOwnerResultV1 {
    const TAG: &'static str = "ELO1";
    const MAX_BYTES: usize = 4 * KIB;

    fn field_count() -> usize {
        8
    }

    fn fields(&self) -> Vec<Value> {
        vec![
            digest(self.request),
            digest(self.attempt),
            digest(self.obligation),
            digest(self.command),
            digest(self.owner_ref),
            uint(u64::from(self.error.is_some())),
            self.error.map_or(Value::Null, |error| uint(error as u64)),
            digest(self.effect_digest),
        ]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        let request = fields.digest()?;
        let attempt = fields.digest()?;
        let obligation = fields.digest()?;
        let command = fields.digest()?;
        let owner_ref = fields.digest()?;
        let outcome = fields.uint()?;
        let error = match (outcome, fields.next()?) {
            (0, Value::Null) => None,
            (1, code) => Some(ErasureErrorV1::from_code(unsigned(code)?)?),
            _ => return Err(ErasureErrorV1::InvalidEncoding),
        };
        Ok(Self {
            request,
            attempt,
            obligation,
            command,
            owner_ref,
            error,
            effect_digest: fields.digest()?,
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

impl LocalErasureSignaturePurposeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::FreezeAuthorization => 0,
            Self::OwnerResult => 1,
            Self::ReceiptBody => 2,
        }
    }

    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
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

    fn field_count() -> usize {
        4
    }

    fn fields(&self) -> Vec<Value> {
        vec![
            uint(self.purpose.code()),
            digest(self.signed_digest),
            self.signer_identity.value(),
            bytes_value(&self.signature),
        ]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        let purpose = LocalErasureSignaturePurposeV1::from_code(fields.uint()?)?;
        let signed_digest = fields.digest()?;
        let signer_identity = LocalErasureSignerIdentityV1::read(fields.next()?)?;
        Ok(Self {
            purpose,
            signed_digest,
            signer_identity,
            signature: fields.fixed()?,
        })
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        require(
            !self.signer_identity.owner_id.is_empty()
                && self.signer_identity.owner_id.len() <= MAX_IDENTIFIER_BYTES
                && self.signer_identity.epoch >= 1,
        )
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
            uint(purpose.code()),
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

    fn field_count() -> usize {
        2
    }

    fn fields(&self) -> Vec<Value> {
        vec![text(&self.ack_class), digest(self.policy)]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        Ok(Self {
            ack_class: fields.text(MAX_ACK_CLASS_BYTES)?,
            policy: fields.digest()?,
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

    fn field_count() -> usize {
        2
    }

    fn fields(&self) -> Vec<Value> {
        vec![digest(self.subject), uint(0)]
    }

    fn read(fields: &mut Fields<'_>) -> Result<Self, ErasureErrorV1> {
        let subject = fields.digest()?;
        require(fields.uint()? == 0).map(|()| Self { subject })
    }
}

local_record_api!(LocalErasureLineageRuleV1);
