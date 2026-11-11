//! Exact quarantine control data. A request or receipt cannot authorize reset.

use super::quarantine::{encode_reasons, read_reasons, validate_reasons};
use super::{
    bounded_bytes, canonical_end, fixed_bytes, read_hash, read_head, read_optional_hash,
    record_cursor, record_prefix, validate_horizon, CommunityLifecycleErrorV1 as Error,
    CommunityQuarantineKeyV1, CommunityQuarantineReasonsV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, ImplementationKeyV1};
use zeroize::Zeroizing;

/// Exact `contract-v1.artifact-ref`, shared with the live Runtime public path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactRefV1 {
    /// Registered schema ID.
    pub schema_id: u32,
    /// Exact artifact length.
    pub byte_length: u64,
    /// BLAKE3-256 artifact digest.
    pub digest: [u8; 32],
}

/// Two distinct installed host operations, never guest-controlled reset modes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityQuarantineControlKindV1 {
    /// Code0; installed failure producer, exactly one reason and no guest refs.
    SetReason,
    /// Code1; complete expected reason set and actual current reset authority.
    AuthenticatedReset,
}

impl CommunityQuarantineControlKindV1 {
    const fn code(self) -> u64 {
        match self {
            Self::SetReason => 0,
            Self::AuthenticatedReset => 1,
        }
    }
}

/// Untrusted CQC1 fields; all current premises require actual same-fence compare.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityQuarantineControlInputV1<'a> {
    /// Original host-selected nonzero16-byte idempotency identity, scoped to T.
    pub control_operation_id: [u8; 16],
    /// Stable Timeline/entry/implementation quarantine key.
    pub key: CommunityQuarantineKeyV1<'a>,
    /// Exact selected predecessor or independently admitted first-use absence.
    pub expected_ledger_digest: Option<Hash>,
    /// Closed installed host operation.
    pub operation: CommunityQuarantineControlKindV1,
    /// One new reason for `SetReason`, complete expected active set for reset.
    pub bound_reasons: CommunityQuarantineReasonsV1<'a>,
    /// Exact current trust snapshot binding.
    pub trust_snapshot_digest: Hash,
    /// Current active generation, never part of the stable quarantine key.
    pub expected_generation: [u8; 16],
    /// Exact current complete selected State head.
    pub expected_state_head_digest: Hash,
    /// Required only for authenticated reset, with independently verified schema.
    pub principal_ref: Option<ArtifactRefV1>,
    /// Required only for authenticated reset, never permission from a stored hash.
    pub authorization_ref: Option<ArtifactRefV1>,
    /// Current host-command bound, not permission to run a quarantined Plugin.
    pub authorization_not_after_micros: u64,
    /// Actual original host decision provenance, not a self-issued proof.
    pub host_decision_provenance_digest: Hash,
}

/// Immutable CQC1 data, excluding its future CQR1/CQO1/CAB1 identities.
pub struct CommunityQuarantineControlV1<'a>(CommunityQuarantineControlInputV1<'a>);

impl<'a> CommunityQuarantineControlV1<'a> {
    /// Validate local identities and distinct `SetReason`/reset field shapes.
    ///
    /// # Errors
    /// Rejects zero identities, invalid reason sets/horizon, wrong reference
    /// optionality or a `SetReason` with other than one reason. Actual failure
    /// mapping, first-use proof, current reset authority and CAS are owner work.
    pub fn new(input: CommunityQuarantineControlInputV1<'a>) -> Result<Self> {
        if input.control_operation_id == [0; 16]
            || input.expected_generation == [0; 16]
            || input.expected_ledger_digest == Some(Hash::zero())
            || [
                input.trust_snapshot_digest,
                input.expected_state_head_digest,
                input.host_decision_provenance_digest,
            ]
            .contains(&Hash::zero())
            || [input.principal_ref, input.authorization_ref]
                .iter()
                .flatten()
                .any(|reference| reference.digest == [0; 32])
        {
            return Err(Error::InvalidBinding);
        }
        let shape = match input.operation {
            CommunityQuarantineControlKindV1::SetReason => {
                input.bound_reasons.len() == 1
                    && input.principal_ref.is_none()
                    && input.authorization_ref.is_none()
            }
            CommunityQuarantineControlKindV1::AuthenticatedReset => {
                input.principal_ref.is_some() && input.authorization_ref.is_some()
            }
        };
        if !shape {
            return Err(Error::InvalidBinding);
        }
        validate_reasons(input.bound_reasons)
            .and_then(|()| validate_horizon(input.authorization_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow expected data without installing reset in an existing verifier.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityQuarantineControlInputV1<'a> {
        &self.0
    }

    /// Encode exact14-field CQC1 into pre-sized zeroizing private staging.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        record_prefix(&mut out, 14, *b"CQC1");
        encode_bytes(&mut out, &input.control_operation_id, 2);
        let key = input.key.to_canonical_cbor();
        encode_bytes(&mut out, &key, 2);
        super::encode_optional_hash(&mut out, input.expected_ledger_digest);
        encode_head(&mut out, 0, input.operation.code());
        encode_reasons(&mut out, input.bound_reasons);
        encode_hash(&mut out, input.trust_snapshot_digest);
        encode_bytes(&mut out, &input.expected_generation, 2);
        encode_hash(&mut out, input.expected_state_head_digest);
        encode_optional_ref(&mut out, input.principal_ref);
        encode_optional_ref(&mut out, input.authorization_ref);
        encode_head(&mut out, 0, input.authorization_not_after_micros);
        encode_hash(&mut out, input.host_decision_provenance_digest);
        out
    }

    /// Protected original request identity for idempotent exact comparisons.
    #[must_use]
    pub fn digest(&self) -> Hash {
        super::digest(b"PiglorOS.Community.CQC1.v1\0", &self.to_canonical_cbor())
    }

    /// Parse exact CQC1 against the independently retained implementation.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/versioned/oversized data, nested
    /// key mismatch, unknown operation and invalid local field/reference shape.
    pub fn from_canonical_cbor(
        bytes: &'a [u8],
        implementation: &'a ImplementationKeyV1,
    ) -> Result<Self> {
        record_cursor(bytes, 4096, 14, *b"CQC1").and_then(|mut cursor| {
            read_request_prefix(&mut cursor, implementation).and_then(|prefix| {
                read_current_bindings(&mut cursor).and_then(|bindings| {
                    read_control_refs(&mut cursor).and_then(|references| {
                        read_head(&mut cursor, 0).and_then(|authorization_not_after_micros| {
                            read_hash(&mut cursor).and_then(|host_decision_provenance_digest| {
                                canonical_end(&cursor).and_then(|()| {
                                    Self::new(CommunityQuarantineControlInputV1 {
                                        control_operation_id: prefix.operation_id,
                                        key: prefix.key,
                                        expected_ledger_digest: prefix.predecessor,
                                        operation: prefix.kind,
                                        bound_reasons: prefix.reasons,
                                        trust_snapshot_digest: bindings.trust,
                                        expected_generation: bindings.generation,
                                        expected_state_head_digest: bindings.head,
                                        principal_ref: references[0],
                                        authorization_ref: references[1],
                                        authorization_not_after_micros,
                                        host_decision_provenance_digest,
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    }
}

/// Closed CQO1 result, distinct from both current selection and permission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityQuarantineDispositionV1 {
    /// Code0; one admitted operation installed its exact original result.
    Applied,
    /// Code1; preserve the already selected evidence/horizon without refresh.
    AlreadyQuarantined,
}

impl CommunityQuarantineDispositionV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Applied => 0,
            Self::AlreadyQuarantined => 1,
        }
    }
}

/// Untrusted retained CQO1 data. It cannot renew evidence or authorize reset.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityQuarantineOutcomeInputV1 {
    /// Original nonzero host-selected control operation ID.
    pub control_operation_id: [u8; 16],
    /// Exact earlier CQC1.
    pub control_request_digest: Hash,
    /// Actual selected predecessor, absent only with independent first-use proof.
    pub prior_ledger_digest: Option<Hash>,
    /// Exact selected CQR1; existing original one when `AlreadyQuarantined`.
    pub selected_ledger_digest: Hash,
    /// Closed admitted outcome.
    pub disposition: CommunityQuarantineDispositionV1,
    /// Original fixed admitted horizon.
    pub evidence_not_after_micros: u64,
}

/// Historical CQO1 receipt, never a current availability fact or reset grant.
pub struct CommunityQuarantineOutcomeV1(CommunityQuarantineOutcomeInputV1);

impl CommunityQuarantineOutcomeV1 {
    /// Check original links/horizon and preservation for `AlreadyQuarantined`.
    ///
    /// # Errors
    /// Rejects zero identities/horizon or an `AlreadyQuarantined` receipt whose
    /// selected identity is not the exact existing prior ledger.
    pub fn new(input: CommunityQuarantineOutcomeInputV1) -> Result<Self> {
        if input.control_operation_id == [0; 16]
            || [input.control_request_digest, input.selected_ledger_digest].contains(&Hash::zero())
            || input.prior_ledger_digest == Some(Hash::zero())
            || (input.disposition == CommunityQuarantineDispositionV1::AlreadyQuarantined
                && input.prior_ledger_digest != Some(input.selected_ledger_digest))
        {
            return Err(Error::InvalidBinding);
        }
        validate_horizon(input.evidence_not_after_micros).map(|()| Self(input))
    }

    /// Borrow immutable outcome data without inferring current selection.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityQuarantineOutcomeInputV1 {
        &self.0
    }

    /// Encode exact eight-field CQO1 in fully reserved private staging.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 8, *b"CQO1");
        encode_bytes(&mut out, &input.control_operation_id, 2);
        encode_hash(&mut out, input.control_request_digest);
        super::encode_optional_hash(&mut out, input.prior_ledger_digest);
        encode_hash(&mut out, input.selected_ledger_digest);
        encode_head(&mut out, 0, input.disposition.code());
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Protected original receipt identity, not authority from a stored digest.
    #[must_use]
    pub fn digest(&self) -> Hash {
        super::digest(b"PiglorOS.Community.CQO1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CQO1 without changing any ledger.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/versioned/oversized data,
    /// unknown disposition or invalid identity/preservation/horizon values.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 1024, 8, *b"CQO1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor).and_then(|control_operation_id| {
                read_hash(&mut cursor).and_then(|control_request_digest| {
                    read_optional_hash(&mut cursor).and_then(|prior_ledger_digest| {
                        read_hash(&mut cursor).and_then(|selected_ledger_digest| {
                            read_disposition(&mut cursor).and_then(|disposition| {
                                read_head(&mut cursor, 0).and_then(|evidence_not_after_micros| {
                                    canonical_end(&cursor).and_then(|()| {
                                        Self::new(CommunityQuarantineOutcomeInputV1 {
                                            control_operation_id,
                                            control_request_digest,
                                            prior_ledger_digest,
                                            selected_ledger_digest,
                                            disposition,
                                            evidence_not_after_micros,
                                        })
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    }
}

struct RequestPrefix<'a> {
    operation_id: [u8; 16],
    key: CommunityQuarantineKeyV1<'a>,
    predecessor: Option<Hash>,
    kind: CommunityQuarantineControlKindV1,
    reasons: CommunityQuarantineReasonsV1<'a>,
}

fn read_request_prefix<'a>(
    cursor: &mut CborCursor<'a>,
    implementation: &'a ImplementationKeyV1,
) -> Result<RequestPrefix<'a>> {
    fixed_bytes(cursor).and_then(|operation_id| {
        bounded_bytes(cursor, 512)
            .and_then(|bytes| CommunityQuarantineKeyV1::from_canonical_cbor(bytes, implementation))
            .and_then(|key| {
                read_optional_hash(cursor).and_then(|predecessor| {
                    read_control_kind(cursor).and_then(|kind| {
                        read_reasons(cursor).map(|reasons| RequestPrefix {
                            operation_id,
                            key,
                            predecessor,
                            kind,
                            reasons,
                        })
                    })
                })
            })
    })
}

struct CurrentBindings {
    trust: Hash,
    generation: [u8; 16],
    head: Hash,
}

fn read_current_bindings(cursor: &mut CborCursor<'_>) -> Result<CurrentBindings> {
    read_hash(cursor).and_then(|trust| {
        fixed_bytes(cursor).and_then(|generation| {
            read_hash(cursor).map(|head| CurrentBindings {
                trust,
                generation,
                head,
            })
        })
    })
}

fn read_control_kind(cursor: &mut CborCursor<'_>) -> Result<CommunityQuarantineControlKindV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(CommunityQuarantineControlKindV1::SetReason),
        1 => Ok(CommunityQuarantineControlKindV1::AuthenticatedReset),
        _ => Err(Error::InvalidEncoding),
    })
}

fn read_disposition(cursor: &mut CborCursor<'_>) -> Result<CommunityQuarantineDispositionV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(CommunityQuarantineDispositionV1::Applied),
        1 => Ok(CommunityQuarantineDispositionV1::AlreadyQuarantined),
        _ => Err(Error::InvalidEncoding),
    })
}

fn encode_optional_ref(out: &mut Vec<u8>, reference: Option<ArtifactRefV1>) {
    match reference {
        None => out.push(0xf6),
        Some(reference) => encode_artifact_ref(out, reference),
    }
}

pub(super) fn encode_artifact_ref(out: &mut Vec<u8>, reference: ArtifactRefV1) {
    out.push(0x83);
    encode_head(out, 0, u64::from(reference.schema_id));
    encode_head(out, 0, reference.byte_length);
    encode_bytes(out, &reference.digest, 2);
}

fn read_control_refs(cursor: &mut CborCursor<'_>) -> Result<[Option<ArtifactRefV1>; 2]> {
    read_optional_ref(cursor).and_then(|principal| {
        read_optional_ref(cursor).map(|authorization| [principal, authorization])
    })
}

fn read_optional_ref(cursor: &mut CborCursor<'_>) -> Result<Option<ArtifactRefV1>> {
    if cursor.consume_if(0xf6) {
        return Ok(None);
    }
    read_artifact_ref(cursor).map(Some)
}

pub(super) fn read_artifact_ref(cursor: &mut CborCursor<'_>) -> Result<ArtifactRefV1> {
    cursor.fixed(&[0x83]).map_err(Error::from).and_then(|()| {
        read_head(cursor, 0)
            .and_then(|schema| u32::try_from(schema).map_err(|_| Error::BoundsExceeded))
            .and_then(|schema_id| {
                read_head(cursor, 0).and_then(|byte_length| {
                    fixed_bytes(cursor).map(|digest| ArtifactRefV1 {
                        schema_id,
                        byte_length,
                        digest,
                    })
                })
            })
    })
}
