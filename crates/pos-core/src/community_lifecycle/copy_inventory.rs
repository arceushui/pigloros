//! CCI1 owned-copy descriptors; a descriptor never proves disposal.
//!
//! The record names a copy's holder, purpose and scope without any payload or
//! key bytes. Disposal requires the actual worker, channel, wipe or key
//! outcome under its installed owner; elapsed time or a missing row is not
//! evidence, and this codec cannot observe either.

use super::envelope::{encode_operation, read_operation, read_purpose, validate_operation};
use super::{
    canonical_end, encode_coordinates, encode_optional_hash, fixed_bytes, read_coordinates,
    read_hash, read_head, read_optional_hash, record_cursor, record_prefix, validate_coordinates,
    validate_horizon, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

const MAX_COPY: usize = 1024;

/// Closed managed holder classes of one owned copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityCopyHolderV1 {
    /// Code0: owner decrypt/validation or encryption staging.
    Staging,
    /// Code1: the registered selected State cell.
    SelectedCell,
    /// Code2: a replaced cell awaiting its guarded wipe.
    RetiredCell,
    /// Code3: the admitted bounded worker.
    Worker,
    /// Code4: an invocation channel or pipe handoff.
    Channel,
    /// Code5: the qualified native context.
    NativeContext,
    /// Code6: the private key vault.
    KeyVault,
    /// Code7: the encrypted evidence store.
    EvidenceStore,
}

impl CommunityCopyHolderV1 {
    /// Return the fixed ADR-129 holder code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Staging => 0,
            Self::SelectedCell => 1,
            Self::RetiredCell => 2,
            Self::Worker => 3,
            Self::Channel => 4,
            Self::NativeContext => 5,
            Self::KeyVault => 6,
            Self::EvidenceStore => 7,
        }
    }

    const fn from_code(code: u64) -> Result<Self> {
        match code {
            0 => Ok(Self::Staging),
            1 => Ok(Self::SelectedCell),
            2 => Ok(Self::RetiredCell),
            3 => Ok(Self::Worker),
            4 => Ok(Self::Channel),
            5 => Ok(Self::NativeContext),
            6 => Ok(Self::KeyVault),
            7 => Ok(Self::EvidenceStore),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

/// Closed copy states; `Disposed` needs its holder's actual outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityCopyStateV1 {
    /// Code0.
    Owned,
    /// Code1.
    DeliveryPending,
    /// Code2.
    ReleaseConfirmed,
    /// Code3.
    DisposalPending,
    /// Code4.
    Disposed,
}

impl CommunityCopyStateV1 {
    /// Return the fixed ADR-129 state code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Owned => 0,
            Self::DeliveryPending => 1,
            Self::ReleaseConfirmed => 2,
            Self::DisposalPending => 3,
            Self::Disposed => 4,
        }
    }

    const fn from_code(code: u64) -> Result<Self> {
        match code {
            0 => Ok(Self::Owned),
            1 => Ok(Self::DeliveryPending),
            2 => Ok(Self::ReleaseConfirmed),
            3 => Ok(Self::DisposalPending),
            4 => Ok(Self::Disposed),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

/// Untrusted CCI1 fields.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityCopyInventoryInputV1 {
    /// Nonzero stable copy identity.
    pub copy_id: [u8; 16],
    /// Positive revision; 1 has no predecessor.
    pub revision: u64,
    /// Prior revision's identity, present exactly after revision 1.
    pub predecessor: Option<Hash>,
    /// Original pass, initialization or Control parent.
    pub parent_operation: CommunityArtifactOperationV1,
    /// Copy Timeline.
    pub timeline: TimelineId,
    /// Copy generation.
    pub generation: [u8; 16],
    /// Managed holder class.
    pub holder: CommunityCopyHolderV1,
    /// Opaque holder identity, never caller text.
    pub holder_digest: Hash,
    /// Key purpose partition of the copied bytes.
    pub purpose: CommunityArtifactPurposeV1,
    /// Exact `ScopeSet` digest of the copied bytes.
    pub scope_set_digest: Hash,
    /// Owner commitment of the copied object, when it is an object.
    pub object_commitment: Option<Hash>,
    /// Current copy state.
    pub state: CommunityCopyStateV1,
    /// Finite deadline; reaching it is never disposal evidence.
    pub deadline_micros: u64,
}

/// CCI1 descriptor with its local invariants checked.
pub struct CommunityCopyInventoryV1(CommunityCopyInventoryInputV1);

impl CommunityCopyInventoryV1 {
    /// Validate identities, revision linkage and the deadline.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero identities, a foreign parent pass or
    /// predecessor presence that does not match the revision, and
    /// `BoundsExceeded` for an invalid deadline.
    pub fn new(input: CommunityCopyInventoryInputV1) -> Result<Self> {
        if input.copy_id == [0; 16]
            || input.revision == 0
            || input.predecessor.is_some() != (input.revision > 1)
            || [input.holder_digest, input.scope_set_digest].contains(&Hash::zero())
            || [input.predecessor, input.object_commitment].contains(&Some(Hash::zero()))
        {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| {
                validate_operation(input.parent_operation, input.timeline, input.generation)
            })
            .and_then(|()| validate_horizon(input.deadline_micros))
            .map(|()| Self(input))
    }

    /// Borrow the exact descriptor fields.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityCopyInventoryInputV1 {
        &self.0
    }

    /// Encode the exact sixteen-field CCI1 into a zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_COPY));
        record_prefix(&mut out, 16, *b"CCI1");
        encode_bytes(&mut out, &input.copy_id, 2);
        encode_head(&mut out, 0, input.revision);
        encode_optional_hash(&mut out, input.predecessor);
        encode_operation(&mut out, input.parent_operation);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_head(&mut out, 0, u64::from(input.holder.code()));
        encode_hash(&mut out, input.holder_digest);
        encode_head(&mut out, 0, u64::from(input.purpose.code()));
        encode_hash(&mut out, input.scope_set_digest);
        encode_optional_hash(&mut out, input.object_commitment);
        encode_head(&mut out, 0, u64::from(input.state.code()));
        encode_head(&mut out, 0, input.deadline_micros);
        out
    }

    /// Decode one complete preferred CCI1.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, versioned, oversized or trailing
    /// records, unknown holder or state codes and invalid local bindings.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_COPY, 16, *b"CCI1").and_then(|mut cursor| {
            read_copy(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

fn read_copy(cursor: &mut CborCursor<'_>) -> Result<CommunityCopyInventoryInputV1> {
    fixed_bytes(cursor).and_then(|copy_id| {
        read_head(cursor, 0).and_then(|revision| {
            read_optional_hash(cursor).and_then(|predecessor| {
                read_operation(cursor).and_then(|parent_operation| {
                    read_coordinates(cursor).and_then(|(timeline, generation)| {
                        read_head(cursor, 0)
                            .and_then(CommunityCopyHolderV1::from_code)
                            .and_then(|holder| {
                                read_copy_tail(
                                    cursor,
                                    (copy_id, revision, predecessor, parent_operation),
                                    (timeline, generation, holder),
                                )
                            })
                    })
                })
            })
        })
    })
}

type CopyHead = ([u8; 16], u64, Option<Hash>, CommunityArtifactOperationV1);

fn read_copy_tail(
    cursor: &mut CborCursor<'_>,
    (copy_id, revision, predecessor, parent_operation): CopyHead,
    (timeline, generation, holder): (TimelineId, [u8; 16], CommunityCopyHolderV1),
) -> Result<CommunityCopyInventoryInputV1> {
    read_hash(cursor).and_then(|holder_digest| {
        read_purpose(cursor).and_then(|purpose| {
            read_hash(cursor).and_then(|scope_set_digest| {
                read_optional_hash(cursor).and_then(|object_commitment| {
                    read_head(cursor, 0)
                        .and_then(CommunityCopyStateV1::from_code)
                        .and_then(|state| {
                            read_head(cursor, 0).map(|deadline_micros| {
                                CommunityCopyInventoryInputV1 {
                                    copy_id,
                                    revision,
                                    predecessor,
                                    parent_operation,
                                    timeline,
                                    generation,
                                    holder,
                                    holder_digest,
                                    purpose,
                                    scope_set_digest,
                                    object_commitment,
                                    state,
                                    deadline_micros,
                                }
                            })
                        })
                })
            })
        })
    })
}
