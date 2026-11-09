//! GCA1 presentation claims compared to exactly delivered inputs and output.

use super::{
    canonical_end, read_hash, read_head, record_cursor, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{CborCursor, Hash};

/// Only guest annotation schema admitted by the initial retention profile.
pub const COMMUNITY_GUEST_CLAIM_SCHEMA_V1: u32 = 0x4341_0001;
/// Schema of the prior/next CSC1 identities used in GCA1 positions.
pub const COMMUNITY_CLAIM_STATE_SCHEMA_V1: u32 = 0x4353_0001;
const MAX_REFERENCES: usize = 4096;
const MAX_DRAFTS: usize = 1024;
// Exact actual-input matching and strict tuple uniqueness further restrict used
// rows to4 and generated rows to1+1024. Thus every accepted pair of lists also
// satisfies the shared4096-row bound without a redundant unreachable branch.
const _: () = assert!(4 + 1 + MAX_DRAFTS <= MAX_REFERENCES);

/// Actual artifact identity supplied by the host's independently validated data.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityClaimArtifactV1 {
    /// Exact registered or admitted guest schema identifier.
    pub schema: u32,
    /// Exact actual identity, never a factual/native node exposed to the guest.
    pub digest: Hash,
}

/// Comparison data, not authorization or a claim that these sources are actual.
pub struct CommunityGuestClaimContextV1<'a> {
    /// Delivered observation, prior State, principal and authorization, in order.
    pub inputs: [CommunityClaimArtifactV1; 4],
    /// Actual validated next State with its CSC1 identity.
    pub next_state: CommunityClaimArtifactV1,
    /// Actual validated drafts in original guest order, with their existing
    /// `GuestEventDraft` identities and guest schema IDs.
    pub event_drafts: &'a [CommunityClaimArtifactV1],
    /// Already delivered execution-profile digest, not caller policy text.
    pub execution_profile_digest: Hash,
}

/// Closed claim kinds. A declared derivation is never host-proved guest use.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityGuestClaimKindV1 {
    /// Code0; nonempty used references and no generated references.
    InputAvailable,
    /// Code1; nonempty generated references and no used references.
    OutputProduced,
    /// Code2; both sets nonempty, still a guest assertion.
    DeclaredDerivation,
}

/// One exact canonical reference triple.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct CommunityGuestClaimReferenceV1 {
    /// Used 0..3, or generated 0 next State and generated 1..k original drafts.
    pub position: u64,
    /// Exact actual artifact schema.
    pub schema: u32,
    /// Exact actual artifact digest.
    pub digest: Hash,
}

/// Borrowed validated reference rows, without a second decoded identity buffer.
#[derive(Clone, Copy)]
pub struct CommunityGuestClaimReferencesV1<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> CommunityGuestClaimReferencesV1<'a> {
    /// Number of exact reference triples.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no reference is present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Borrow the original exact row bytes for private range accounting.
    #[must_use]
    pub const fn as_canonical_rows(&self) -> &'a [u8] {
        self.bytes
    }

    /// Read immutable validated rows without allocating. Fallibility is explicit;
    /// no unexpected parse failure is silently discarded by the iterator.
    #[must_use]
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = Result<CommunityGuestClaimReferenceV1>> + 'a + use<'a> {
        let mut cursor = CborCursor::new(self.bytes);
        (0..self.count).map(move |_| read_reference(&mut cursor))
    }
}

/// An exact validated GCA1 view. It grants no authorization or retention scope.
pub struct CommunityGuestClaimV1<'a> {
    bytes: &'a [u8],
    kind: CommunityGuestClaimKindV1,
    used: CommunityGuestClaimReferencesV1<'a>,
    generated: CommunityGuestClaimReferencesV1<'a>,
}

impl<'a> CommunityGuestClaimV1<'a> {
    /// Validate preferred GCA1 and compare every assertion to actual host data.
    ///
    /// The owner independently establishes authorized delivery, output validity,
    /// the pinned validator catalogue and current presentation retention rights.
    /// This data validator cannot mint any of those premises.
    ///
    /// # Errors
    /// Rejects unsupported/malformed/nonpreferred/trailing/oversized claims,
    /// invalid comparison context, wrong kind/cardinality, unknown/substituted
    /// artifacts, unsorted/duplicate references and a substituted policy digest.
    pub fn validate_annotation(
        schema: u32,
        bytes: &'a [u8],
        context: &CommunityGuestClaimContextV1<'_>,
    ) -> Result<Self> {
        if schema != COMMUNITY_GUEST_CLAIM_SCHEMA_V1 {
            return Err(Error::InvalidBinding);
        }
        record_cursor(bytes, 1_048_576, 6, *b"GCA1").and_then(|mut cursor| {
            validate_context(context).and_then(|()| {
                read_kind(&mut cursor).and_then(|kind| {
                    read_references(&mut cursor, bytes, context, Side::Used).and_then(|used| {
                        read_references(&mut cursor, bytes, context, Side::Generated).and_then(
                            |generated| {
                                validate_cardinality(kind, used.is_empty(), generated.is_empty())
                                    .and_then(|()| read_hash(&mut cursor))
                                    .and_then(|policy| {
                                        if policy != context.execution_profile_digest {
                                            return Err(Error::InvalidBinding);
                                        }
                                        canonical_end(&cursor).map(|()| Self {
                                            bytes,
                                            kind,
                                            used,
                                            generated,
                                        })
                                    })
                            },
                        )
                    })
                })
            })
        })
    }

    /// Exact original preferred bytes; no payload clone is allocated.
    #[must_use]
    pub const fn as_canonical_cbor(&self) -> &'a [u8] {
        self.bytes
    }

    /// What the guest asserted, not a host CTR1 or authorization decision.
    #[must_use]
    pub const fn kind(&self) -> CommunityGuestClaimKindV1 {
        self.kind
    }

    /// Exact used-reference rows, still requiring current guarded retention/use.
    #[must_use]
    pub const fn used_refs(&self) -> CommunityGuestClaimReferencesV1<'a> {
        self.used
    }

    /// Exact generated-reference rows in the guest's own output coordinate space.
    #[must_use]
    pub const fn generated_refs(&self) -> CommunityGuestClaimReferencesV1<'a> {
        self.generated
    }
}

fn validate_context(context: &CommunityGuestClaimContextV1<'_>) -> Result<()> {
    if context.event_drafts.len() > MAX_DRAFTS {
        return Err(Error::BoundsExceeded);
    }
    if context.inputs[1].schema != COMMUNITY_CLAIM_STATE_SCHEMA_V1
        || context.next_state.schema != COMMUNITY_CLAIM_STATE_SCHEMA_V1
        || context.execution_profile_digest == Hash::zero()
        || context
            .inputs
            .iter()
            .chain(std::iter::once(&context.next_state))
            .chain(context.event_drafts)
            .any(|artifact| artifact.digest == Hash::zero())
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

fn read_kind(cursor: &mut CborCursor<'_>) -> Result<CommunityGuestClaimKindV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(CommunityGuestClaimKindV1::InputAvailable),
        1 => Ok(CommunityGuestClaimKindV1::OutputProduced),
        2 => Ok(CommunityGuestClaimKindV1::DeclaredDerivation),
        _ => Err(Error::InvalidEncoding),
    })
}

const fn validate_cardinality(
    kind: CommunityGuestClaimKindV1,
    used_empty: bool,
    generated_empty: bool,
) -> Result<()> {
    let valid = match kind {
        CommunityGuestClaimKindV1::InputAvailable => !used_empty && generated_empty,
        CommunityGuestClaimKindV1::OutputProduced => used_empty && !generated_empty,
        CommunityGuestClaimKindV1::DeclaredDerivation => !used_empty && !generated_empty,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidBinding)
    }
}

#[derive(Clone, Copy)]
enum Side {
    Used,
    Generated,
}

fn read_references<'a>(
    cursor: &mut CborCursor<'a>,
    bytes: &'a [u8],
    context: &CommunityGuestClaimContextV1<'_>,
    side: Side,
) -> Result<CommunityGuestClaimReferencesV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        if count > MAX_REFERENCES {
            return Err(Error::BoundsExceeded);
        }
        let start = cursor.position();
        let mut prior = None;
        (0..count)
            .try_for_each(|_| {
                read_reference(cursor).and_then(|reference| {
                    if prior.is_some_and(|previous| previous >= reference) {
                        return Err(Error::InvalidBinding);
                    }
                    prior = Some(reference);
                    let expected = expected_artifact(context, side, reference.position);
                    if expected
                        == Some(CommunityClaimArtifactV1 {
                            schema: reference.schema,
                            digest: reference.digest,
                        })
                    {
                        Ok(())
                    } else {
                        Err(Error::InvalidBinding)
                    }
                })
            })
            .map(|()| CommunityGuestClaimReferencesV1 {
                bytes: &bytes[start..cursor.position()],
                count,
            })
    })
}

fn expected_artifact(
    context: &CommunityGuestClaimContextV1<'_>,
    side: Side,
    position: u64,
) -> Option<CommunityClaimArtifactV1> {
    match (side, position) {
        (Side::Used, position) => usize::try_from(position)
            .ok()
            .and_then(|index| context.inputs.get(index))
            .copied(),
        (Side::Generated, 0) => Some(context.next_state),
        (Side::Generated, position) => usize::try_from(position - 1)
            .ok()
            .and_then(|index| context.event_drafts.get(index))
            .copied(),
    }
}

fn read_reference(cursor: &mut CborCursor<'_>) -> Result<CommunityGuestClaimReferenceV1> {
    cursor.fixed(&[0x83]).map_err(Error::from).and_then(|()| {
        read_head(cursor, 0).and_then(|position| {
            read_head(cursor, 0).and_then(|schema| {
                u32::try_from(schema)
                    .map_err(|_| Error::BoundsExceeded)
                    .and_then(|schema| {
                        read_hash(cursor).map(|digest| CommunityGuestClaimReferenceV1 {
                            position,
                            schema,
                            digest,
                        })
                    })
            })
        })
    })
}
