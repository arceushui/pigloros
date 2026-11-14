//! ADR-129 §4 CMI1 native materialization binding.
//!
//! CMI1 separates a logical record's identity from its physical
//! materialization: it binds the owning schema's logical digest and length
//! to the exact COW1/ARD1/COA1 identities that hold its bytes, and to the
//! native node or intrinsic control request that produced it. It is finite
//! native control metadata with no own COA1 and no releasing authority.
//! Valid bytes do not prove that the object, registration or attestation
//! exists, or that the bytes reconstruct to that logical record: the
//! concrete owner checks every identity independently before committing.

use super::input_reference::CommunityNativeNodeReferenceV1;
use super::{
    canonical_end, digest, encode_coordinates, fixed_bytes, read_coordinates, read_hash, read_head,
    record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{
    encode_bytes, encode_hash, encode_head, CborCursor, ErasureArtifactClassV1, Hash, TimelineId,
};
use zeroize::Zeroizing;

const MAX_MATERIALIZATION: usize = 1024;
/// Largest logical record: direct up to 3 MiB, fragmented through CMO1 to 64 MiB.
pub const MAX_COMMUNITY_LOGICAL_RECORD_BYTES_V1: u64 = 67_108_864;

/// COW1-placed logical record families (ADR-129 construction annex §1) with
/// their exact ARD1 class. CMO1/CMF1 are byte representations of an owning
/// record, never a logical record of their own, so they are not listed.
const FAMILIES: [([u8; 4], ErasureArtifactClassV1); 19] = [
    (*b"CSC1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CSR1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CIN1", ErasureArtifactClassV1::TimelineReplay),
    (*b"COV1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CPN1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CPI1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CIS1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CIR1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CPE1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CES1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CIB1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CED1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CEB1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CAT1", ErasureArtifactClassV1::CausalTrace),
    (*b"GCA1", ErasureArtifactClassV1::CausalTrace),
    (*b"CIV1", ErasureArtifactClassV1::ReproManifest),
    (*b"CRR1", ErasureArtifactClassV1::ReproManifest),
    (*b"CFI1", ErasureArtifactClassV1::TimelineReplay),
    (*b"CFO1", ErasureArtifactClassV1::TimelineReplay),
];

/// Exact `[owner_reference, artifact_class, COW1_physical_address,
/// ARD1_artifact_digest, ARD1_registration_address, COA1_address]`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMaterializationReferenceV1 {
    /// Registered owner reference.
    pub owner_reference: Hash,
    /// ARD1 artifact class; must be the record family's class.
    pub artifact_class: ErasureArtifactClassV1,
    /// Physical COW1 address, distinct from the ARD1 artifact digest.
    pub object_address: Hash,
    /// ARD1 artifact digest.
    pub artifact_digest: Hash,
    /// ARD1 registration address.
    pub registration_address: Hash,
    /// COA1 address.
    pub attestation_address: Hash,
}

impl CommunityMaterializationReferenceV1 {
    fn validate(self) -> Result<()> {
        if [
            self.owner_reference,
            self.object_address,
            self.artifact_digest,
            self.registration_address,
            self.attestation_address,
        ]
        .contains(&Hash::zero())
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(())
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.push(0x86);
        encode_hash(out, self.owner_reference);
        encode_head(out, 0, self.artifact_class.code());
        encode_hash(out, self.object_address);
        encode_hash(out, self.artifact_digest);
        encode_hash(out, self.registration_address);
        encode_hash(out, self.attestation_address);
    }

    fn read(cursor: &mut CborCursor<'_>) -> Result<Self> {
        cursor.fixed(&[0x86]).map_err(Error::from).and_then(|()| {
            read_hash(cursor).and_then(|owner_reference| {
                read_head(cursor, 0)
                    .and_then(|code| {
                        ErasureArtifactClassV1::from_code(code).map_err(|_| Error::InvalidEncoding)
                    })
                    .and_then(|artifact_class| {
                        read_hash(cursor).and_then(|object_address| {
                            read_hash(cursor).and_then(|artifact_digest| {
                                read_hash(cursor).and_then(|registration_address| {
                                    read_hash(cursor).map(|attestation_address| Self {
                                        owner_reference,
                                        artifact_class,
                                        object_address,
                                        artifact_digest,
                                        registration_address,
                                        attestation_address,
                                    })
                                })
                            })
                        })
                    })
            })
        })
    }
}

/// Producer of the materialized logical record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityProducerBindingV1 {
    /// `[0, native_node_ref]` for a causal value.
    Native(CommunityNativeNodeReferenceV1),
    /// `[1, closed_control_request_digest]` for an intrinsic control format.
    Control(Hash),
}

impl CommunityProducerBindingV1 {
    fn validate(self, store_incarnation: [u8; 16]) -> Result<()> {
        match self {
            Self::Native(node) => node.validate().and_then(|()| {
                if node.store_incarnation == store_incarnation {
                    Ok(())
                } else {
                    Err(Error::InvalidBinding)
                }
            }),
            Self::Control(request) if request == Hash::zero() => Err(Error::InvalidBinding),
            Self::Control(_) => Ok(()),
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.push(0x82);
        match self {
            Self::Native(node) => {
                out.push(0);
                node.encode(out);
            }
            Self::Control(request) => {
                out.push(1);
                encode_hash(out, request);
            }
        }
    }

    fn read(cursor: &mut CborCursor<'_>) -> Result<Self> {
        cursor.fixed(&[0x82]).map_err(Error::from).and_then(|()| {
            read_head(cursor, 0).and_then(|code| match code {
                0 => CommunityNativeNodeReferenceV1::read(cursor).map(Self::Native),
                1 => read_hash(cursor).map(Self::Control),
                _ => Err(Error::InvalidEncoding),
            })
        })
    }
}

/// Untrusted CMI1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMaterializationInputV1 {
    /// Nonzero protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// Owning logical record's magic; one of the closed COW1 families.
    pub record_magic: [u8; 4],
    /// Owning schema's logical record hash, never a cipher or byte hash.
    pub logical_record_digest: Hash,
    /// Exact plaintext length, 1..=64 MiB.
    pub plaintext_length: u64,
    /// Exact physical materialization identities.
    pub materialization: CommunityMaterializationReferenceV1,
    /// Producing native node or intrinsic control request.
    pub producer: CommunityProducerBindingV1,
    /// Exact scope binding identity of the materialized record.
    pub scope_binding_digest: Hash,
    /// Original positive evidence horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact twelve-field CMI1.
pub struct CommunityMaterializationV1(CommunityMaterializationInputV1);

impl CommunityMaterializationV1 {
    /// Validate local identities, the record family and its artifact class.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero identities, a magic outside the
    /// closed COW1 families, an artifact class other than the family's, or a
    /// native producer from another store incarnation, and `BoundsExceeded`
    /// for an empty or over-64-MiB length or an invalid horizon.
    pub fn new(input: CommunityMaterializationInputV1) -> Result<Self> {
        if input.plaintext_length == 0
            || input.plaintext_length > MAX_COMMUNITY_LOGICAL_RECORD_BYTES_V1
        {
            return Err(Error::BoundsExceeded);
        }
        if input.store_incarnation == [0; 16]
            || input.logical_record_digest == Hash::zero()
            || input.scope_binding_digest == Hash::zero()
            || !FAMILIES.contains(&(input.record_magic, input.materialization.artifact_class))
        {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .and_then(|()| input.materialization.validate())
            .and_then(|()| input.producer.validate(input.store_incarnation))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving any identity.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityMaterializationInputV1 {
        &self.0
    }

    /// Encode the complete preferred CMI1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_MATERIALIZATION));
        record_prefix(&mut out, 12, *b"CMI1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_bytes(&mut out, &input.record_magic, 2);
        encode_hash(&mut out, input.logical_record_digest);
        encode_head(&mut out, 0, input.plaintext_length);
        input.materialization.encode(&mut out);
        input.producer.encode(&mut out);
        encode_hash(&mut out, input.scope_binding_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CMI1.v1\0" || CMI1)`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CMI1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CMI1.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_MATERIALIZATION, 12, *b"CMI1").and_then(|mut cursor| {
            read_body(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

fn read_body(cursor: &mut CborCursor<'_>) -> Result<CommunityMaterializationInputV1> {
    fixed_bytes(cursor).and_then(|store_incarnation| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            fixed_bytes(cursor).and_then(|record_magic| {
                read_hash(cursor).and_then(|logical_record_digest| {
                    read_head(cursor, 0).and_then(|plaintext_length| {
                        CommunityMaterializationReferenceV1::read(cursor).and_then(
                            |materialization| {
                                CommunityProducerBindingV1::read(cursor).and_then(|producer| {
                                    read_hash(cursor).and_then(|scope_binding_digest| {
                                        read_head(cursor, 0).map(|evidence_not_after_micros| {
                                            CommunityMaterializationInputV1 {
                                                store_incarnation,
                                                timeline,
                                                generation,
                                                record_magic,
                                                logical_record_digest,
                                                plaintext_length,
                                                materialization,
                                                producer,
                                                scope_binding_digest,
                                                evidence_not_after_micros,
                                            }
                                        })
                                    })
                                })
                            },
                        )
                    })
                })
            })
        })
    })
}
