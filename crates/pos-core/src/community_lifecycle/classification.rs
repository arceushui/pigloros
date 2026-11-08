//! CAR1 proof data bound to the actual inner envelope header, not authority.

use super::envelope::{read_kind, read_owner, read_purpose, read_role_epoch};
use super::{
    bounded_bytes, canonical_end, digest, read_coordinates, read_hash, read_hashes, read_head,
    record_cursor, record_prefix, CommunityArtifactHeaderV1, CommunityLifecycleErrorV1 as Error,
    Result,
};
use crate::{
    encode_bytes, encode_hash, encode_head, ArtifactChildEdgeV1, CborCursor,
    ErasureArtifactClassV1, Hash,
};
use zeroize::Zeroizing;

const MAX_PROOF: usize = 512 * 1024;
const MAX_CHILDREN: usize = 2048;
const CHILD_BYTES: usize = 71;

/// Borrowed direct ARD1 child references. A native extractor must derive them.
#[derive(Clone, Copy)]
pub struct CommunityArtifactChildrenV1<'a>(ChildRows<'a>);

#[derive(Clone, Copy)]
enum ChildRows<'a> {
    Typed(&'a [ArtifactChildEdgeV1]),
    Canonical(&'a [u8]),
}

impl<'a> CommunityArtifactChildrenV1<'a> {
    /// Borrow untrusted child rows; the proof constructor checks shape/order.
    #[must_use]
    pub const fn from_children(children: &'a [ArtifactChildEdgeV1]) -> Self {
        Self(ChildRows::Typed(children))
    }

    /// Number of direct edges; descendants are independently graph-accounted.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            ChildRows::Typed(rows) => rows.len(),
            ChildRows::Canonical(bytes) => bytes.len() / CHILD_BYTES,
        }
    }

    /// Whether this proof has no direct child references.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate validated fixed-size rows without allocating an identity buffer.
    pub fn iter(&self) -> impl Iterator<Item = ArtifactChildEdgeV1> + '_ {
        (0..self.len()).map(|index| match self.0 {
            ChildRows::Typed(rows) => rows[index],
            ChildRows::Canonical(bytes) => {
                let row = &bytes[index * CHILD_BYTES..(index + 1) * CHILD_BYTES];
                // Canonical rows are created only after read_child succeeds.
                let mut artifact_digest = [0; 32];
                let mut registration_address = [0; 32];
                artifact_digest.copy_from_slice(&row[4..36]);
                registration_address.copy_from_slice(&row[38..70]);
                ArtifactChildEdgeV1 {
                    artifact_class: match row[1] {
                        0 => ErasureArtifactClassV1::TimelineReplay,
                        1 => ErasureArtifactClassV1::ReproManifest,
                        2 => ErasureArtifactClassV1::CausalTrace,
                        3 => ErasureArtifactClassV1::CalibrationReport,
                        4 => ErasureArtifactClassV1::Export,
                        5 => ErasureArtifactClassV1::ForkOrSnapshot,
                        _ => ErasureArtifactClassV1::ConformanceReport,
                    },
                    artifact_digest: Hash::from_bytes(artifact_digest),
                    registration_address: Hash::from_bytes(registration_address),
                    required: row[70] == 0xf5,
                }
            }
        })
    }

    /// Original exact decoded range, for the qualified owner's copy accounting.
    #[must_use]
    pub const fn as_canonical_rows(&self) -> Option<&'a [u8]> {
        match self.0 {
            ChildRows::Typed(_) => None,
            ChildRows::Canonical(bytes) => Some(bytes),
        }
    }
}

/// Untrusted CAR1 data; fixed context/classification comes from exact COH1.
pub struct CommunityClassificationProofInputV1<'a> {
    /// Actual inner envelope header; parsing it does not authenticate it.
    pub header: &'a CommunityArtifactHeaderV1,
    /// COB1 owner commitment derived before encryption.
    pub owner_binding_digest: Hash,
    /// Private owner plaintext commitment, not a public State index.
    pub plaintext_commitment: Hash,
    /// Actual inner COE1 address, never this proof or its containing COW1.
    pub envelope_address: Hash,
    /// Complete direct references fixed by the native format extractor.
    pub children: CommunityArtifactChildrenV1<'a>,
    /// Exact CPV1 original host provenance commitment, not current authority.
    pub host_provenance_digest: Hash,
}

/// Structurally bound CAR1, still requiring authentication/native verification.
pub struct CommunityClassificationProofV1<'a>(CommunityClassificationProofInputV1<'a>);

impl<'a> CommunityClassificationProofV1<'a> {
    /// Check nonzero commitments, direct edge bounds and strict identity order.
    ///
    /// # Errors
    /// Rejects zero links, over2048 children and duplicate/unsorted references.
    /// Self/cycle exclusion and completeness require the native graph extractor;
    /// this data constructor cannot authenticate a caller-selected child list.
    pub fn new(input: CommunityClassificationProofInputV1<'a>) -> Result<Self> {
        if [
            input.owner_binding_digest,
            input.plaintext_commitment,
            input.envelope_address,
            input.host_provenance_digest,
        ]
        .contains(&Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        if input.children.len() > MAX_CHILDREN {
            return Err(Error::BoundsExceeded);
        }
        let mut prior = None;
        let validation = input.children.iter().try_for_each(|child| {
            let identity = (
                child.artifact_class,
                child.artifact_digest,
                child.registration_address,
            );
            if child.artifact_digest == Hash::zero()
                || child.registration_address == Hash::zero()
                || prior.is_some_and(|previous| previous >= identity)
            {
                return Err(Error::InvalidBinding);
            }
            prior = Some(identity);
            Ok(())
        });
        validation.map(|()| Self(input))
    }

    /// Borrow proof data without authenticating its provenance or classification.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityClassificationProofInputV1<'a> {
        &self.0
    }

    /// Encode exact15-field CAR1, using only class0 `PrivateSubjectData`.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let header = input.header.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(
            1024 + input.children.len() * CHILD_BYTES,
        ));
        record_prefix(&mut out, 15, *b"CAR1");
        encode_hash(&mut out, input.owner_binding_digest);
        super::encode_coordinates(&mut out, header.timeline, header.generation);
        encode_head(&mut out, 0, u64::from(header.purpose.code()));
        encode_head(&mut out, 0, u64::from(header.record_kind.code()));
        encode_hash(&mut out, input.plaintext_commitment);
        encode_hash(&mut out, input.envelope_address);
        encode_hash(&mut out, header.scope_cover_digest);
        out.push(0);
        encode_head(&mut out, 4, input.children.len() as u64);
        for child in input.children.iter() {
            out.push(0x84);
            encode_head(&mut out, 0, child.artifact_class.code());
            encode_hash(&mut out, child.artifact_digest);
            encode_hash(&mut out, child.registration_address);
            out.push(if child.required { 0xf5 } else { 0xf4 });
        }
        let mut identity = Zeroizing::new(Vec::with_capacity(136));
        identity.push(0x83);
        encode_bytes(
            &mut identity,
            input.header.key_identity().owner_id.as_str().as_bytes(),
            3,
        );
        identity.extend_from_slice(&[7, 1]);
        encode_bytes(&mut out, &identity, 2);
        encode_head(&mut out, 0, header.evidence_not_after_micros);
        encode_hash(&mut out, input.host_provenance_digest);
        out
    }

    /// Protected proof identity; never a public State index or read permit.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"PiglorOS.Community.ClassificationProof.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode exact CAR1 and compare every context/key field to inner COH1.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/oversized/trailing records, invalid links
    /// or ordering and any T/G/purpose/kind/scope/key/horizon/class mismatch.
    /// No plaintext authentication or current authority is inferred.
    pub fn from_canonical_cbor(
        bytes: &'a [u8],
        header: &'a CommunityArtifactHeaderV1,
    ) -> Result<Self> {
        record_cursor(bytes, MAX_PROOF, 15, *b"CAR1").and_then(|mut cursor| {
            read_prefix(&mut cursor, header).and_then(
                |[owner_binding_digest, plaintext_commitment, envelope_address]| {
                    read_scope_class(&mut cursor, header)
                        .and_then(|()| read_children(&mut cursor))
                        .and_then(|children| {
                            read_key_horizon(&mut cursor, header)
                                .and_then(|()| read_hash(&mut cursor))
                                .and_then(|host_provenance_digest| {
                                    canonical_end(&cursor).and_then(|()| {
                                        Self::new(CommunityClassificationProofInputV1 {
                                            header,
                                            owner_binding_digest,
                                            plaintext_commitment,
                                            envelope_address,
                                            children,
                                            host_provenance_digest,
                                        })
                                    })
                                })
                        })
                },
            )
        })
    }
}

fn read_prefix(
    cursor: &mut CborCursor<'_>,
    header: &CommunityArtifactHeaderV1,
) -> Result<[Hash; 3]> {
    read_hash(cursor).and_then(|owner| {
        read_context(cursor, header)
            .and_then(|()| read_hashes(cursor))
            .map(|[plaintext, envelope]| [owner, plaintext, envelope])
    })
}

fn read_context(cursor: &mut CborCursor<'_>, header: &CommunityArtifactHeaderV1) -> Result<()> {
    read_coordinates(cursor).and_then(|(timeline, generation)| {
        read_purpose(cursor).and_then(|purpose| {
            read_kind(cursor).and_then(|kind| {
                let expected = header.as_input();
                if (timeline, generation, purpose, kind)
                    == (
                        expected.timeline,
                        expected.generation,
                        expected.purpose,
                        expected.record_kind,
                    )
                {
                    Ok(())
                } else {
                    Err(Error::InvalidBinding)
                }
            })
        })
    })
}

fn read_scope_class(cursor: &mut CborCursor<'_>, header: &CommunityArtifactHeaderV1) -> Result<()> {
    read_hash(cursor).and_then(|scope| {
        read_head(cursor, 0).and_then(|class| {
            if scope == header.as_input().scope_cover_digest && class == 0 {
                Ok(())
            } else {
                Err(Error::InvalidBinding)
            }
        })
    })
}

fn read_key_horizon(cursor: &mut CborCursor<'_>, header: &CommunityArtifactHeaderV1) -> Result<()> {
    bounded_bytes(cursor, 136).and_then(|bytes| {
        let mut identity = CborCursor::new(bytes);
        identity.fixed(&[0x83]).map_err(Error::from).and_then(|()| {
            read_owner(&mut identity).and_then(|owner| {
                read_role_epoch(&mut identity)
                    .and_then(|()| canonical_end(&identity))
                    .and_then(|()| {
                        read_head(cursor, 0).and_then(|horizon| {
                            if owner == header.key_identity().owner_id
                                && horizon == header.as_input().evidence_not_after_micros
                            {
                                Ok(())
                            } else {
                                Err(Error::InvalidBinding)
                            }
                        })
                    })
            })
        })
    })
}

fn read_children<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityArtifactChildrenV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        if count > MAX_CHILDREN {
            return Err(Error::BoundsExceeded);
        }
        cursor
            .take(count * CHILD_BYTES)
            .map_err(Error::from)
            .and_then(|bytes| {
                bytes
                    .chunks_exact(CHILD_BYTES)
                    .try_for_each(read_child)
                    .map(|()| CommunityArtifactChildrenV1(ChildRows::Canonical(bytes)))
            })
    })
}

fn read_child(row: &[u8]) -> Result<()> {
    let mut cursor = CborCursor::new(row);
    cursor.fixed(&[0x84]).map_err(Error::from).and_then(|()| {
        read_head(&mut cursor, 0).and_then(|class| {
            ErasureArtifactClassV1::from_code(class)
                .map_err(|_| Error::InvalidEncoding)
                .and_then(|_| {
                    read_hash(&mut cursor)
                        .and_then(|_| read_hash(&mut cursor))
                        .and_then(|_| {
                            if cursor.consume_if(0xf4) || cursor.consume_if(0xf5) {
                                canonical_end(&cursor)
                            } else {
                                Err(Error::InvalidEncoding)
                            }
                        })
                })
        })
    })
}
