//! Original owner and metadata-anchor data, never current-use/service authority.

use super::envelope::append_hex;
use super::{
    bounded_text, canonical_end, digest, encode_coordinates, fixed_bytes, read_coordinates,
    read_hashes, read_head, record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, Hash, TimelineId};
use zeroize::Zeroizing;

/// Untrusted original COB1 fields; the catalogue-owner spelling is derived.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityOwnerBindingInputV1 {
    /// Nonzero actual protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// Actual execution Timeline, not the metadata anchor's substitute.
    pub timeline: TimelineId,
    /// Exact admitted execution generation.
    pub generation: [u8; 16],
    /// Actual qualified native/CPU/runtime profile identity.
    pub native_profile_digest: Hash,
    /// Independently installed actual owner catalogue.
    pub installed_owner_catalogue_digest: Hash,
    /// Independently installed actual authority catalogue.
    pub authority_catalogue_digest: Hash,
    /// Original complete CDP1, before this binding and CMB1 exist.
    pub durable_profile_digest: Hash,
    /// Nonzero original host installation identity.
    pub installation_id: [u8; 16],
    /// Original finite evidence deadline, not permission to renew it.
    pub evidence_not_after_micros: u64,
}

/// Exact COB1 data. Its digest cannot qualify a native handle or mint a grant.
pub struct CommunityOwnerBindingV1 {
    input: CommunityOwnerBindingInputV1,
    catalogue_owner: Zeroizing<String>,
}

impl CommunityOwnerBindingV1 {
    /// Validate identifiers/links and derive the exact ADR-128 catalogue owner.
    ///
    /// # Errors
    /// Rejects zero coordinates/identifiers/digests or an invalid horizon. The
    /// installed native profile, catalogues and current authority still require
    /// independent concrete-owner verification.
    pub fn new(input: CommunityOwnerBindingInputV1) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation).and_then(|()| {
            if input.store_incarnation == [0; 16]
                || input.installation_id == [0; 16]
                || [
                    input.native_profile_digest,
                    input.installed_owner_catalogue_digest,
                    input.authority_catalogue_digest,
                    input.durable_profile_digest,
                ]
                .contains(&Hash::zero())
            {
                return Err(Error::InvalidBinding);
            }
            validate_horizon(input.evidence_not_after_micros).map(|()| {
                let mut catalogue_owner = Zeroizing::new(String::with_capacity(84));
                catalogue_owner.push_str("community-artifact:");
                append_hex(&mut catalogue_owner, &input.timeline.inner().to_bytes());
                catalogue_owner.push(':');
                append_hex(&mut catalogue_owner, &input.generation);
                Self {
                    input,
                    catalogue_owner,
                }
            })
        })
    }

    /// Borrow the exact historical binding data; it grants no current use.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityOwnerBindingInputV1 {
        &self.input
    }

    /// Borrow exact lowercase `community-artifact:<T32>:<G32>` catalogue text.
    /// This is distinct from the per-operation role7 key owner's spelling.
    #[must_use]
    pub fn catalogue_owner_text(&self) -> &str {
        &self.catalogue_owner
    }

    /// Copy exact12-field COB1 into a fully pre-sized zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 12, *b"COB1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_bytes(&mut out, self.catalogue_owner_text().as_bytes(), 3);
        for hash in [
            input.native_profile_digest,
            input.installed_owner_catalogue_digest,
            input.authority_catalogue_digest,
            input.durable_profile_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_bytes(&mut out, &input.installation_id, 2);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// ADR-128 `OwnerBinding` identity, not the generic COB1 record hash domain.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"PiglorOS.Community.OwnerBinding.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode exact COB1 and reject any substituted catalogue-owner spelling.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/versioned/oversized/trailing records,
    /// invalid bindings and foreign owner text without cloning wire text.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 1_048_576, 12, *b"COB1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor).and_then(|store_incarnation| {
                read_coordinates(&mut cursor).and_then(|(timeline, generation)| {
                    bounded_text(&mut cursor, 128).and_then(|owner| {
                        read_hashes(&mut cursor).and_then(|[native_profile_digest, installed_owner_catalogue_digest, authority_catalogue_digest, durable_profile_digest]| {
                            fixed_bytes(&mut cursor).and_then(|installation_id| {
                                read_head(&mut cursor, 0).and_then(|evidence_not_after_micros| {
                                    canonical_end(&cursor).and_then(|()| Self::new(CommunityOwnerBindingInputV1 {
                                        store_incarnation, timeline, generation, native_profile_digest, installed_owner_catalogue_digest,
                                        authority_catalogue_digest, durable_profile_digest, installation_id, evidence_not_after_micros,
                                    })).and_then(|record| {
                                        if record.catalogue_owner_text() == owner { Ok(record) } else { Err(Error::InvalidBinding) }
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

/// Exact original NMP1 inputs. Hashes name sources; they do not resolve them.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMetadataPolicyInputV1 {
    /// Independently authenticated owner/authority registry binding.
    pub metadata_owner_registry_binding: Hash,
    /// Existing CPG1 leaf grant identity, a 32-byte hash.
    pub metadata_authority_leaf_grant: Hash,
    /// Installed exact closed schema catalogue, not an arbitrary decoder callback.
    pub compiled_schema_catalogue_digest: Hash,
    /// Original immutable finite metadata horizon.
    pub metadata_not_after_micros: u64,
}

/// Metadata policy data; the declared actions are never a live service grant.
pub struct CommunityMetadataPolicyV1(CommunityMetadataPolicyInputV1);

impl CommunityMetadataPolicyV1 {
    /// Validate required original bindings and immutable finite policy horizon.
    ///
    /// # Errors
    /// Rejects zero bindings or invalid time. Actual registry/CPG1 sources,
    /// current revocations and catalogue qualification remain owner obligations.
    pub fn new(input: CommunityMetadataPolicyInputV1) -> Result<Self> {
        if [
            input.metadata_owner_registry_binding,
            input.metadata_authority_leaf_grant,
            input.compiled_schema_catalogue_digest,
        ]
        .contains(&Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        validate_horizon(input.metadata_not_after_micros).map(|()| Self(input))
    }

    /// Borrow original policy data, without inspecting or admitting any source.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityMetadataPolicyInputV1 {
        &self.0
    }

    /// Encode exact10-field NMP1, fixed capacity bounds and actions `[0,1,2]`.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 10, *b"NMP1");
        for hash in [
            input.metadata_owner_registry_binding,
            input.metadata_authority_leaf_grant,
            input.compiled_schema_catalogue_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_head(&mut out, 0, input.metadata_not_after_micros);
        for limit in [4_194_304, 3_145_728, 1_000_000] {
            encode_head(&mut out, 0, limit);
        }
        out.extend_from_slice(&[0x83, 0, 1, 2]);
        out
    }

    /// Exact NMP1 policy identity, without granting metadata inspection.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.NMP1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode only the exact initial metadata limits and three declared actions.
    ///
    /// # Errors
    /// Rejects unknown/nonpreferred/trailing/oversized/versioned data, zero
    /// links, invalid deadlines or different limit/action semantics.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 1024, 10, *b"NMP1").and_then(|mut cursor| {
            read_hashes(&mut cursor).and_then(|[metadata_owner_registry_binding, metadata_authority_leaf_grant, compiled_schema_catalogue_digest]| {
                read_head(&mut cursor, 0).and_then(|metadata_not_after_micros| {
                    [4_194_304, 3_145_728, 1_000_000].into_iter().try_for_each(|expected| {
                        read_head(&mut cursor, 0).and_then(|actual| {
                            if actual == expected { Ok(()) } else { Err(Error::InvalidBinding) }
                        })
                    }).and_then(|()| cursor.fixed(&[0x83,0,1,2]).map_err(Error::from))
                        .and_then(|()| canonical_end(&cursor))
                        .and_then(|()| Self::new(CommunityMetadataPolicyInputV1 {
                            metadata_owner_registry_binding, metadata_authority_leaf_grant, compiled_schema_catalogue_digest, metadata_not_after_micros,
                        }))
                })
            })
        })
    }
}

/// Original CMA1 anchor binding, distinct from later selected execution T/G.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMetadataAnchorInputV1 {
    /// Actual protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// Real first admitted Timeline, not a synthetic subject.
    pub anchor_timeline: TimelineId,
    /// Real first admitted generation, retained after its execution retires.
    pub anchor_generation: [u8; 16],
    /// Exact original NMP1 identity.
    pub metadata_policy_digest: Hash,
    /// Exact registry binding from the original policy.
    pub metadata_owner_registry_binding: Hash,
    /// Exact CPG1 leaf grant identity from that policy.
    pub metadata_authority_leaf_grant: Hash,
    /// Exact immutable original metadata horizon.
    pub metadata_not_after_micros: u64,
}

/// CMA1 derived from original NMP1 data, not authority to inspect a CNE1 body.
pub struct CommunityMetadataAnchorV1(CommunityMetadataAnchorInputV1);

impl CommunityMetadataAnchorV1 {
    /// Derive exact policy bindings without minting a bootstrap or guest permit.
    ///
    /// # Errors
    /// Rejects zero store/Timeline/generation identities. Actual initial admission,
    /// current metadata service authority and native binding remain owner checks.
    pub fn new(
        store_incarnation: [u8; 16],
        anchor_timeline: TimelineId,
        anchor_generation: [u8; 16],
        policy: &CommunityMetadataPolicyV1,
    ) -> Result<Self> {
        if store_incarnation == [0; 16] {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(anchor_timeline, anchor_generation).map(|()| {
            let input = policy.as_input();
            Self(CommunityMetadataAnchorInputV1 {
                store_incarnation,
                anchor_timeline,
                anchor_generation,
                metadata_policy_digest: policy.digest(),
                metadata_owner_registry_binding: input.metadata_owner_registry_binding,
                metadata_authority_leaf_grant: input.metadata_authority_leaf_grant,
                metadata_not_after_micros: input.metadata_not_after_micros,
            })
        })
    }

    /// Borrow original anchor data; it does not select an execution generation.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityMetadataAnchorInputV1 {
        &self.0
    }

    /// Encode exact9-field CMA1, with no raw payload or logical State identity.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 9, *b"CMA1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.anchor_timeline, input.anchor_generation);
        for hash in [
            input.metadata_policy_digest,
            input.metadata_owner_registry_binding,
            input.metadata_authority_leaf_grant,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_head(&mut out, 0, input.metadata_not_after_micros);
        out
    }

    /// Exact CMA1 identity, not a proof of completed bootstrap.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CMA1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode against the independently retained exact original NMP1.
    ///
    /// # Errors
    /// Rejects invalid framing/versions/limits/identities or any policy, registry,
    /// grant or immutable-horizon substitution. Current grant validation remains
    /// mandatory even after original-data equality succeeds.
    pub fn from_canonical_cbor(bytes: &[u8], policy: &CommunityMetadataPolicyV1) -> Result<Self> {
        record_cursor(bytes, 1024, 9, *b"CMA1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor).and_then(|incarnation| {
                read_coordinates(&mut cursor).and_then(|(timeline, generation)| {
                    read_hashes::<3>(&mut cursor).and_then(|hashes| {
                        read_head(&mut cursor, 0).and_then(|horizon| {
                            canonical_end(&cursor)
                                .and_then(|()| Self::new(incarnation, timeline, generation, policy))
                                .and_then(|record| {
                                    let input = record.as_input();
                                    if hashes
                                        == [
                                            input.metadata_policy_digest,
                                            input.metadata_owner_registry_binding,
                                            input.metadata_authority_leaf_grant,
                                        ]
                                        && horizon == input.metadata_not_after_micros
                                    {
                                        Ok(record)
                                    } else {
                                        Err(Error::InvalidBinding)
                                    }
                                })
                        })
                    })
                })
            })
        })
    }
}
