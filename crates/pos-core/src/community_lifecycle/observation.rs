//! ADR-129 §4 COV1 observation value and CPE1 observation-source
//! materialization (revision 9, R9.2–R9.5).
//!
//! COV1 retains the exact observation bytes the runtime projection publisher
//! folded, under their existing three-field artifact reference. CPE1 is the
//! host materialization control proof: the complete prefix cut, one mode-2
//! row per Event naming that Event's CES1, the recorded reducer bindings and
//! the identities of the observation, its scope union and its Event-history
//! authority. Valid bytes prove none of those facts: the store re-checks the
//! rows against its own Event history before it mints either record.

use super::input_reference::{read_typed_ref, CommunityTypedInputRefV1};
use super::quarantine_control::{encode_artifact_ref, read_artifact_ref};
use super::{
    bounded_bytes, canonical_end, digest, encode_coordinates, fixed_bytes, read_coordinates,
    read_hash, read_hashes, read_head, read_vec, record_cursor, record_prefix,
    validate_coordinates, validate_horizon, ArtifactRefV1, CommunityLifecycleErrorV1 as Error,
    Result, MAX_COMMUNITY_MEMBERS_V1,
};
use crate::{
    encode_bytes, encode_hash, encode_head, CborCursor, ErasureArtifactClassV1, Hash, TimelineId,
};
use zeroize::Zeroizing;

/// Maximum canonical COV1 encoding.
pub const MAX_COMMUNITY_OBSERVATION_VALUE_BYTES_V1: usize = 1_048_704;
/// Maximum observation payload one COV1 retains.
pub const MAX_COMMUNITY_OBSERVATION_BYTES_V1: usize = 1_048_576;
/// Maximum canonical CPE1 encoding.
pub const MAX_COMMUNITY_OBSERVATION_SOURCE_BYTES_V1: usize = 1_048_576;
/// Maximum Event rows of one CPE1: the complete prefix must fit.
pub const MAX_COMMUNITY_OBSERVATION_EVENTS_V1: usize = 4096;
/// Maximum recorded consumers, and so reducer rows, of one CPE1.
pub const MAX_COMMUNITY_RECORDED_CONSUMERS_V1: usize = MAX_COMMUNITY_MEMBERS_V1;
/// Maximum bytes of a recorded consumer's Plugin ID text.
const MAX_PLUGIN_ID_BYTES: usize = 128;
// COV1 framing: record head and magic 6, version 1, T, G and operation 51,
// the artifact ref at most 49 and the payload head 5.
const COV1_FIXED: usize = 112;
const _: () = assert!(
    COV1_FIXED + MAX_COMMUNITY_OBSERVATION_BYTES_V1 <= MAX_COMMUNITY_OBSERVATION_VALUE_BYTES_V1
);
// CPE1 framing and fixed fields fit 256 bytes, one Event row 200 (head 1,
// seq 9, ID 17, payload hash 34 and the mode-2 ref 139) and one reducer row
// 205, so the largest CPE1 is 832,578 bytes, under the 1 MiB bound.
const CPE1_FIXED: usize = 256;
const ROW_BYTES: usize = 200;
const REDUCER_BYTES: usize = 205;
const _: () = assert!(
    CPE1_FIXED
        + ROW_BYTES * MAX_COMMUNITY_OBSERVATION_EVENTS_V1
        + REDUCER_BYTES * MAX_COMMUNITY_RECORDED_CONSUMERS_V1
        <= MAX_COMMUNITY_OBSERVATION_SOURCE_BYTES_V1
);

/// Untrusted COV1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityObservationValueInputV1<'a> {
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// The materialization control identity `M_id`.
    pub operation_id: [u8; 16],
    /// The installed observation encoder's artifact reference.
    pub observation_artifact_ref: ArtifactRefV1,
    /// Exact observation payload, 0..=1 MiB, of the reference's length.
    pub observation_bytes: &'a [u8],
}

/// Exact seven-field COV1.
pub struct CommunityObservationValueV1<'a>(CommunityObservationValueInputV1<'a>);

impl<'a> CommunityObservationValueV1<'a> {
    /// Validate coordinates, the operation, the reference and the payload.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero coordinates, operation or digest, or
    /// a reference length other than the payload's; `BoundsExceeded` for a
    /// payload over 1 MiB. The reference schema and digest are the installed
    /// encoder's, checked by the store.
    pub fn new(input: CommunityObservationValueInputV1<'a>) -> Result<Self> {
        if input.observation_bytes.len() > MAX_COMMUNITY_OBSERVATION_BYTES_V1 {
            return Err(Error::BoundsExceeded);
        }
        validate_coordinates(input.timeline, input.generation).and_then(|()| {
            if input.operation_id == [0; 16]
                || input.observation_artifact_ref.digest == [0; 32]
                || input.observation_artifact_ref.byte_length
                    != input.observation_bytes.len() as u64
            {
                Err(Error::InvalidBinding)
            } else {
                Ok(Self(input))
            }
        })
    }

    /// Borrow exact fields without authenticating the encoder.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityObservationValueInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred COV1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(
            COV1_FIXED + input.observation_bytes.len(),
        ));
        record_prefix(&mut out, 7, *b"COV1");
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_bytes(&mut out, &input.operation_id, 2);
        encode_artifact_ref(&mut out, input.observation_artifact_ref);
        encode_bytes(&mut out, input.observation_bytes, 2);
        out
    }

    /// `H(COV1)`, the CPE1 `observation_value_digest` (R9.4).
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.COV1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred COV1, borrowing its payload.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_COMMUNITY_OBSERVATION_VALUE_BYTES_V1, 7, *b"COV1").and_then(
            |mut cursor| {
                read_coordinates(&mut cursor)
                    .and_then(|(timeline, generation)| {
                        fixed_bytes(&mut cursor).and_then(|operation_id| {
                            read_artifact_ref(&mut cursor).and_then(|observation_artifact_ref| {
                                bounded_bytes(&mut cursor, MAX_COMMUNITY_OBSERVATION_BYTES_V1).map(
                                    |observation_bytes| CommunityObservationValueInputV1 {
                                        timeline,
                                        generation,
                                        operation_id,
                                        observation_artifact_ref,
                                        observation_bytes,
                                    },
                                )
                            })
                        })
                    })
                    .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
            },
        )
    }
}

/// The mode-2 registration fields of one Event's CES1 (R9.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityEventSourceRefV1 {
    /// The CES1 registration's owner reference.
    pub owner_reference: Hash,
    /// `H(CES1)`.
    pub artifact_digest: Hash,
    /// The CES1 ARD1 registration address.
    pub registration_address: Hash,
    /// The CES1 `source_scope_binding_digest`.
    pub source_scope_binding_digest: Hash,
}

impl CommunityEventSourceRefV1 {
    /// The row's typed reference: mode 2, class `TimelineReplay`.
    #[must_use]
    pub const fn typed_ref(self) -> CommunityTypedInputRefV1<'static> {
        CommunityTypedInputRefV1::Artifact {
            owner_reference: self.owner_reference,
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: self.artifact_digest,
            registration_address: self.registration_address,
            source_scope_binding_digest: self.source_scope_binding_digest,
        }
    }
}

/// `[logical_seq, event_id16, payload_hash32, typed_source_ref]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityObservationEventRowV1 {
    /// Logical sequence in the cut's order.
    pub logical_seq: u64,
    /// Committed Event identity.
    pub event_id: [u8; 16],
    /// Committed payload hash.
    pub payload_hash: Hash,
    /// The Event's CES1.
    pub source: CommunityEventSourceRefV1,
}

/// `[consumer_identity_digest, schema_digest, reducer_digest,
/// configuration_digest, admission_evidence_digest, minimization_policy_digest]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityReducerBindingV1 {
    /// `H("RecordedConsumer", [plugin_id, reducer_identity])`.
    pub consumer_identity_digest: Hash,
    /// The observation policy's schema revision.
    pub schema_digest: Hash,
    /// The recorded reducer identity.
    pub reducer_digest: Hash,
    /// `H("ReducerConfiguration", configuration_details)`.
    pub configuration_digest: Hash,
    /// The staged admission's conformance digest.
    pub admission_evidence_digest: Hash,
    /// The observation policy digest.
    pub minimization_policy_digest: Hash,
}

impl CommunityReducerBindingV1 {
    const fn values(self) -> [Hash; 6] {
        [
            self.consumer_identity_digest,
            self.schema_digest,
            self.reducer_digest,
            self.configuration_digest,
            self.admission_evidence_digest,
            self.minimization_policy_digest,
        ]
    }
}

/// Untrusted CPE1 fields.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityObservationSourceInputV1 {
    /// The materialization control identity `M_id`.
    pub operation_id: [u8; 16],
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// The complete prefix's last logical sequence, 0 for empty history.
    pub through_seq: u64,
    /// One row per prefix Event, sequences `1..=through_seq` in order.
    pub event_rows: Vec<CommunityObservationEventRowV1>,
    /// 1..=64 rows, strictly ascending by consumer identity.
    pub reducer_policy_bindings: Vec<CommunityReducerBindingV1>,
    /// `H(COV1)`.
    pub observation_value_digest: Hash,
    /// `H("ScopeSet", union of the rows' CES1 scope members)`.
    pub scope_union_digest: Hash,
    /// `H("EventSourceAuthority", [U, request_digest] rows)`.
    pub authority_request_digest: Hash,
    /// Fixed positive horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact fourteen-field CPE1.
///
/// `from_seq` and `recorded_consumer_set_digest` are derived: `from_seq` is
/// 1 for a nonempty prefix and 0 for empty history, and the consumer-set
/// digest covers the reducer rows' identities.
pub struct CommunityObservationSourceV1(CommunityObservationSourceInputV1);

impl CommunityObservationSourceV1 {
    /// Validate the complete-prefix shape, the rows and the identities.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for more than 4,096 Event rows, no or more
    /// than 64 reducer rows or an invalid horizon; `InvalidBinding` for zero
    /// coordinates, operation or identities, rows that are not exactly the
    /// sequences `1..=through_seq`, a zero row identity and reducer rows not
    /// strictly ascending by consumer.
    pub fn new(input: CommunityObservationSourceInputV1) -> Result<Self> {
        if input.event_rows.len() > MAX_COMMUNITY_OBSERVATION_EVENTS_V1
            || input.reducer_policy_bindings.is_empty()
            || input.reducer_policy_bindings.len() > MAX_COMMUNITY_RECORDED_CONSUMERS_V1
        {
            return Err(Error::BoundsExceeded);
        }
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| validate_rows(&input))
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving any row or consumer.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityObservationSourceInputV1 {
        &self.0
    }

    /// `from_seq`: 1 for a nonempty prefix, 0 for empty history.
    #[must_use]
    pub const fn from_seq(&self) -> u64 {
        if self.0.through_seq == 0 {
            0
        } else {
            1
        }
    }

    /// The recorded consumer-set digest of the reducer rows (R9.4).
    #[must_use]
    pub fn recorded_consumer_set_digest(&self) -> Hash {
        let identities: Vec<Hash> = self
            .0
            .reducer_policy_bindings
            .iter()
            .map(|row| row.consumer_identity_digest)
            .collect();
        community_recorded_consumer_set_digest_v1(&identities)
    }

    /// Encode the complete preferred CPE1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(
            CPE1_FIXED
                + ROW_BYTES * input.event_rows.len()
                + REDUCER_BYTES * input.reducer_policy_bindings.len(),
        ));
        record_prefix(&mut out, 14, *b"CPE1");
        encode_bytes(&mut out, &input.operation_id, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_hash(&mut out, self.recorded_consumer_set_digest());
        encode_head(&mut out, 0, self.from_seq());
        encode_head(&mut out, 0, input.through_seq);
        encode_head(&mut out, 4, input.event_rows.len() as u64);
        for row in &input.event_rows {
            out.push(0x84);
            encode_head(&mut out, 0, row.logical_seq);
            encode_bytes(&mut out, &row.event_id, 2);
            encode_hash(&mut out, row.payload_hash);
            row.source.typed_ref().encode(&mut out);
        }
        encode_head(&mut out, 4, input.reducer_policy_bindings.len() as u64);
        for row in &input.reducer_policy_bindings {
            out.push(0x86);
            for hash in row.values() {
                encode_hash(&mut out, hash);
            }
        }
        for hash in [
            input.observation_value_digest,
            input.scope_union_digest,
            input.authority_request_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// `H(CPE1)`, the materialization's `input_identity`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CPE1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CPE1.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records, a `from_seq` or consumer-set digest other than the derived
    /// one, a row reference other than mode 2 `TimelineReplay`, and every
    /// invalid local binding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(
            bytes,
            MAX_COMMUNITY_OBSERVATION_SOURCE_BYTES_V1,
            14,
            *b"CPE1",
        )
        .and_then(|mut cursor| {
            read_materialization(&mut cursor).and_then(|(input, from_seq, set_digest)| {
                canonical_end(&cursor)
                    .and_then(|()| Self::new(input))
                    .and_then(|record| {
                        if record.from_seq() == from_seq
                            && record.recorded_consumer_set_digest() == set_digest
                        {
                            Ok(record)
                        } else {
                            Err(Error::InvalidBinding)
                        }
                    })
            })
        })
    }
}

fn validate_rows(input: &CommunityObservationSourceInputV1) -> Result<()> {
    let contiguous = input.event_rows.len() as u64 == input.through_seq
        && input
            .event_rows
            .iter()
            .zip(1_u64..)
            .all(|(row, seq)| row.logical_seq == seq);
    let zero_row = input.event_rows.iter().any(|row| {
        row.event_id == [0; 16]
            || [
                row.payload_hash,
                row.source.owner_reference,
                row.source.artifact_digest,
                row.source.registration_address,
                row.source.source_scope_binding_digest,
            ]
            .contains(&Hash::zero())
    });
    let reducers = &input.reducer_policy_bindings;
    if !contiguous
        || zero_row
        || input.operation_id == [0; 16]
        || [
            input.observation_value_digest,
            input.scope_union_digest,
            input.authority_request_digest,
        ]
        .contains(&Hash::zero())
        || reducers
            .iter()
            .any(|row| row.values().contains(&Hash::zero()))
        || reducers
            .windows(2)
            .any(|pair| pair[0].consumer_identity_digest >= pair[1].consumer_identity_digest)
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

type Materialization = (CommunityObservationSourceInputV1, u64, Hash);

fn read_materialization(cursor: &mut CborCursor<'_>) -> Result<Materialization> {
    let head = fixed_bytes(cursor).and_then(|operation_id| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            read_hash(cursor).and_then(|set_digest| {
                read_head(cursor, 0).and_then(|from_seq| {
                    read_head(cursor, 0).map(|through_seq| {
                        (
                            operation_id,
                            timeline,
                            generation,
                            set_digest,
                            from_seq,
                            through_seq,
                        )
                    })
                })
            })
        })
    });
    head.and_then(
        |(operation_id, timeline, generation, set_digest, from_seq, through_seq)| {
            read_vec(cursor, MAX_COMMUNITY_OBSERVATION_EVENTS_V1, read_row).and_then(
                |event_rows| {
                    read_vec(cursor, MAX_COMMUNITY_RECORDED_CONSUMERS_V1, read_reducer).and_then(
                        |reducer_policy_bindings| {
                            read_hashes(cursor).and_then(
                                |[observation_value_digest, scope_union_digest, authority_request_digest]| {
                                    read_head(cursor, 0).map(|evidence_not_after_micros| {
                                        (
                                            CommunityObservationSourceInputV1 {
                                                operation_id,
                                                timeline,
                                                generation,
                                                through_seq,
                                                event_rows,
                                                reducer_policy_bindings,
                                                observation_value_digest,
                                                scope_union_digest,
                                                authority_request_digest,
                                                evidence_not_after_micros,
                                            },
                                            from_seq,
                                            set_digest,
                                        )
                                    })
                                },
                            )
                        },
                    )
                },
            )
        },
    )
}

fn read_row(cursor: &mut CborCursor<'_>) -> Result<CommunityObservationEventRowV1> {
    cursor.fixed(&[0x84]).map_err(Error::from).and_then(|()| {
        read_head(cursor, 0).and_then(|logical_seq| {
            fixed_bytes(cursor).and_then(|event_id| {
                read_hash(cursor).and_then(|payload_hash| {
                    read_typed_ref(cursor).and_then(|reference| match reference {
                        CommunityTypedInputRefV1::Artifact {
                            owner_reference,
                            artifact_class: ErasureArtifactClassV1::TimelineReplay,
                            artifact_digest,
                            registration_address,
                            source_scope_binding_digest,
                        } => Ok(CommunityObservationEventRowV1 {
                            logical_seq,
                            event_id,
                            payload_hash,
                            source: CommunityEventSourceRefV1 {
                                owner_reference,
                                artifact_digest,
                                registration_address,
                                source_scope_binding_digest,
                            },
                        }),
                        _ => Err(Error::InvalidBinding),
                    })
                })
            })
        })
    })
}

fn read_reducer(cursor: &mut CborCursor<'_>) -> Result<CommunityReducerBindingV1> {
    cursor.fixed(&[0x86]).map_err(Error::from).and_then(|()| {
        read_hashes(cursor).map(
            |[consumer_identity_digest, schema_digest, reducer_digest, configuration_digest, admission_evidence_digest, minimization_policy_digest]| {
                CommunityReducerBindingV1 {
                    consumer_identity_digest,
                    schema_digest,
                    reducer_digest,
                    configuration_digest,
                    admission_evidence_digest,
                    minimization_policy_digest,
                }
            },
        )
    })
}

/// `consumer_identity_digest` = `H("RecordedConsumer", preferred
/// [plugin_id_text, reducer_identity32])` of one `RecordedConsumerV1` (R9.4).
///
/// # Errors
/// Returns `InvalidBinding` for an empty Plugin ID or a zero identity and
/// `BoundsExceeded` for a Plugin ID over 128 bytes.
pub fn community_recorded_consumer_digest_v1(
    plugin_id: &str,
    reducer_identity: Hash,
) -> Result<Hash> {
    if plugin_id.len() > MAX_PLUGIN_ID_BYTES {
        Err(Error::BoundsExceeded)
    } else if plugin_id.is_empty() || reducer_identity == Hash::zero() {
        Err(Error::InvalidBinding)
    } else {
        let mut preimage = Vec::with_capacity(4 + MAX_PLUGIN_ID_BYTES + 34);
        preimage.push(0x82);
        encode_bytes(&mut preimage, plugin_id.as_bytes(), 3);
        encode_hash(&mut preimage, reducer_identity);
        Ok(digest(
            b"PiglorOS.Community.RecordedConsumer.v1\0",
            &preimage,
        ))
    }
}

/// `recorded_consumer_set_digest` = `H("RecordedConsumerSet", preferred
/// array of consumer_identity_digest)`, in the given (reducer-row) order.
#[must_use]
pub fn community_recorded_consumer_set_digest_v1(consumer_identities: &[Hash]) -> Hash {
    let mut preimage = Vec::with_capacity(3 + 34 * consumer_identities.len());
    encode_head(&mut preimage, 4, consumer_identities.len() as u64);
    for identity in consumer_identities {
        encode_hash(&mut preimage, *identity);
    }
    digest(b"PiglorOS.Community.RecordedConsumerSet.v1\0", &preimage)
}

/// `configuration_digest` = `H("ReducerConfiguration", c)`, with c the
/// canonical CBOR byte-string item of `configuration_details` (R9.4).
#[must_use]
pub fn community_reducer_configuration_digest_v1(configuration_details: &[u8]) -> Hash {
    let mut preimage = Zeroizing::new(Vec::with_capacity(9 + configuration_details.len()));
    encode_bytes(&mut preimage, configuration_details, 2);
    digest(b"PiglorOS.Community.ReducerConfiguration.v1\0", &preimage)
}

/// CPE1 `authority_request_digest` = `H("EventSourceAuthority", preferred
/// [[U, request_digest], ...])` over one Event-history `read` request per
/// owning Timeline U, sorted by U (R9.5).
///
/// # Errors
/// Returns `InvalidBinding` for no rows, a zero Timeline or digest, or rows
/// not strictly ascending by Timeline.
pub fn community_event_source_authority_digest_v1(rows: &[(TimelineId, Hash)]) -> Result<Hash> {
    if rows.is_empty()
        || rows.iter().any(|(timeline, request)| {
            timeline.inner().to_bytes() == [0; 16] || *request == Hash::zero()
        })
        || rows
            .windows(2)
            .any(|pair| pair[0].0.inner().to_bytes() >= pair[1].0.inner().to_bytes())
    {
        return Err(Error::InvalidBinding);
    }
    let mut preimage = Vec::with_capacity(3 + 52 * rows.len());
    encode_head(&mut preimage, 4, rows.len() as u64);
    for (timeline, request) in rows {
        preimage.push(0x82);
        encode_bytes(&mut preimage, &timeline.inner().to_bytes(), 2);
        encode_hash(&mut preimage, *request);
    }
    Ok(digest(
        b"PiglorOS.Community.EventSourceAuthority.v1\0",
        &preimage,
    ))
}

/// The materialization control identity `M_id`: the first 16 bytes of
/// `H("ObservationMaterialization", preferred [T, reservation_operation_id])`
/// (R9.7). It is the CPE1 and COV1 `operation_id`.
///
/// # Errors
/// Returns `InvalidBinding` for a zero Timeline or operation.
pub fn community_observation_materialization_id_v1(
    timeline: TimelineId,
    reservation_operation_id: [u8; 16],
) -> Result<[u8; 16]> {
    if timeline.inner().to_bytes() == [0; 16] || reservation_operation_id == [0; 16] {
        return Err(Error::InvalidBinding);
    }
    let mut preimage = Vec::with_capacity(35);
    preimage.push(0x82);
    encode_bytes(&mut preimage, &timeline.inner().to_bytes(), 2);
    encode_bytes(&mut preimage, &reservation_operation_id, 2);
    let full = digest(
        b"PiglorOS.Community.ObservationMaterialization.v1\0",
        &preimage,
    );
    let mut id = [0; 16];
    id.copy_from_slice(&full.as_bytes()[..16]);
    Ok(id)
}
