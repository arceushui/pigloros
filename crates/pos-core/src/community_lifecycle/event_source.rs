//! ADR-129 §4 CES1 source-owner Event binding (revision 9, R9.1).
//!
//! CES1 binds one committed Event to the classification, scope and key facts
//! its installed source owner derives through the pinned source catalogue. A
//! materialization row names it by a mode-2 typed reference. Valid bytes do
//! not prove that the Event exists, that the owner derived these facts or
//! that the schema rule is a row of the pinned catalogue: the store re-checks
//! each of them before it mints a CES1.

use super::guest_error::is_valid_community_id_v1;
use super::{
    bounded_text, canonical_end, digest, fixed_bytes, read_hash, read_head, read_vec,
    record_cursor, record_prefix, validate_horizon, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::erasure::encode_artifact_key_dependency;
use crate::{
    encode_bytes, encode_hash, encode_head, ArtifactKeyDependencyV1, CborCursor, Hash,
    KeyIdentityV1, KeyRoleV1, OwnerIdV1, TimelineId,
};
use zeroize::Zeroizing;

/// Maximum canonical CES1 encoding.
pub const MAX_COMMUNITY_EVENT_SOURCE_BYTES_V1: usize = 1_048_576;
/// Maximum key dependencies of one CES1, the ARD1 registration-key bound.
pub const MAX_COMMUNITY_EVENT_SOURCE_KEYS_V1: usize = crate::MAX_ARTIFACT_REGISTRATION_KEYS_V1;
/// Maximum bytes of each CES1 schema-rule text.
pub const MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1: usize = 128;
/// Encoding capacity of a typical CES1: framing and the fixed fields fit in
/// 512 bytes, and each key dependency in 177 (head 1, owner 130, role 2,
/// epoch 9, material 34, flag 1).
const FIXED_CAPACITY: usize = 512;
const KEY_CAPACITY: usize = 177;

/// `[event_type, schema_version, extractor_rule, extractor_rule_version]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunitySourceSchemaRuleV1<'a> {
    /// The Event's own type, 1..=128 bytes.
    pub event_type: &'a str,
    /// The Event's own schema version.
    pub schema_version: u32,
    /// Extractor rule, 1..=128 bytes in the `valid_id_text` grammar.
    pub extractor_rule: &'a str,
    /// Extractor rule version.
    pub extractor_rule_version: u32,
}

impl CommunitySourceSchemaRuleV1<'_> {
    fn validate(self) -> Result<()> {
        if self.event_type.len() > MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1
            || self.extractor_rule.len() > MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1
        {
            Err(Error::BoundsExceeded)
        } else if self.event_type.is_empty() || !is_valid_community_id_v1(self.extractor_rule) {
            Err(Error::InvalidBinding)
        } else {
            Ok(())
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.push(0x84);
        encode_bytes(out, self.event_type.as_bytes(), 3);
        encode_head(out, 0, u64::from(self.schema_version));
        encode_bytes(out, self.extractor_rule.as_bytes(), 3);
        encode_head(out, 0, u64::from(self.extractor_rule_version));
    }
}

/// Untrusted CES1 fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityEventSourceInputV1<'a> {
    /// The Event's owning Timeline.
    pub timeline: TimelineId,
    /// The Event's positive sequence on its owning Timeline.
    pub logical_seq: u64,
    /// Committed Event identity.
    pub event_id: [u8; 16],
    /// Committed payload hash.
    pub payload_hash: Hash,
    /// Authenticated Event envelope identity.
    pub event_envelope_digest: Hash,
    /// Source owner reference.
    pub owner_reference: Hash,
    /// Source scope binding the owner derives.
    pub source_scope_binding_digest: Hash,
    /// Pinned schema and extractor rule.
    pub source_schema_rule: CommunitySourceSchemaRuleV1<'a>,
    /// The exact ARD1 key dependencies of the source, strictly ascending by
    /// identity, with nonzero epochs, at most 2,048.
    pub required_key_dependencies: Vec<ArtifactKeyDependencyV1>,
    /// Admitted source policy identity.
    pub admitted_policy_digest: Hash,
    /// Fixed positive horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact thirteen-field CES1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityEventSourceV1<'a>(CommunityEventSourceInputV1<'a>);

impl<'a> CommunityEventSourceV1<'a> {
    /// Validate identities, the schema-rule texts and the key list.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero Timeline, sequence, Event ID or
    /// digest, an empty Event type, an extractor rule outside the ID grammar
    /// and an unsorted, repeated or epoch-0 key dependency; `BoundsExceeded`
    /// for a text over 128 bytes, more than 2,048 keys or an invalid horizon.
    pub fn new(input: CommunityEventSourceInputV1<'a>) -> Result<Self> {
        if input.timeline.inner().to_bytes() == [0; 16]
            || input.logical_seq == 0
            || input.event_id == [0; 16]
            || [
                input.payload_hash,
                input.event_envelope_digest,
                input.owner_reference,
                input.source_scope_binding_digest,
                input.admitted_policy_digest,
            ]
            .contains(&Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        input
            .source_schema_rule
            .validate()
            .and_then(|()| validate_keys(&input.required_key_dependencies))
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving the Event or its owner.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityEventSourceInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CES1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(
            FIXED_CAPACITY + KEY_CAPACITY * input.required_key_dependencies.len(),
        ));
        record_prefix(&mut out, 13, *b"CES1");
        encode_bytes(&mut out, &input.timeline.inner().to_bytes(), 2);
        encode_head(&mut out, 0, input.logical_seq);
        encode_bytes(&mut out, &input.event_id, 2);
        for hash in [
            input.payload_hash,
            input.event_envelope_digest,
            input.owner_reference,
            input.source_scope_binding_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        input.source_schema_rule.encode(&mut out);
        encode_head(&mut out, 4, input.required_key_dependencies.len() as u64);
        for dependency in &input.required_key_dependencies {
            encode_artifact_key_dependency(&mut out, dependency);
        }
        encode_hash(&mut out, input.admitted_policy_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// `H(CES1)`, the `BLAKE3("PiglorOS.Community.CES1.v1\0" || CES1)` artifact
    /// digest a mode-2 row reference names.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CES1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CES1, borrowing its texts.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records, an unknown key role or invalid owner text, and every invalid
    /// local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_COMMUNITY_EVENT_SOURCE_BYTES_V1, 13, *b"CES1").and_then(
            |mut cursor| {
                read_source(&mut cursor)
                    .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
            },
        )
    }
}

fn validate_keys(keys: &[ArtifactKeyDependencyV1]) -> Result<()> {
    if keys.len() > MAX_COMMUNITY_EVENT_SOURCE_KEYS_V1 {
        Err(Error::BoundsExceeded)
    } else if keys.iter().any(|key| key.identity.epoch == 0)
        || keys
            .windows(2)
            .any(|pair| pair[0].identity >= pair[1].identity)
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

fn read_source<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityEventSourceInputV1<'a>> {
    let head = fixed_bytes(cursor).and_then(|timeline| {
        read_head(cursor, 0).and_then(|logical_seq| {
            fixed_bytes(cursor).and_then(|event_id| {
                super::read_hashes(cursor).map(|hashes| {
                    (
                        TimelineId::from_ulid(ulid::Ulid::from_bytes(timeline)),
                        logical_seq,
                        event_id,
                        hashes,
                    )
                })
            })
        })
    });
    head.and_then(
        |(
            timeline,
            logical_seq,
            event_id,
            [payload_hash, event_envelope_digest, owner_reference, source_scope_binding_digest],
        )| {
            read_rule(cursor).and_then(|source_schema_rule| {
                read_vec(cursor, MAX_COMMUNITY_EVENT_SOURCE_KEYS_V1, read_key).and_then(
                    |required_key_dependencies| {
                        read_hash(cursor).and_then(|admitted_policy_digest| {
                            read_head(cursor, 0).map(|evidence_not_after_micros| {
                                CommunityEventSourceInputV1 {
                                    timeline,
                                    logical_seq,
                                    event_id,
                                    payload_hash,
                                    event_envelope_digest,
                                    owner_reference,
                                    source_scope_binding_digest,
                                    source_schema_rule,
                                    required_key_dependencies,
                                    admitted_policy_digest,
                                    evidence_not_after_micros,
                                }
                            })
                        })
                    },
                )
            })
        },
    )
}

fn read_rule<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunitySourceSchemaRuleV1<'a>> {
    cursor.fixed(&[0x84]).map_err(Error::from).and_then(|()| {
        bounded_text(cursor, MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1).and_then(|event_type| {
            read_u32(cursor).and_then(|schema_version| {
                bounded_text(cursor, MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1).and_then(
                    |extractor_rule| {
                        read_u32(cursor).map(|extractor_rule_version| CommunitySourceSchemaRuleV1 {
                            event_type,
                            schema_version,
                            extractor_rule,
                            extractor_rule_version,
                        })
                    },
                )
            })
        })
    })
}

/// One ARD1 key dependency `[owner_text, role, epoch, material_digest,
/// private_material_required]`.
fn read_key(cursor: &mut CborCursor<'_>) -> Result<ArtifactKeyDependencyV1> {
    cursor.fixed(&[0x85]).map_err(Error::from).and_then(|()| {
        bounded_text(cursor, MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1)
            .and_then(|owner| OwnerIdV1::new(owner).map_err(|_| Error::InvalidEncoding))
            .and_then(|owner_id| {
                read_head(cursor, 0)
                    .and_then(|code| {
                        u8::try_from(code)
                            .ok()
                            .and_then(|code| KeyRoleV1::from_code(code).ok())
                            .ok_or(Error::InvalidEncoding)
                    })
                    .and_then(|role| {
                        read_head(cursor, 0).and_then(|epoch| {
                            read_hash(cursor).and_then(|material_digest| {
                                read_flag(cursor).map(|private_material_required| {
                                    ArtifactKeyDependencyV1 {
                                        identity: KeyIdentityV1::from_parts(owner_id, role, epoch),
                                        material_digest,
                                        private_material_required,
                                    }
                                })
                            })
                        })
                    })
            })
    })
}

fn read_flag(cursor: &mut CborCursor<'_>) -> Result<bool> {
    if cursor.consume_if(0xf5) {
        Ok(true)
    } else {
        cursor.fixed(&[0xf4]).map_err(Error::from).map(|()| false)
    }
}

fn read_u32(cursor: &mut CborCursor<'_>) -> Result<u32> {
    read_head(cursor, 0).and_then(|value| u32::try_from(value).map_err(|_| Error::BoundsExceeded))
}

/// The one V1 extractor rule: a plaintext native Event of whole-Timeline
/// scope with no key dependencies (owner 2026-11-21 (#560), item (f)).
pub const COMMUNITY_NATIVE_EVENT_EXTRACTOR_RULE_V1: (&str, u32) = ("pos.community.native-event", 1);

/// Maximum rows of the installed source catalogue (owner 2026-11-21, #560).
pub const MAX_COMMUNITY_SOURCE_CATALOGUE_ROWS_V1: usize = 4096;

/// The closed installed source catalogue whose digest is the CDP1
/// `source_catalogue_digest` (owner 2026-11-21 (#560), item (f)).
///
/// Rows are `[event_type, schema_version, extractor_rule, rule_version]`,
/// strictly ascending and unique by `(event_type bytes, schema_version)`.
/// The deployment lists its Event types at the composition root; none is
/// pinned by default.
#[derive(Clone, Copy)]
pub struct CommunitySourceCatalogueV1<'a>(&'a [CommunitySourceSchemaRuleV1<'a>]);

impl<'a> CommunitySourceCatalogueV1<'a> {
    /// Validate every row and the strict `(event_type, schema_version)` order.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for more than 4,096 rows, the row errors of
    /// [`CommunitySourceSchemaRuleV1`], and `InvalidBinding` for unsorted or
    /// repeated `(event_type, version)` keys.
    pub fn new(rows: &'a [CommunitySourceSchemaRuleV1<'a>]) -> Result<Self> {
        if rows.len() > MAX_COMMUNITY_SOURCE_CATALOGUE_ROWS_V1 {
            return Err(Error::BoundsExceeded);
        }
        rows.iter()
            .try_for_each(|row| row.validate())
            .and_then(|()| {
                if rows.windows(2).any(|pair| {
                    (pair[0].event_type.as_bytes(), pair[0].schema_version)
                        >= (pair[1].event_type.as_bytes(), pair[1].schema_version)
                }) {
                    Err(Error::InvalidBinding)
                } else {
                    Ok(Self(rows))
                }
            })
    }

    /// `BLAKE3("PiglorOS.Community.SourceCatalogue.v1\0" || preferred array
    /// of rows)`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut preimage = Vec::with_capacity(9 + 280 * self.0.len());
        encode_head(&mut preimage, 4, self.0.len() as u64);
        for row in self.0 {
            row.encode(&mut preimage);
        }
        digest(b"PiglorOS.Community.SourceCatalogue.v1\0", &preimage)
    }

    /// The pinned row of one Event's `(event_type, schema_version)`, if any.
    #[must_use]
    pub fn rule(
        &self,
        event_type: &str,
        schema_version: u32,
    ) -> Option<CommunitySourceSchemaRuleV1<'a>> {
        self.0
            .binary_search_by(|row| {
                (row.event_type.as_bytes(), row.schema_version)
                    .cmp(&(event_type.as_bytes(), schema_version))
            })
            .ok()
            .map(|index| self.0[index])
    }
}
