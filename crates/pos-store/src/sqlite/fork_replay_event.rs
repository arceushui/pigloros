//! Bounded actual Event getters and parent hash inputs in the held snapshot.

use pos_core::{
    CoreError, Event, ForkAdmissionErrorV1 as Error, ForkAppendOperationV1, Hash, Seq, TimelineId,
};
use rusqlite::{types::FromSql, Connection, Row, Rows, Statement};
use zeroize::{Zeroize, Zeroizing};

use super::{
    fork_replay_chain::{chain_with_context, logical_head_from_chain},
    fork_replay_row::{selected_field_with_context, SelectedRowV1},
    fork_segment_length, BoundedForkSegment, Hasher,
};
use crate::fork_replay::NativeReadContextV1;

type Result<T> = std::result::Result<T, Error>;

// The outer scalar row exists even at EOF. It is real query work, not a
// phantom stored Event. Each Event costs one scalar probe and one raw row;
// exhausting a segment costs one final scalar probe. All seeks use the pinned
// (timeline_id, seq) primary key and a closed, non-nullable range predicate.
macro_rules! event_probe_sql {
    ($range:literal) => {
        concat!(
            "SELECT probe.* FROM (SELECT 1) AS boundary LEFT JOIN (
             SELECT seq,
                typeof(seq) = 'integer' AND typeof(wall_time) = 'integer'
                AND typeof(schema_version) = 'integer'
                AND typeof(signature_role) IN ('null', 'integer')
                AND typeof(signature_epoch) IN ('null', 'integer')
                AND typeof(origin_logical_seq) = 'integer',
                typeof(event_id) = 'text', length(CAST(event_id AS BLOB)),
                typeof(entity_id) = 'text', length(CAST(entity_id AS BLOB)),
                typeof(event_type) = 'text', length(CAST(event_type AS BLOB)),
                typeof(payload) = 'blob', length(payload),
                typeof(causation_id) IN ('null', 'text'), length(CAST(causation_id AS BLOB)),
                typeof(correlation_id) IN ('null', 'text'), length(CAST(correlation_id AS BLOB)),
                typeof(payload_hash) = 'blob', length(payload_hash),
                typeof(signature) IN ('null', 'blob'), length(signature),
                typeof(signature_owner_id) IN ('null', 'text'), length(CAST(signature_owner_id AS BLOB)),
                typeof(origin_timeline_id) = 'text', length(CAST(origin_timeline_id AS BLOB))
             FROM events WHERE timeline_id = ?1 AND ",
            $range,
            " ORDER BY seq ASC LIMIT 1) AS probe ON 1 = 1"
        )
    };
}

const FIRST_OPEN: &str = event_probe_sql!("seq >= 0");
const FIRST_CAPPED: &str = event_probe_sql!("seq >= 0 AND seq <= ?2");
const AFTER_OPEN: &str = event_probe_sql!("seq > ?2");
const AFTER_CAPPED: &str = event_probe_sql!("seq > ?2 AND seq <= ?3");
pub(super) const EXACT_EVENT: &str = event_probe_sql!("seq = ?2");

#[derive(Clone, Copy)]
pub(super) struct EventCursorV1 {
    after: Option<i64>,
    to: Option<i64>,
}

impl EventCursorV1 {
    pub(super) const fn sql(self) -> &'static str {
        match (self.after, self.to) {
            (None, None) => FIRST_OPEN,
            (None, Some(_)) => FIRST_CAPPED,
            (Some(_), None) => AFTER_OPEN,
            (Some(_), Some(_)) => AFTER_CAPPED,
        }
    }

    pub(super) fn query<'statement>(
        self,
        statement: &'statement mut Statement<'_>,
        key: &str,
    ) -> rusqlite::Result<Rows<'statement>> {
        match (self.after, self.to) {
            (None, None) => statement.query([key]),
            (None, Some(to)) => statement.query(rusqlite::params![key, to]),
            (Some(after), None) => statement.query(rusqlite::params![key, after]),
            (Some(after), Some(to)) => statement.query(rusqlite::params![key, after, to]),
        }
    }
}

#[derive(Clone, Copy)]
enum FieldWidthV1 {
    Fixed(usize),
    Owner,
    Variable,
}

#[derive(Clone, Copy)]
struct VariableFieldV1 {
    value_column: usize,
    type_column: usize,
    length_column: usize,
    width: FieldWidthV1,
}

const VARIABLE_FIELDS: [VariableFieldV1; 10] = [
    VariableFieldV1 {
        value_column: 1,
        type_column: 2,
        length_column: 3,
        width: FieldWidthV1::Fixed(ulid::ULID_LEN),
    },
    VariableFieldV1 {
        value_column: 2,
        type_column: 4,
        length_column: 5,
        width: FieldWidthV1::Fixed(ulid::ULID_LEN),
    },
    VariableFieldV1 {
        value_column: 3,
        type_column: 6,
        length_column: 7,
        width: FieldWidthV1::Variable,
    },
    VariableFieldV1 {
        value_column: 4,
        type_column: 8,
        length_column: 9,
        width: FieldWidthV1::Variable,
    },
    VariableFieldV1 {
        value_column: 6,
        type_column: 10,
        length_column: 11,
        width: FieldWidthV1::Fixed(ulid::ULID_LEN),
    },
    VariableFieldV1 {
        value_column: 7,
        type_column: 12,
        length_column: 13,
        width: FieldWidthV1::Fixed(ulid::ULID_LEN),
    },
    VariableFieldV1 {
        value_column: 9,
        type_column: 14,
        length_column: 15,
        width: FieldWidthV1::Fixed(32),
    },
    VariableFieldV1 {
        value_column: 10,
        type_column: 16,
        length_column: 17,
        width: FieldWidthV1::Fixed(64),
    },
    VariableFieldV1 {
        value_column: 11,
        type_column: 18,
        length_column: 19,
        width: FieldWidthV1::Owner,
    },
    VariableFieldV1 {
        value_column: 14,
        type_column: 20,
        length_column: 21,
        width: FieldWidthV1::Fixed(ulid::ULID_LEN),
    },
];

/// Fixed scalar metadata for the next actual row, not an Event representation.
pub(super) struct EventRowLengthsV1 {
    seq: i64,
    columns: [usize; 16],
}

impl EventRowLengthsV1 {
    fn probe(row: &Row<'_>) -> Result<Option<Self>> {
        row.get::<_, Option<i64>>(0)
            .map_err(|_| Error::StorageIndeterminate)
            .and_then(|seq| {
                seq.map(|seq| {
                    row.get::<_, bool>(1)
                        .map_err(|_| Error::StorageIndeterminate)
                        .and_then(|scalar_types| {
                            if !scalar_types {
                                return Err(Error::StorageIndeterminate);
                            }
                            VARIABLE_FIELDS.iter().try_fold(
                                Self {
                                    seq,
                                    columns: [0; 16],
                                },
                                |mut lengths, field| {
                                    field.length(row).map(|length| {
                                        lengths.columns[field.value_column] = length;
                                        lengths
                                    })
                                },
                            )
                        })
                })
                .transpose()
            })
    }

    fn total(&self) -> Option<usize> {
        self.columns
            .iter()
            .try_fold(0_usize, |sum, length| sum.checked_add(*length))
    }
}

impl VariableFieldV1 {
    fn length(self, row: &Row<'_>) -> Result<usize> {
        row.get::<_, bool>(self.type_column)
            .map_err(|_| Error::StorageIndeterminate)
            .and_then(|valid_type| {
                if !valid_type {
                    return Err(Error::StorageIndeterminate);
                }
                row.get::<_, Option<i64>>(self.length_column)
                    .map_err(|_| Error::StorageIndeterminate)
                    .and_then(|length| {
                        length.map_or(Ok(0), |length| {
                            usize::try_from(length)
                                .map_err(|_| Error::CorruptAuthority)
                                .and_then(|length| {
                                    let valid = match self.width {
                                        FieldWidthV1::Fixed(width) => length == width,
                                        // Same 1..=128-byte contract as OwnerIdV1::new.
                                        FieldWidthV1::Owner => (1..=128).contains(&length),
                                        FieldWidthV1::Variable => true,
                                    };
                                    if valid {
                                        Ok(length)
                                    } else {
                                        Err(Error::CorruptAuthority)
                                    }
                                })
                        })
                    })
            })
    }
}

/// Ordinary and protected callers use the same semantic decoder. Only this
/// private getter seam distinguishes a borrowed ledger from ordinary reads.
pub(super) struct EventRowReaderV1<'read, 'statement, 'budget, 'clock> {
    row: &'read Row<'statement>,
    context: &'read mut NativeReadContextV1<'budget, 'clock>,
    lengths: Option<&'read EventRowLengthsV1>,
}

impl<'read, 'statement, 'budget, 'clock> EventRowReaderV1<'read, 'statement, 'budget, 'clock> {
    pub(super) const fn new(
        row: &'read Row<'statement>,
        context: &'read mut NativeReadContextV1<'budget, 'clock>,
        lengths: Option<&'read EventRowLengthsV1>,
    ) -> Self {
        Self {
            row,
            context,
            lengths,
        }
    }

    fn before(&mut self, column: usize) -> std::result::Result<(), CoreError> {
        self.context
            .check()
            .map_err(|_| CoreError::ArtifactUnavailable)
            .and_then(|()| {
                self.lengths.map_or(Ok(()), |lengths| {
                    self.context
                        .bytes(lengths.columns[column])
                        .map_err(|_| CoreError::ArtifactUnavailable)
                })
            })
    }

    fn storage(&self, error: &rusqlite::Error) -> CoreError {
        if self.context.is_protected() {
            CoreError::ArtifactUnavailable
        } else {
            CoreError::Storage(error.to_string())
        }
    }

    pub(super) fn serialization(&self, message: &str) -> CoreError {
        if self.context.is_protected() {
            CoreError::ArtifactUnavailable
        } else {
            CoreError::Serialization(message.to_owned())
        }
    }

    pub(super) fn parse_ulid(&self, text: &str) -> std::result::Result<ulid::Ulid, CoreError> {
        text.parse().map_err(|_| {
            if self.context.is_protected() {
                CoreError::ArtifactUnavailable
            } else {
                CoreError::Serialization(format!("invalid ULID: {text}"))
            }
        })
    }

    pub(super) fn get<T: FromSql>(&mut self, column: usize) -> std::result::Result<T, CoreError> {
        self.before(column)
            .and_then(|()| self.row.get(column).map_err(|error| self.storage(&error)))
            .and_then(|value| {
                self.context
                    .check()
                    .map(|()| value)
                    .map_err(|_| CoreError::ArtifactUnavailable)
            })
    }

    pub(super) fn plaintext<T: FromSql + Zeroize>(
        &mut self,
        column: usize,
    ) -> std::result::Result<Zeroizing<T>, CoreError> {
        self.before(column)
            .and_then(|()| {
                self.row
                    .get(column)
                    .map(Zeroizing::new)
                    .map_err(|error| self.storage(&error))
            })
            .and_then(|value| {
                // Own the zeroizing guard before a post-fetch time check can fail.
                self.context
                    .check()
                    .map(|()| value)
                    .map_err(|_| CoreError::ArtifactUnavailable)
            })
    }
}

pub(super) struct ScopedEventV1(Event);

impl ScopedEventV1 {
    pub(super) const fn new(event: Event) -> Self {
        Self(event)
    }

    pub(super) const fn event(&self) -> &Event {
        &self.0
    }
}

impl Drop for ScopedEventV1 {
    fn drop(&mut self) {
        let scrubbed =
            pos_core::store::zeroize_event_plaintext_staging(std::slice::from_mut(&mut self.0));
        debug_assert!(scrubbed);
    }
}

struct ParentHashStateV1 {
    seen: u64,
    hash: Hash,
    at: Seq,
}

impl ParentHashStateV1 {
    fn observe(&mut self) -> Result<bool> {
        self.seen
            .checked_add(1)
            .ok_or(Error::CorruptAuthority)
            .map(|seen| {
                self.seen = seen;
                seen <= self.at.as_u64()
            })
    }

    fn hash_event(
        &mut self,
        hasher: &dyn Hasher,
        event: &Event,
        context: &mut NativeReadContextV1<'_, '_>,
    ) -> Result<()> {
        self.observe().and_then(|selected| {
            if !selected {
                return Ok(());
            }
            context
                .bytes(event.payload.len())
                .map_err(|_| Error::CorruptAuthority)
                .and_then(|()| {
                    context
                        .bytes(ulid::ULID_LEN)
                        .map_err(|_| Error::CorruptAuthority)
                })
                .and_then(|()| {
                    let id = event.id.to_string();
                    context
                        .check()
                        .map_err(|_| Error::CorruptAuthority)
                        .and_then(|()| {
                            self.hash =
                                hasher.hash_event(&self.hash, id.as_bytes(), &event.payload);
                            context.check().map_err(|_| Error::CorruptAuthority)
                        })
                })
        })
    }
}

fn read_probed_event(
    conn: &Connection,
    key: &str,
    lengths: &EventRowLengthsV1,
    timeline: TimelineId,
    prefix: u64,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<ScopedEventV1> {
    context
        .require_bytes(lengths.total())
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            selected_field_with_context(
                conn,
                SelectedRowV1::EventFields(key, lengths.seq),
                context,
                |row, context| {
                    let mut reader = EventRowReaderV1::new(row, context, Some(lengths));
                    super::decode_event_row_with_reader(&mut reader)
                        .and_then(|event| super::finalize_sqlite_own_event(event, timeline, prefix))
                        .map(ScopedEventV1::new)
                        .map_err(|_| Error::CorruptAuthority)
                },
            )
            .and_then(|event| event.ok_or(Error::CorruptAuthority))
        })
}

/// Read only the prefix the existing own-Event decoder consumes. This is one
/// actual metadata visit, not an ancestry walk: parent/name/head must not add
/// stronger validation to this lookup. No variable-width field is fetched.
pub(super) fn origin_prefix_with_context(
    conn: &Connection,
    timeline: TimelineId,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<u64> {
    context
        .node(0)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            context
                .bytes(ulid::ULID_LEN)
                .map_err(|_| Error::CorruptAuthority)
        })
        .and_then(|()| {
            let key = timeline.to_string();
            selected_field_with_context(
                conn,
                SelectedRowV1::OriginPrefix(&key),
                context,
                |row, _| {
                    row.get::<_, Option<i64>>(0)
                        .map_err(|_| Error::StorageIndeterminate)
                        .and_then(|fork| {
                            super::sqlite_fork_prefix(fork).map_err(|_| Error::CorruptAuthority)
                        })
                },
            )
            .and_then(|prefix| prefix.ok_or(Error::CorruptAuthority))
        })
}

/// Reuse the ordinary classified-Event semantic decoder without collecting a
/// Vec or releasing plaintext. The caller retains this scrub-on-drop owner
/// while it validates provenance in the same already-held snapshot.
pub(super) fn classified_event_with_context(
    conn: &Connection,
    operation: &ForkAppendOperationV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> std::result::Result<ScopedEventV1, crate::ForkEventAuthorityErrorV1> {
    let input = operation.input();
    origin_prefix_with_context(conn, input.child_timeline_id, context)
        .and_then(|prefix| {
            input
                .logical_seq
                .checked_sub(prefix)
                .ok_or(Error::CorruptAuthority)
                .map(|local| (prefix, super::seq_as_i64(Seq::from_u64(local))))
        })
        .and_then(|(prefix, local)| {
            context
                .bytes(ulid::ULID_LEN)
                .map_err(|_| Error::CorruptAuthority)
                .and_then(|()| {
                    let key = input.child_timeline_id.to_string();
                    selected_field_with_context(
                        conn,
                        SelectedRowV1::ClassifiedEventProbe(&key, local),
                        context,
                        |row, _| EventRowLengthsV1::probe(row),
                    )
                    .and_then(|probe| probe.flatten().ok_or(Error::CorruptAuthority))
                    .and_then(|lengths| {
                        read_probed_event(
                            conn,
                            &key,
                            &lengths,
                            input.child_timeline_id,
                            prefix,
                            context,
                        )
                    })
                    .and_then(|mut event| {
                        prefix
                            .checked_add(event.0.seq.as_u64())
                            .ok_or(Error::CorruptAuthority)
                            .and_then(|logical| {
                                event.0.seq = Seq::from_u64(logical);
                                if event.0.id == input.event_id && logical == input.logical_seq {
                                    context
                                        .check()
                                        .map(|()| event)
                                        .map_err(|_| Error::CorruptAuthority)
                                } else {
                                    Err(Error::CorruptAuthority)
                                }
                            })
                    })
                })
        })
        .map_err(|_| crate::ForkEventAuthorityErrorV1::CorruptAuthority)
}

fn next_event(
    conn: &Connection,
    key: &str,
    cursor: EventCursorV1,
    segment: &BoundedForkSegment,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<Option<(i64, ScopedEventV1)>> {
    selected_field_with_context(
        conn,
        SelectedRowV1::EventProbe(key, cursor),
        context,
        |row, _| EventRowLengthsV1::probe(row),
    )
    .and_then(|probe| probe.ok_or(Error::StorageIndeterminate))
    .and_then(|probe| {
        probe.map_or_else(
            || Ok(None),
            |lengths| {
                read_probed_event(
                    conn,
                    key,
                    &lengths,
                    segment.id,
                    segment.fork.map_or(0, Seq::as_u64),
                    context,
                )
                .map(|event| Some((lengths.seq, event)))
            },
        )
    })
}

fn hash_segment(
    conn: &Connection,
    hasher: &dyn Hasher,
    segment: &BoundedForkSegment,
    to: Option<i64>,
    state: &mut ParentHashStateV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> Result<()> {
    context
        .bytes(ulid::ULID_LEN)
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            let key = segment.id.to_string();
            let mut cursor = EventCursorV1 { after: None, to };
            loop {
                match next_event(conn, &key, cursor, segment, context) {
                    Ok(Some((seq, event))) => {
                        let result = state.hash_event(hasher, &event.0, context);
                        // Preserve full validation after at_seq. Scrub before
                        // the post-batch check; no Event clone or Vec escapes.
                        drop(event);
                        match result
                            .and_then(|()| context.check().map_err(|_| Error::CorruptAuthority))
                        {
                            Ok(()) => cursor.after = Some(seq),
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(None) => return context.check().map_err(|_| Error::CorruptAuthority),
                    Err(error) => return Err(error),
                }
            }
        })
}

pub(super) fn chain_hash_with_context(
    conn: &Connection,
    hasher: &dyn Hasher,
    timeline: TimelineId,
    at_seq: Seq,
    context: &mut NativeReadContextV1<'_, '_>,
) -> std::result::Result<Hash, CoreError> {
    chain_with_context(conn, timeline, context)
        .map_err(|_| CoreError::ArtifactUnavailable)
        .and_then(|chain| {
            logical_head_from_chain(&chain, context)
                .map_err(|_| CoreError::ArtifactUnavailable)
                .map(|head| (chain, head))
        })
        .and_then(|(chain, head)| {
            if at_seq > head {
                return Err(CoreError::ForkBeyondHead {
                    fork_seq: at_seq.as_u64(),
                    head: head.as_u64(),
                });
            }
            context
                .check()
                .map_err(|_| CoreError::ArtifactUnavailable)
                .and_then(|()| {
                    let mut state = ParentHashStateV1 {
                        seen: 0,
                        hash: hasher.genesis_hash(),
                        at: at_seq,
                    };
                    let validation = if at_seq == Seq::ZERO {
                        Ok(())
                    } else {
                        chain.iter().enumerate().try_for_each(|(index, segment)| {
                            chain
                                .get(index + 1)
                                .and_then(|next| next.fork)
                                .map(|cut| {
                                    fork_segment_length(
                                        segment.fork.map_or(0, Seq::as_u64),
                                        segment.head,
                                        Some(cut.as_u64()),
                                    )
                                    .map(super::u64_as_i64)
                                    .map_err(|_| CoreError::ArtifactUnavailable)
                                })
                                .transpose()
                                .and_then(|to| {
                                    hash_segment(conn, hasher, segment, to, &mut state, context)
                                        .map_err(|_| CoreError::ArtifactUnavailable)
                                })
                        })
                    };
                    validation.and_then(|()| {
                        context
                            .check()
                            .map(|()| state.hash)
                            .map_err(|_| CoreError::ArtifactUnavailable)
                    })
                })
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::{
        store::{EventStore, SeqRange},
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        CanonicalBytes, EntityId, EventDraft, KeyIdentityV1, KeyRoleV1, Kind, Signature,
    };
    use rusqlite::{params, types::Value};
    use std::{sync::Arc, time::Duration};

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn append(
        store: &mut super::super::SqliteStore,
        timeline: TimelineId,
        count: usize,
    ) -> Fallible<()> {
        let drafts: Vec<_> = (0..count)
            .map(|index| {
                EventDraft::new(
                    EntityId::new(),
                    Kind::new("parent.\0é"),
                    CanonicalBytes::from_vec(vec![0x41, u8::try_from(index).unwrap_or_default()]),
                )
            })
            .collect();
        store.append(timeline, &drafts)?;
        Ok(())
    }

    fn fixture() -> Fallible<(
        tempfile::TempDir,
        super::super::SqliteStore,
        [TimelineId; 3],
    )> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("parent-events.sqlite3");
        let mut store =
            super::super::SqliteStore::open(path.to_str().ok_or("Event fixture path")?)?;
        // Public structural setup, not minted FCC/protected-use authority.
        store.bind_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()))?;
        let root = store.create_timeline("root")?.id();
        append(&mut store, root, 3)?;
        let child = store.fork(root, Seq::from_u64(2), "child")?.id();
        append(&mut store, child, 2)?;
        let grandchild = store.fork(child, Seq::from_u64(4), "grandchild")?.id();
        append(&mut store, grandchild, 1)?;
        Ok((directory, store, [root, child, grandchild]))
    }

    fn raw_cost(event: &Event) -> usize {
        // Independent inventory of the actual SQLite String/Vec getters.
        event.id.to_string().len()
            + event.entity.to_string().len()
            + event.event_type.as_str().len()
            + event.payload.len()
            + event.causation_id.map_or(0, |id| id.to_string().len())
            + event.correlation_id.map_or(0, |id| id.to_string().len())
            + event.payload_hash.as_bytes().len()
            + event.signature.map_or(0, |_| 64)
            + event
                .signature_identity
                .map_or(0, |identity| identity.owner_id.as_str().len())
            + event
                .origin
                .map_or(0, |origin| origin.origin_timeline_id.to_string().len())
    }

    fn cost(ids: &[TimelineId], events: &[Event], at: u64) -> Fallible<usize> {
        let ancestry: usize = ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                16 + id.to_string().len()
                    + 16
                    + 8
                    + if index == 0 {
                        0
                    } else {
                        ids[index - 1].to_string().len() + 8
                    }
            })
            .sum();
        let hash_inputs: usize = events
            .iter()
            .take(usize::try_from(at)?)
            .map(|event| event.id.to_string().len() + event.payload.len())
            .sum();
        Ok(ancestry
            + ids.iter().map(|id| id.to_string().len()).sum::<usize>()
            + events.iter().map(raw_cost).sum::<usize>()
            + hash_inputs)
    }

    fn protected_hash(
        store: &super::super::SqliteStore,
        timeline: TimelineId,
        at: u64,
        limits: ForkReplayReadLimitsV1,
    ) -> Fallible<(std::result::Result<Hash, CoreError>, usize, bool)> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let result = super::super::SqliteStore::compute_chain_hash_at_with_context_on(
            &store.conn,
            store.hasher.as_ref(),
            timeline,
            Seq::from_u64(at),
            &mut NativeReadContextV1::protected(&mut budget),
        );
        Ok((
            result,
            budget.remaining_native_bytes(),
            budget.check_time().is_ok(),
        ))
    }

    #[test]
    fn actual_file_backed_parent_events_and_hash_inputs_have_exact_byte_prefixes() -> Fallible<()> {
        let (_directory, store, ids) = fixture()?;
        store.conn.execute_batch("BEGIN IMMEDIATE")?;
        for count in 1..=ids.len() {
            let timeline = ids[count - 1];
            let events = store.read(timeline, SeqRange::all())?;
            for at in [1, u64::try_from(events.len())?] {
                let expected = cost(&ids[..count], &events, at)?;
                let rows = count * 3 + events.len() * 2;
                let ordinary = store.compute_chain_hash_at(timeline, Seq::from_u64(at))?;
                for bytes in 1..=expected {
                    let limits =
                        ForkReplayReadLimitsV1::new(count.max(1), count, rows, bytes, 1_000_000)?;
                    let (result, remaining, open) = protected_hash(&store, timeline, at, limits)?;
                    if bytes == expected {
                        assert_eq!(result?, ordinary);
                        assert_eq!(remaining, 0);
                        assert!(open);
                    } else {
                        assert!(matches!(result, Err(CoreError::ArtifactUnavailable)));
                        assert!(!open);
                    }
                    assert!(!store.conn.is_autocommit());
                }
            }
        }
        store.conn.execute_batch("ROLLBACK")?;
        Ok(())
    }

    #[test]
    fn actual_event_rows_eof_probes_and_repeated_walks_share_one_ledger() -> Fallible<()> {
        let (_directory, store, ids) = fixture()?;
        let events = store.read(ids[2], SeqRange::all())?;
        let bytes = cost(&ids, &events, 5)?;
        let rows = 3 * ids.len() + 2 * events.len();
        for (depth, visits, row_limit, byte_limit, walks, success) in [
            (2, 3, rows, bytes, 1, true),
            (1, 3, rows, bytes, 1, false),
            (2, 2, rows, bytes, 1, false),
            (2, 3, rows - 1, bytes, 1, false),
            (2, 3, rows, bytes - 1, 1, false),
            (2, 6, rows * 2, bytes * 2, 2, true),
            (2, 5, rows * 2, bytes * 2, 2, false),
            (2, 6, rows * 2 - 1, bytes * 2, 2, false),
            (2, 6, rows * 2, bytes * 2 - 1, 2, false),
        ] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits =
                ForkReplayReadLimitsV1::new(depth, visits, row_limit, byte_limit, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = (0..walks).try_for_each(|_| {
                chain_hash_with_context(
                    &store.conn,
                    store.hasher.as_ref(),
                    ids[2],
                    Seq::from_u64(5),
                    &mut NativeReadContextV1::protected(&mut budget),
                )
                .map(|_| ())
            });
            assert_eq!(result.is_ok(), success);
            assert_eq!(budget.check_time().is_ok(), success);
            if success {
                assert_eq!(budget.remaining_native_bytes(), 0);
            }
        }
        Ok(())
    }

    #[test]
    fn empty_inherited_segments_use_real_eof_rows_without_skipping_leaf_events() -> Fallible<()> {
        let (_directory, mut store, ids) = fixture()?;
        let empty_child = store.fork(ids[0], Seq::ZERO, "empty-prefix")?.id();
        append(&mut store, empty_child, 1)?;
        let chain = [ids[0], empty_child];
        let events = store.read(empty_child, SeqRange::all())?;
        assert_eq!(events.len(), 1);
        let bytes = cost(&chain, &events, 1)?;
        let rows = chain.len() * 3 + events.len() * 2;
        let limits = ForkReplayReadLimitsV1::new(1, 2, rows, bytes, 1_000_000)?;
        let (result, remaining, open) = protected_hash(&store, empty_child, 1, limits)?;
        assert_eq!(
            result?,
            store.compute_chain_hash_at(empty_child, Seq::from_u64(1))?
        );
        assert_eq!(remaining, 0);
        assert!(open);
        Ok(())
    }

    #[test]
    fn signed_causal_unicode_fields_use_the_same_semantic_decoder_and_exact_copies() -> Fallible<()>
    {
        let (_directory, mut store, ids) = fixture()?;
        let timeline = store.create_timeline("signed")?.id();
        let mut event = store.read(ids[0], SeqRange::all())?.remove(0);
        // The production schema owns one globally unique Event ID. This is
        // a new local commit, not a duplicate import of the root Event.
        event.id = pos_core::EventId::new();
        event.seq = Seq::from_u64(1);
        event.origin = None;
        event.causation_id = Some(pos_core::EventId::new());
        event.correlation_id = Some(pos_core::CorrelationId::new());
        event.signature = Some(Signature::from_bytes([7; 64]));
        event.signature_identity = Some(KeyIdentityV1::new(
            pos_core::OwnerIdV1::new("é".repeat(64))?,
            KeyRoleV1::TimelineIntegritySigning,
            1,
        ));
        store.append_committed(timeline, &[event])?;
        let events = store.read(timeline, SeqRange::all())?;
        let bytes = cost(&[timeline], &events, 1)?;
        for limit in [bytes - 1, bytes] {
            let limits = ForkReplayReadLimitsV1::new(1, 1, 5, limit, 1_000_000)?;
            let (result, remaining, open) = protected_hash(&store, timeline, 1, limits)?;
            assert_eq!(result.is_ok(), limit == bytes);
            assert_eq!(open, limit == bytes);
            if limit == bytes {
                assert_eq!(
                    result?,
                    store.compute_chain_hash_at(timeline, Seq::from_u64(1))?
                );
                assert_eq!(remaining, 0);
            }
        }
        // ULID aliases accepted by the existing parser remain accepted.
        store.conn.execute(
            "UPDATE events SET event_id = lower(event_id), entity_id = lower(entity_id),
            causation_id = lower(causation_id), correlation_id = lower(correlation_id),
            origin_timeline_id = lower(origin_timeline_id) WHERE timeline_id = ?1",
            [timeline.to_string()],
        )?;
        let limits = ForkReplayReadLimitsV1::new(1, 1, 5, bytes, 1_000_000)?;
        let (result, remaining, open) = protected_hash(&store, timeline, 1, limits)?;
        assert_eq!(
            result?,
            store.compute_chain_hash_at(timeline, Seq::from_u64(1))?
        );
        assert_eq!(remaining, 0);
        assert!(open);
        Ok(())
    }

    fn raw_fixture() -> Fallible<(Connection, TimelineId)> {
        let conn = Connection::open_in_memory()?;
        // Isolated impossible-state faults deliberately omit affinity and NOT
        // NULL constraints, retaining the production cursor's unique key.
        conn.execute_batch("CREATE TABLE timelines(id PRIMARY KEY, parent_id, fork_seq, head_seq);
            CREATE TABLE events(timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
                causation_id, correlation_id, schema_version, payload_hash, signature,
                signature_owner_id, signature_role, signature_epoch, origin_timeline_id,
                origin_logical_seq, PRIMARY KEY(timeline_id, seq));")?;
        let timeline = TimelineId::new();
        let key = timeline.to_string();
        conn.execute("INSERT INTO timelines VALUES (?1, NULL, NULL, 1)", [&key])?;
        conn.execute(
            "INSERT INTO events VALUES (?1, 1, ?2, ?3, 'raw', ?4, 0, NULL, NULL, 1,
            ?5, NULL, NULL, NULL, NULL, ?1, 1)",
            params![
                key,
                pos_core::EventId::new().to_string(),
                EntityId::new().to_string(),
                vec![0xf6_u8],
                vec![1_u8; 32]
            ],
        )?;
        Ok((conn, timeline))
    }

    fn raw_hash(
        conn: &Connection,
        timeline: TimelineId,
        at: u64,
    ) -> Fallible<std::result::Result<Hash, CoreError>> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(4, 8, 64, 16_384, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        Ok(chain_hash_with_context(
            conn,
            &pos_crypto::chain::Blake3Hasher,
            timeline,
            Seq::from_u64(at),
            &mut NativeReadContextV1::protected(&mut budget),
        ))
    }

    #[test]
    fn actual_probe_rejects_types_widths_and_oversized_fields_before_raw_getters() -> Fallible<()> {
        for (column, value) in [
            ("event_id", Value::Text("x".repeat(27))),
            ("entity_id", Value::Blob(vec![1; 26])),
            ("event_type", Value::Blob(vec![1; 1])),
            ("payload", Value::Text("payload".to_owned())),
            ("payload_hash", Value::Blob(vec![1; 31])),
            ("signature", Value::Blob(vec![1; 63])),
            ("signature_owner_id", Value::Text("x".repeat(129))),
            ("causation_id", Value::Text("x".repeat(25))),
            ("correlation_id", Value::Integer(1)),
            ("origin_timeline_id", Value::Text("x".repeat(25))),
            ("wall_time", Value::Text("0".to_owned())),
            ("schema_version", Value::Null),
            ("signature_role", Value::Blob(vec![1])),
            ("signature_epoch", Value::Text("1".to_owned())),
            ("origin_logical_seq", Value::Real(1.0)),
        ] {
            let (conn, timeline) = raw_fixture()?;
            conn.execute(&format!("UPDATE events SET {column} = ?1"), [value])?;
            assert!(matches!(
                raw_hash(&conn, timeline, 1)?,
                Err(CoreError::ArtifactUnavailable)
            ));
        }
        let (conn, timeline) = raw_fixture()?;
        conn.execute_batch("UPDATE events SET payload = zeroblob(32768)")?;
        assert!(matches!(
            raw_hash(&conn, timeline, 1)?,
            Err(CoreError::ArtifactUnavailable)
        ));
        let (conn, timeline) = raw_fixture()?;
        conn.execute_batch("UPDATE events SET event_type = CAST(x'ff' AS TEXT)")?;
        assert!(matches!(
            raw_hash(&conn, timeline, 1)?,
            Err(CoreError::ArtifactUnavailable)
        ));
        let (conn, timeline) = raw_fixture()?;
        conn.execute_batch("UPDATE events SET seq = 'bad'")?;
        assert!(matches!(
            raw_hash(&conn, timeline, 1)?,
            Err(CoreError::ArtifactUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn semantic_faults_after_requested_cut_are_still_validated_and_closed() -> Fallible<()> {
        for mutation in [
            "schema_version = 2", "wall_time = -1", "origin_logical_seq = 0",
            "origin_logical_seq = 3", "event_id = '!!!!!!!!!!!!!!!!!!!!!!!!!!'",
            "entity_id = '!!!!!!!!!!!!!!!!!!!!!!!!!!'", "causation_id = '!!!!!!!!!!!!!!!!!!!!!!!!!!'",
            "correlation_id = '!!!!!!!!!!!!!!!!!!!!!!!!!!'", "origin_timeline_id = '!!!!!!!!!!!!!!!!!!!!!!!!!!'",
            "signature_owner_id = 'owner'",
            "signature_owner_id = 'owner', signature_role = -1, signature_epoch = 1",
            "signature_owner_id = 'owner', signature_role = 255, signature_epoch = 1",
            "signature_owner_id = 'owner', signature_role = 1, signature_epoch = -1",
            "signature_owner_id = 'owner', signature_role = 1, signature_epoch = 0",
            "signature = zeroblob(64), signature_owner_id = 'owner', signature_role = 2, signature_epoch = 0",
        ] {
            let (conn, timeline) = raw_fixture()?;
            conn.execute_batch("UPDATE timelines SET head_seq = 2;
                INSERT INTO events SELECT timeline_id, 2, event_id, entity_id, event_type, payload, wall_time,
                    causation_id, correlation_id, schema_version, payload_hash, signature,
                    signature_owner_id, signature_role, signature_epoch, origin_timeline_id, 2 FROM events;")?;
            conn.execute_batch(&format!("UPDATE events SET {mutation} WHERE seq = 2"))?;
            assert!(matches!(raw_hash(&conn, timeline, 1)?, Err(CoreError::ArtifactUnavailable)));
            // Ordinary semantics also reject this later selected row before
            // their final range filter; the protected path must not skip it.
            assert!(super::super::SqliteStore::read_unchecked_on(&conn, timeline, SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(1))).is_err());
        }
        Ok(())
    }

    #[test]
    fn sparse_rows_keep_ordinary_hash_order_and_i64_max_cursor_does_not_overflow() -> Fallible<()> {
        let (conn, timeline) = raw_fixture()?;
        conn.execute(
            "UPDATE events SET seq = ?1, origin_logical_seq = ?1",
            [i64::MAX],
        )?;
        conn.execute("UPDATE timelines SET head_seq = ?1", [i64::MAX])?;
        let expected = super::super::SqliteStore::compute_chain_hash_at_unchecked_on(
            &conn,
            &pos_crypto::chain::Blake3Hasher,
            timeline,
            Seq::from_u64(1),
        )?;
        assert_eq!(raw_hash(&conn, timeline, 1)??, expected);
        // SQLite orders an impossible TEXT key after INTEGER keys. A saturating
        // or incrementing cursor must not silently terminate at i64::MAX.
        conn.execute_batch("INSERT INTO events SELECT timeline_id, 'bad', event_id, entity_id, event_type,
            payload, wall_time, causation_id, correlation_id, schema_version, payload_hash, signature,
            signature_owner_id, signature_role, signature_epoch, origin_timeline_id, origin_logical_seq FROM events;")?;
        assert!(matches!(
            raw_hash(&conn, timeline, 1)?,
            Err(CoreError::ArtifactUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn private_native_preflight_overflow_is_latched_without_inventing_a_debit() -> Fallible<()> {
        for length in [None, Some(9), Some(8)] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = NativeReadContextV1::protected(&mut budget).require_bytes(length);
            assert_eq!(result.is_ok(), length == Some(8));
            assert_eq!(budget.remaining_native_bytes(), 8);
            assert_eq!(budget.check_time().is_ok(), length == Some(8));
        }
        // Arithmetic witness only, not representable as an admitted SQLite row.
        let lengths = EventRowLengthsV1 {
            seq: 1,
            columns: [usize::MAX; 16],
        };
        assert_eq!(lengths.total(), None);
        // Same checked primitive used by the streaming hash owner, not an
        // admitted SQLite history with an impossible number of stored rows.
        let mut state = ParentHashStateV1 {
            seen: u64::MAX - 1,
            hash: Hash::from_bytes([1; 32]),
            at: Seq::from_u64(u64::MAX),
        };
        assert!(state.observe()?);
        assert_eq!(state.seen, u64::MAX);
        assert_eq!(state.observe(), Err(Error::CorruptAuthority));
        Ok(())
    }

    #[test]
    fn original_guard_epoch_is_checked_inside_getters_and_hash_batches() -> Fallible<()> {
        let (_directory, store, ids) = fixture()?;
        for regression in [false, true] {
            let mut observed_failures = 0;
            let mut observed_successes = 0;
            for boundary in 2..=512 {
                let initial = if regression {
                    Duration::from_micros(1)
                } else {
                    Duration::ZERO
                };
                let later = if regression {
                    Duration::ZERO
                } else {
                    Duration::from_micros(11)
                };
                let marks = std::iter::repeat_n(initial, boundary).chain(std::iter::once(later));
                let mut clock = ScriptedGuardMonotonicSourceV1::new(marks);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(2, 3, 64, 16_384, 10)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = chain_hash_with_context(
                    &store.conn,
                    store.hasher.as_ref(),
                    ids[2],
                    Seq::from_u64(1),
                    &mut NativeReadContextV1::protected(&mut budget),
                );
                if result.is_ok() {
                    observed_successes += 1;
                } else {
                    observed_failures += 1;
                    assert!(matches!(result, Err(CoreError::ArtifactUnavailable)));
                    assert!(budget.check_time().is_err());
                }
            }
            assert!(observed_failures > 0);
            assert!(observed_successes > 0);
        }
        Ok(())
    }
}
