//! Shared fork-chain stitching for [`EventStore`] backends.
//!
//! Child timelines restart local `seq` at 1. Callers that read a forked timeline
//! must see a single logical sequence: parent[`0..=fork_seq`] + child events,
//! renumbered to `1..n`, then filtered by the requested [`SeqRange`].

use pos_core::{clock::Seq, event::Event, store::SeqRange};

/// Assign logical seqs (`1..n` in chain order) and apply `range`.
///
/// `segments` must already be in root→leaf order, each segment containing only
/// that level's contribution (parent capped at `fork_seq`; leaf = own events).
#[must_use]
pub fn renumber_and_filter(
    segments: impl IntoIterator<Item = Event>,
    range: SeqRange,
) -> Vec<Event> {
    segments
        .into_iter()
        .enumerate()
        .map(|(i, mut e)| {
            e.seq = Seq::from_u64((i + 1) as u64);
            e
        })
        .filter(|e| e.seq >= range.from && range.to.is_none_or(|to| e.seq <= to))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::WallTime,
        crypto::Hash,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::{EntityId, EventId},
    };

    fn ev(payload: &[u8], raw_seq: u64) -> Event {
        Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("t"),
            payload: CanonicalBytes::from_vec(payload.to_vec()),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(raw_seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn renumbers_colliding_raw_seqs_in_order() {
        // Two levels both have local seq=1 — logical order must preserve segment order.
        let out = renumber_and_filter(vec![ev(b"parent", 1), ev(b"child", 1)], SeqRange::all());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].seq.as_u64(), 1);
        assert_eq!(out[1].seq.as_u64(), 2);
        assert_eq!(out[0].payload.as_slice(), b"parent");
        assert_eq!(out[1].payload.as_slice(), b"child");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn filters_by_logical_range() {
        let out = renumber_and_filter(
            vec![ev(b"a", 1), ev(b"b", 1), ev(b"c", 2)],
            SeqRange::bounded(Seq::from_u64(2), Seq::from_u64(2)),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload.as_slice(), b"b");
        assert_eq!(out[0].seq.as_u64(), 2);
    }
}
