//! CST1 committed host boundary; its Tick is not a factual dependency Tick.

use super::{
    canonical_end, digest, encode_coordinates, read_coordinates, read_head, record_cursor,
    record_prefix, validate_coordinates, CommunityLifecycleErrorV1, Result,
};
use crate::{encode_head, CborCursor, Hash, TimelineId};

/// Committed host Tick and Simulation Time, including an explicit initial state.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityHostProgressV1 {
    timeline: TimelineId,
    generation: [u8; 16],
    host_tick: Option<u64>,
    simulation_time: Option<u64>,
}

impl CommunityHostProgressV1 {
    /// Check the coordinate shape without selecting or committing progress.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero Timeline or generation. A tagged
    /// value0 is distinct from no admitted boundary and is valid.
    pub fn new(
        timeline: TimelineId,
        generation: [u8; 16],
        host_tick: Option<u64>,
        simulation_time: Option<u64>,
    ) -> Result<Self> {
        validate_coordinates(timeline, generation).map(|()| Self {
            timeline,
            generation,
            host_tick,
            simulation_time,
        })
    }

    /// Return the execution Timeline.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// Return the bound execution generation.
    #[must_use]
    pub const fn generation(&self) -> [u8; 16] {
        self.generation
    }

    /// Return the committed host boundary Tick, independently of factual Tick.
    #[must_use]
    pub const fn host_tick(&self) -> Option<u64> {
        self.host_tick
    }

    /// Return the committed host-supplied Simulation Time.
    #[must_use]
    pub const fn simulation_time(&self) -> Option<u64> {
        self.simulation_time
    }

    /// Encode the exact preferred six-field CST1 record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        record_prefix(&mut out, 6, *b"CST1");
        encode_coordinates(&mut out, self.timeline, self.generation);
        encode_boundary(&mut out, self.host_tick);
        encode_boundary(&mut out, self.simulation_time);
        out
    }

    /// Derive the exact domain-separated CST1 content identity.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let bytes = zeroize::Zeroizing::new(self.to_canonical_cbor());
        digest(b"PiglorOS.Community.CST1.v1\0", &bytes)
    }

    /// Decode the whole preferred record; this does not advance a live clock.
    ///
    /// # Errors
    /// Rejects malformed tags/framing, unknown versions, zero coordinates,
    /// nonpreferred encodings and records longer than128 bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 128, 6, *b"CST1").and_then(|mut cursor| {
            read_coordinates(&mut cursor).and_then(|(timeline, generation)| {
                read_boundary(&mut cursor).and_then(|host_tick| {
                    read_boundary(&mut cursor).and_then(|simulation_time| {
                        Self::new(timeline, generation, host_tick, simulation_time)
                            .and_then(|record| canonical_end(&cursor).map(|()| record))
                    })
                })
            })
        })
    }
}

fn encode_boundary(out: &mut Vec<u8>, boundary: Option<u64>) {
    match boundary {
        None => out.extend_from_slice(&[0x81, 0]),
        Some(value) => {
            out.extend_from_slice(&[0x82, 1]);
            encode_head(out, 0, value);
        }
    }
}

fn read_boundary(cursor: &mut CborCursor<'_>) -> Result<Option<u64>> {
    if cursor.consume_if(0x81) {
        cursor
            .fixed(&[0])
            .map_err(CommunityLifecycleErrorV1::from)
            .map(|()| None)
    } else {
        cursor
            .fixed(&[0x82, 1])
            .map_err(CommunityLifecycleErrorV1::from)
            .and_then(|()| read_head(cursor, 0))
            .map(Some)
    }
}
