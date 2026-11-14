//! CSI1 identity/allocation selection floors, never a live selection pointer.
//!
//! CSI1 is native control metadata stored only inside a CNE1 envelope. A
//! decoded record proves its wire shape; the native factory must still verify
//! it against the actual key vault, erasure inventory and authority stores.

use super::{
    canonical_end, fixed_bytes, read_hashes, read_head, read_optional_hash, record_cursor,
    record_prefix, validate_horizon, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

/// Maximum Timeline floor rows in one CSI1.
pub const MAX_COMMUNITY_SELECTION_TIMELINES_V1: usize = 256;
/// Maximum closed generation IDs retained by one Timeline floor row.
pub const MAX_COMMUNITY_CLOSED_GENERATIONS_V1: usize = 64;
const MAX_SELECTION: usize = 1_048_576;
const GENERATION_WIDTH: usize = 17;

/// Closed generation IDs in strictly ascending byte order.
#[derive(Clone, Copy)]
pub struct CommunityGenerationIdsV1<'a>(GenerationRows<'a>);

#[derive(Clone, Copy)]
enum GenerationRows<'a> {
    Typed(&'a [[u8; 16]]),
    Canonical(&'a [u8]),
}

impl<'a> CommunityGenerationIdsV1<'a> {
    /// Borrow caller IDs; the CSI1 constructor validates order and bounds.
    #[must_use]
    pub const fn from_ids(ids: &'a [[u8; 16]]) -> Self {
        Self(GenerationRows::Typed(ids))
    }

    /// Number of closed generation IDs.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            GenerationRows::Typed(ids) => ids.len(),
            GenerationRows::Canonical(bytes) => bytes.len() / GENERATION_WIDTH,
        }
    }

    /// Whether no generation has closed on this Timeline.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate IDs without copying a second metadata buffer.
    pub fn iter(&self) -> impl Iterator<Item = [u8; 16]> + '_ {
        let rows = self.0;
        (0..self.len()).map(move |index| match rows {
            GenerationRows::Typed(ids) => ids[index],
            GenerationRows::Canonical(bytes) => {
                let mut id = [0; 16];
                id.copy_from_slice(&bytes[index * GENERATION_WIDTH + 1..][..16]);
                id
            }
        })
    }
}

impl PartialEq for CommunityGenerationIdsV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityGenerationIdsV1<'_> {}

/// One Timeline's never-decreasing pass/generation floor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityTimelineFloorV1<'a> {
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Highest pass ordinal ever allocated on this Timeline.
    pub highest_pass_ordinal: u64,
    /// Currently admitted generation, if any.
    pub active_generation: Option<[u8; 16]>,
    /// Every retired generation, retained so it is never selected again.
    pub closed_generations: CommunityGenerationIdsV1<'a>,
    /// Opaque selected-head ciphertext reference, if any.
    pub selected_head: Option<Hash>,
    /// Whether this Timeline is closed to new allocation.
    pub closed: bool,
}

/// Borrowed Timeline floor rows in strictly ascending Timeline order.
#[derive(Clone, Copy)]
pub struct CommunityTimelineFloorsV1<'a>(FloorRows<'a>);

#[derive(Clone, Copy)]
enum FloorRows<'a> {
    Typed(&'a [CommunityTimelineFloorV1<'a>]),
    Canonical { bytes: &'a [u8], count: usize },
}

impl<'a> CommunityTimelineFloorsV1<'a> {
    /// Borrow caller rows; the CSI1 constructor validates them.
    #[must_use]
    pub const fn from_floors(floors: &'a [CommunityTimelineFloorV1<'a>]) -> Self {
        Self(FloorRows::Typed(floors))
    }

    /// Number of Timeline rows.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            FloorRows::Typed(floors) => floors.len(),
            FloorRows::Canonical { count, .. } => count,
        }
    }

    /// Whether no Timeline has been admitted yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate rows; decoded rows are re-read from their validated bytes.
    pub fn iter(&self) -> impl Iterator<Item = Result<CommunityTimelineFloorV1<'a>>> + '_ {
        let rows = self.0;
        let mut cursor = match rows {
            FloorRows::Typed(_) => CborCursor::new(&[]),
            FloorRows::Canonical { bytes, .. } => CborCursor::new(bytes),
        };
        (0..self.len()).map(move |index| match rows {
            FloorRows::Typed(floors) => Ok(floors[index]),
            FloorRows::Canonical { .. } => read_floor(&mut cursor),
        })
    }
}

impl PartialEq for CommunityTimelineFloorsV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityTimelineFloorsV1<'_> {}

/// Untrusted CSI1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunitySelectionInputV1<'a> {
    /// Nonzero actual protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// Installed catalogue identity.
    pub installed_catalogue_digest: Hash,
    /// Qualified native profile identity.
    pub native_profile_digest: Hash,
    /// Highest native producer ordinal ever allocated.
    pub highest_native_producer_ordinal: u64,
    /// Complete Timeline floors.
    pub timeline_floors: CommunityTimelineFloorsV1<'a>,
    /// Finite metadata horizon.
    pub metadata_not_after_micros: u64,
}

/// CSI1 selection floors. Valid framing never blesses a copied older store.
pub struct CommunitySelectionV1<'a>(CommunitySelectionInputV1<'a>);

impl<'a> CommunitySelectionV1<'a> {
    /// Validate identities, bounded strictly ordered rows and the horizon.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for too many rows or closed generations and
    /// `InvalidBinding` for zero identities, unordered rows or generation IDs
    /// and an active generation that is also closed.
    pub fn new(input: CommunitySelectionInputV1<'a>) -> Result<Self> {
        if input.timeline_floors.len() > MAX_COMMUNITY_SELECTION_TIMELINES_V1 {
            return Err(Error::BoundsExceeded);
        }
        if input.store_incarnation == [0; 16]
            || [
                input.installed_catalogue_digest,
                input.native_profile_digest,
            ]
            .contains(&Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        validate_horizon(input.metadata_not_after_micros)
            .and_then(|()| validate_floors(input.timeline_floors))
            .map(|()| Self(input))
    }

    /// Borrow original floor fields; they do not select a generation.
    #[must_use]
    pub const fn as_input(&self) -> &CommunitySelectionInputV1<'a> {
        &self.0
    }

    /// Encode the exact eight-field CSI1 into a zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(128 + input.timeline_floors.len() * 256));
        record_prefix(&mut out, 8, *b"CSI1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_hash(&mut out, input.installed_catalogue_digest);
        encode_hash(&mut out, input.native_profile_digest);
        encode_head(&mut out, 0, input.highest_native_producer_ordinal);
        encode_head(&mut out, 4, input.timeline_floors.len() as u64);
        match input.timeline_floors.0 {
            FloorRows::Typed(floors) => {
                for floor in floors {
                    encode_floor(&mut out, *floor);
                }
            }
            FloorRows::Canonical { bytes, .. } => out.extend_from_slice(bytes),
        }
        encode_head(&mut out, 0, input.metadata_not_after_micros);
        out
    }

    /// Decode one complete CSI1, borrowing its row bytes.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, versioned, oversized or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_SELECTION, 8, *b"CSI1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor).and_then(|store_incarnation| {
                read_hashes(&mut cursor).and_then(
                    |[installed_catalogue_digest, native_profile_digest]| {
                        read_head(&mut cursor, 0).and_then(|highest_native_producer_ordinal| {
                            read_floors(&mut cursor).and_then(|timeline_floors| {
                                read_head(&mut cursor, 0).and_then(|metadata_not_after_micros| {
                                    canonical_end(&cursor).and_then(|()| {
                                        Self::new(CommunitySelectionInputV1 {
                                            store_incarnation,
                                            installed_catalogue_digest,
                                            native_profile_digest,
                                            highest_native_producer_ordinal,
                                            timeline_floors,
                                            metadata_not_after_micros,
                                        })
                                    })
                                })
                            })
                        })
                    },
                )
            })
        })
    }
}

fn validate_floors(floors: CommunityTimelineFloorsV1<'_>) -> Result<()> {
    let mut previous: Option<[u8; 16]> = None;
    floors.iter().try_for_each(|floor| {
        floor.and_then(|floor| {
            let timeline = floor.timeline.inner().to_bytes();
            if timeline == [0; 16] || previous.is_some_and(|previous| previous >= timeline) {
                return Err(Error::InvalidBinding);
            }
            previous = Some(timeline);
            validate_floor(&floor)
        })
    })
}

fn validate_floor(floor: &CommunityTimelineFloorV1<'_>) -> Result<()> {
    if floor.closed_generations.len() > MAX_COMMUNITY_CLOSED_GENERATIONS_V1 {
        return Err(Error::BoundsExceeded);
    }
    let mut previous: Option<[u8; 16]> = None;
    let ordered = floor.closed_generations.iter().all(|id| {
        let fresh = id != [0; 16] && previous.is_none_or(|previous| previous < id);
        previous = Some(id);
        fresh && Some(id) != floor.active_generation
    });
    if !ordered
        || floor.active_generation == Some([0; 16])
        || floor.selected_head == Some(Hash::zero())
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

fn encode_floor(out: &mut Vec<u8>, floor: CommunityTimelineFloorV1<'_>) {
    out.push(0x86);
    encode_bytes(out, &floor.timeline.inner().to_bytes(), 2);
    encode_head(out, 0, floor.highest_pass_ordinal);
    match floor.active_generation {
        Some(generation) => encode_bytes(out, &generation, 2),
        None => out.push(0xf6),
    }
    encode_head(out, 4, floor.closed_generations.len() as u64);
    for id in floor.closed_generations.iter() {
        encode_bytes(out, &id, 2);
    }
    match floor.selected_head {
        Some(head) => encode_hash(out, head),
        None => out.push(0xf6),
    }
    out.push(if floor.closed { 0xf5 } else { 0xf4 });
}

fn read_optional_generation(cursor: &mut CborCursor<'_>) -> Result<Option<[u8; 16]>> {
    if cursor.consume_if(0xf6) {
        Ok(None)
    } else {
        fixed_bytes(cursor).map(Some)
    }
}

fn read_generations<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityGenerationIdsV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        if count > MAX_COMMUNITY_CLOSED_GENERATIONS_V1 as u64 {
            return Err(Error::BoundsExceeded);
        }
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        cursor
            .take(count * GENERATION_WIDTH)
            .map_err(Error::from)
            .and_then(|bytes| {
                if bytes.chunks_exact(GENERATION_WIDTH).all(|id| id[0] == 0x50) {
                    Ok(CommunityGenerationIdsV1(GenerationRows::Canonical(bytes)))
                } else {
                    Err(Error::InvalidEncoding)
                }
            })
    })
}

fn read_bool(cursor: &mut CborCursor<'_>) -> Result<bool> {
    if cursor.consume_if(0xf5) {
        Ok(true)
    } else if cursor.consume_if(0xf4) {
        Ok(false)
    } else {
        Err(Error::InvalidEncoding)
    }
}

fn read_floor<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityTimelineFloorV1<'a>> {
    cursor.fixed(&[0x86]).map_err(Error::from).and_then(|()| {
        fixed_bytes(cursor).and_then(|timeline| {
            read_head(cursor, 0).and_then(|highest_pass_ordinal| {
                read_optional_generation(cursor).and_then(|active_generation| {
                    read_generations(cursor).and_then(|closed_generations| {
                        read_optional_hash(cursor).and_then(|selected_head| {
                            read_bool(cursor).map(|closed| CommunityTimelineFloorV1 {
                                timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes(timeline)),
                                highest_pass_ordinal,
                                active_generation,
                                closed_generations,
                                selected_head,
                                closed,
                            })
                        })
                    })
                })
            })
        })
    })
}

fn read_floors<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityTimelineFloorsV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        if count > MAX_COMMUNITY_SELECTION_TIMELINES_V1 as u64 {
            return Err(Error::BoundsExceeded);
        }
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        let mut original = cursor.clone();
        let start = cursor.position();
        (0..count)
            .try_for_each(|_| read_floor(cursor).map(drop))
            .and_then(|()| {
                original
                    .take(cursor.position() - start)
                    .map_err(Error::from)
                    .map(|bytes| CommunityTimelineFloorsV1(FloorRows::Canonical { bytes, count }))
            })
    })
}
