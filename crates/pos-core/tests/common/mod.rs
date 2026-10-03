//! Shared fixtures for the ADR-105 authority public-seam tests.

use ciborium::Value;
use pos_core::{
    CanonicalBytes, EntityId, EventId, ForkAttributionIssuerV1, ForkEventEvidenceV1, Hash,
    KeyIdentityV1, KeyRoleV1, Kind, PublicKey, Seq, Signature, TimelineEventEnvelopeInputV1,
    TimelineEventEnvelopeV1, TimelineId, WallTime,
};
use ulid::Ulid;

/// A test result carrying any public error.
pub type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
/// A test body's result.
pub type TestResult = Fallible<()>;

/// A digest of 32 copies of `value`.
#[must_use]
pub const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

/// A Timeline ID of 16 copies of `value`.
#[must_use]
pub const fn timeline_id(value: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([value; 16]))
}

/// Decode hex digits, ignoring whitespace.
///
/// # Errors
/// Returns the fixture's construction or codec error.
pub fn unhex(text: &str) -> Fallible<Vec<u8>> {
    let digits = text.split_whitespace().collect::<String>();
    (0..digits.len())
        .step_by(2)
        .map(|at| -> Fallible<u8> {
            let pair = digits.get(at..at + 2).ok_or("odd hex length")?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}

/// Decode one CBOR array into its items.
///
/// # Errors
/// Returns the fixture's construction or codec error.
pub fn items(bytes: &[u8]) -> Fallible<Vec<Value>> {
    ciborium::from_reader::<Value, _>(bytes)?
        .into_array()
        .map_err(|_| "not a CBOR array".into())
}

/// Encode items as one canonical CBOR array.
///
/// # Errors
/// Returns the fixture's construction or codec error.
pub fn encode(items: Vec<Value>) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Array(items), &mut out)?;
    Ok(out)
}

/// Re-encode the one-byte unsigned integer at `at` in a wider, noncanonical form.
#[must_use]
pub fn widened(bytes: &[u8], at: usize) -> Vec<u8> {
    [&bytes[..at], &[0x18_u8][..], &bytes[at..]].concat()
}

/// The fixture `FAI1` issuer.
///
/// # Errors
/// Returns the fixture's construction or codec error.
pub fn issuer() -> Fallible<ForkAttributionIssuerV1> {
    Ok(ForkAttributionIssuerV1::new(
        "issuer-a",
        1,
        PublicKey::from_bytes([0x22; 32]),
    )?)
}

/// The fixture creator's attribution-signing identity at `epoch`.
#[must_use]
pub fn attribution_identity(epoch: u64) -> KeyIdentityV1 {
    KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, epoch)
}

/// One Timeline envelope at `seq` on `origin`.
///
/// # Errors
/// Returns the fixture's construction or codec error.
pub fn envelope_at(
    origin: TimelineId,
    seq: u64,
    schema_version: u32,
    payload: &CanonicalBytes,
) -> Fallible<TimelineEventEnvelopeV1> {
    Ok(TimelineEventEnvelopeV1::new(
        TimelineEventEnvelopeInputV1 {
            identity: KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1),
            origin_timeline_id: origin,
            event_id: EventId::from_ulid(Ulid::from_parts(seq, 7)),
            origin_logical_seq: Seq::from_u64(seq),
            entity_id: EntityId::from_ulid(Ulid::from_parts(1, 2)),
            event_type: Kind::new("fork.test"),
            schema_version,
            wall_time: WallTime::from_micros(1_000 + seq),
            causation_id: None,
            correlation_id: None,
        },
        payload,
    )?)
}

/// One `FEE1` at origin logical sequence `seq` on `origin`.
///
/// # Errors
/// Returns the fixture's construction or codec error.
pub fn evidence_from(
    origin: TimelineId,
    seq: u64,
    payload: &[u8],
) -> Fallible<ForkEventEvidenceV1> {
    let payload = CanonicalBytes::from_vec(payload.to_vec());
    Ok(ForkEventEvidenceV1::new(
        envelope_at(origin, seq, 1, &payload)?,
        payload,
        Signature::from_bytes([0x77; 64]),
    )?)
}

/// One `FEE1` at origin logical sequence `seq` on the fixture child.
///
/// # Errors
/// Returns the fixture's construction or codec error.
pub fn evidence(seq: u64, payload: &[u8]) -> Fallible<ForkEventEvidenceV1> {
    evidence_from(timeline_id(2), seq, payload)
}
