//! The capture helpers every capture adapter shares (ADR-062 Revision 8
//! slices N1-N4): the three facets of a row's surfaces and their raw capture,
//! the canonical CBOR records, and the position-relative Event stream of
//! owner note `ADR-062_R8_NonInterference_Executions`, decision 7.

use ciborium::Value;
use pos_conformance::{
    non_interference_surface_names_v1, NonInterferenceRawCaptureV1,
    NonInterferenceRawOperationalV1, NonInterferenceVariantV1,
};
use pos_core::{EntityId, Event};

/// Every runner replaces a capture's provenance digest with its own execution
/// provenance; a capture adapter's placeholder is never compared.
const RUNNER_BOUND_PROVENANCE_V1: [u8; 32] = [0xff; 32];

/// The three facets of every surface of one row, in surface order.
pub(super) struct SurfacesV1 {
    pub(super) authoritative: Vec<Vec<u8>>,
    pub(super) public: Vec<Vec<u8>>,
    pub(super) operational: Vec<NonInterferenceRawOperationalV1>,
}

impl SurfacesV1 {
    pub(super) fn into_capture(self, fixture_id: &str) -> NonInterferenceRawCaptureV1 {
        NonInterferenceRawCaptureV1 {
            surface_names: non_interference_surface_names_v1(fixture_id)
                .unwrap_or_default()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            authoritative: self.authoritative,
            public: self.public,
            operational: self.operational,
            unexpected_network_accesses: 0,
            provenance_digest: RUNNER_BOUND_PROVENANCE_V1,
        }
    }
}

/// The canonical CBOR encoding of one record. An encoding failure yields no
/// bytes, which the #181 normalizer refuses as out of bounds.
pub(super) fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_or(Vec::new(), |()| bytes)
}

pub(super) fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

pub(super) fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

pub(super) const fn variant_name(variant: NonInterferenceVariantV1) -> &'static str {
    match variant {
        NonInterferenceVariantV1::Success => "success",
        NonInterferenceVariantV1::Denial => "denial",
        NonInterferenceVariantV1::WarmCache => "warm_cache",
        NonInterferenceVariantV1::ColdCache => "cold_cache",
    }
}

/// The first-appearance ordinal of `value` in `seen`.
pub(super) fn ordinal<T: PartialEq + Clone>(seen: &mut Vec<T>, value: &T) -> u64 {
    let position = seen
        .iter()
        .position(|known| known == value)
        .unwrap_or_else(|| {
            seen.push(value.clone());
            seen.len() - 1
        });
    position as u64
}

/// The position-relative record of an Event stream in Timeline Order:
/// `[seq, entity ordinal, event type, schema version, causation seq or
/// null, correlation ordinal or null, payload, payload hash]` per Event,
/// the ADR-127 section 2 Event record.
/// The Timeline `owner`, when present, takes entity ordinal 0. A cause
/// outside the stream has no position, so the stream is refused (`None`):
/// the authoritative field is never normalized to "no cause". Signatures and
/// their identities are operational and are not captured.
pub(super) fn event_stream(events: &[Event], owner: Option<EntityId>) -> Option<Value> {
    let mut entities = owner.into_iter().collect::<Vec<_>>();
    let mut correlations = Vec::new();
    events
        .iter()
        .map(|event| {
            let cause = event.causation_id.map_or_else(
                || Some(Value::Null),
                |cause| {
                    events
                        .iter()
                        .find(|candidate| candidate.id == cause)
                        .map(|candidate| uint(candidate.seq.as_u64()))
                },
            );
            cause.map(|cause| {
                Value::Array(vec![
                    uint(event.seq.as_u64()),
                    uint(ordinal(&mut entities, &event.entity)),
                    text(event.event_type.as_str()),
                    uint(u64::from(event.schema_version.as_u32())),
                    cause,
                    event.correlation_id.map_or(Value::Null, |correlation| {
                        uint(ordinal(&mut correlations, &correlation))
                    }),
                    Value::Bytes(event.payload.as_slice().to_vec()),
                    Value::Bytes(event.payload_hash.as_bytes().to_vec()),
                ])
            })
        })
        .collect::<Option<Vec<_>>>()
        .map(Value::Array)
}
