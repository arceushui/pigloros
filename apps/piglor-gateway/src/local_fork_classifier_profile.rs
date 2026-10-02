//! Activation-scoped ADR-099 revision 11 `FCP1` classifier profile.
//!
//! ADR-107 revision 6 delivers the profile as the third encrypted
//! managed-service credential. Gateway decodes it in startup step 1, runs the
//! read-only durable preflight on the host adapter before the FAO1 open proof,
//! and moves its rows only into the executor's private Fork-admission slot
//! when that slot is installed (ADR-109 revision 12). No request, Plugin,
//! client, imported record, or public API can supply, install, or change a
//! profile, and the profile never becomes Replay authority: durable
//! FCS1/FCT1/FCR1/FOP1 records remain that source.

use ciborium::value::Value;
use pos_core::ForkClassifierSourceV1;

use crate::local_fork_authentication::LocalForkAuthenticationErrorV1;

/// Fixed ADR-107 r6 credential name of the FCP1 plaintext.
pub(super) const CLASSIFIER_PROFILE_CREDENTIAL_NAME: &str = "pigloros.fork-classifier-profile";
/// Fixed ADR-099 r11 registrar identifier of every profile row.
pub(super) const CLASSIFIER_REGISTRAR_IDENTIFIER: &str = "piglor-gateway.local-fork-classifier/v1";
/// Complete canonical FCP1 byte bound.
pub(super) const MAX_CLASSIFIER_PROFILE_BYTES: usize = 786_688;
const MAX_PROFILE_ROWS: usize = 4;

/// Immutable descriptor-hash to FCS1 rows selected at managed activation.
pub(super) struct ForkClassifierProfileV1 {
    sources: Vec<ForkClassifierSourceV1>,
}

impl ForkClassifierProfileV1 {
    /// Strictly decode one canonical FCP1 plaintext.
    ///
    /// Every rejection is `CredentialInvalid`: an oversized, malformed, or
    /// noncanonical profile; wrong marker, version, registrar, or cardinality;
    /// an invalid inner FCS1 or one for another registrar; and descriptor rows
    /// that are unsorted or repeated.
    pub(super) fn from_canonical_cbor(
        bytes: &[u8],
    ) -> Result<Self, LocalForkAuthenticationErrorV1> {
        canonical_profile_rows(bytes)
            .and_then(|rows| {
                rows.iter()
                    .map(profile_source)
                    .collect::<Result<Vec<_>, _>>()
            })
            .and_then(|sources| {
                sources
                    .windows(2)
                    .all(|pair| {
                        pair[0].input().room_revision_descriptor_hash
                            < pair[1].input().room_revision_descriptor_hash
                    })
                    .then_some(Self { sources })
                    .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)
            })
    }

    /// Every profile row, for the read-only durable FCS1 preflight.
    #[must_use]
    pub(super) fn sources(&self) -> &[ForkClassifierSourceV1] {
        &self.sources
    }

    /// Move the immutable rows into the executor's Fork-admission slot,
    /// which alone selects a row by a durable FAR1 descriptor hash.
    #[must_use]
    pub(super) fn into_sources(self) -> Vec<ForkClassifierSourceV1> {
        self.sources
    }
}

/// Decode the bounded FCP1 array and return its row field.
///
/// The decoded value must re-encode byte-for-byte, which rejects trailing
/// bytes, indefinite lengths, and non-shortest integer or length forms.
fn canonical_profile_rows(bytes: &[u8]) -> Result<Vec<Value>, LocalForkAuthenticationErrorV1> {
    let mut remaining = bytes;
    let mut encoded = Vec::new();
    (bytes.len() <= MAX_CLASSIFIER_PROFILE_BYTES)
        .then(|| ciborium::from_reader::<Value, _>(&mut remaining).ok())
        .flatten()
        .filter(|value| {
            remaining.is_empty()
                && ciborium::into_writer(value, &mut encoded).is_ok()
                && encoded == bytes
        })
        .and_then(|value| value.into_array().ok())
        .and_then(profile_rows)
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)
}

/// Match `["FCP1", 1, registrar, [1*4 bstr]]` and return the rows.
fn profile_rows(fields: Vec<Value>) -> Option<Vec<Value>> {
    match <[Value; 4]>::try_from(fields).ok()? {
        [Value::Text(marker), Value::Integer(version), Value::Text(registrar), Value::Array(rows)]
            if marker == "FCP1"
                && version == 1.into()
                && registrar == CLASSIFIER_REGISTRAR_IDENTIFIER
                && (1..=MAX_PROFILE_ROWS).contains(&rows.len()) =>
        {
            Some(rows)
        }
        _ => None,
    }
}

/// Strictly decode one inner FCS1 row of the fixed registrar.
fn profile_source(row: &Value) -> Result<ForkClassifierSourceV1, LocalForkAuthenticationErrorV1> {
    row.as_bytes()
        .and_then(|bytes| ForkClassifierSourceV1::from_canonical_cbor(bytes).ok())
        .filter(|source| source.input().registrar_identifier == CLASSIFIER_REGISTRAR_IDENTIFIER)
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)
}

/// Encode a canonical FCP1 test profile from FCS1 rows.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn test_profile_bytes(rows: &[ForkClassifierSourceV1]) -> Vec<u8> {
    test_profile_value(
        rows.iter()
            .map(|row| Value::Bytes(row.to_canonical_cbor()))
            .collect(),
    )
}

/// Encode FCP1 test bytes around arbitrary row values.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn test_profile_value(rows: Vec<Value>) -> Vec<u8> {
    test_cbor(&Value::Array(vec![
        Value::Text("FCP1".to_owned()),
        Value::Integer(1.into()),
        Value::Text(CLASSIFIER_REGISTRAR_IDENTIFIER.to_owned()),
        Value::Array(rows),
    ]))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn test_cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    if ciborium::into_writer(value, &mut bytes).is_err() {
        bytes.clear();
    }
    bytes
}

/// One FCS1 row of the fixed registrar for a repeated descriptor byte.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn test_profile_source(
    descriptor: u8,
    routes: Vec<pos_core::ForkExternalInputRouteV1>,
) -> Result<ForkClassifierSourceV1, pos_core::ForkEventProvenanceErrorV1> {
    ForkClassifierSourceV1::new(pos_core::ForkClassifierSourceInputV1 {
        room_revision_descriptor_hash: pos_core::Hash::from_bytes([descriptor; 32]),
        registrar_identifier: CLASSIFIER_REGISTRAR_IDENTIFIER.to_owned(),
        routes,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        ForkClassifierSourceInputV1, ForkEventSourceDescriptorV1, ForkExternalInputRouteV1, Hash,
    };

    const INVALID: Option<LocalForkAuthenticationErrorV1> =
        Some(LocalForkAuthenticationErrorV1::CredentialInvalid);

    fn row(descriptor: u8) -> Result<ForkClassifierSourceV1, Box<dyn std::error::Error>> {
        let route =
            ForkEventSourceDescriptorV1::new("gateway.action.v1", Hash::from_bytes([3; 32]))?;
        Ok(test_profile_source(
            descriptor,
            vec![ForkExternalInputRouteV1::new(route, true)],
        )?)
    }

    fn decode(bytes: &[u8]) -> Option<LocalForkAuthenticationErrorV1> {
        ForkClassifierProfileV1::from_canonical_cbor(bytes).err()
    }

    #[test]
    fn profile_round_trips_canonical_sorted_rows() -> Result<(), Box<dyn std::error::Error>> {
        for rows in [vec![row(1)?], vec![row(1)?, row(2)?, row(3)?, row(4)?]] {
            let bytes = test_profile_bytes(&rows);
            let profile = ForkClassifierProfileV1::from_canonical_cbor(&bytes)?;
            assert_eq!(profile.sources(), rows.as_slice());
            assert_eq!(test_profile_bytes(profile.sources()), bytes);
            assert_eq!(profile.into_sources(), rows);
        }
        Ok(())
    }

    #[test]
    fn profile_rejects_bounds_cardinality_and_ordering() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(decode(&vec![0; MAX_CLASSIFIER_PROFILE_BYTES + 1]), INVALID);
        assert_eq!(decode(&test_profile_bytes(&[])), INVALID);
        let five = [row(1)?, row(2)?, row(3)?, row(4)?, row(5)?];
        assert_eq!(decode(&test_profile_bytes(&five)), INVALID);
        assert_eq!(decode(&test_profile_bytes(&[row(1)?, row(1)?])), INVALID);
        assert_eq!(decode(&test_profile_bytes(&[row(2)?, row(1)?])), INVALID);
        Ok(())
    }

    #[test]
    fn profile_rejects_noncanonical_or_malformed_encodings(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let canonical = test_profile_bytes(&[row(1)?]);
        let mut trailing = canonical.clone();
        trailing.push(0xf6);
        assert_eq!(decode(&trailing), INVALID);
        assert_eq!(decode(&canonical[..canonical.len() - 1]), INVALID);
        assert_eq!(decode(&[]), INVALID);
        // A non-shortest version integer.
        let long_version = [&canonical[..6], &[0x18, 0x01], &canonical[7..]].concat();
        assert_eq!(decode(&long_version), INVALID);
        // An indefinite-length outer array.
        let mut indefinite = canonical.clone();
        indefinite[0] = 0x9f;
        indefinite.push(0xff);
        assert_eq!(decode(&indefinite), INVALID);
        // A tagged profile and a non-array profile.
        assert_eq!(
            decode(&test_cbor(&Value::Tag(
                24,
                Box::new(Value::Bytes(canonical))
            ))),
            INVALID
        );
        assert_eq!(decode(&test_cbor(&Value::Text("FCP1".to_owned()))), INVALID);
        Ok(())
    }

    #[test]
    fn profile_rejects_wrong_header_fields() -> Result<(), Box<dyn std::error::Error>> {
        let rows = Value::Array(vec![Value::Bytes(row(1)?.to_canonical_cbor())]);
        let marker = || Value::Text("FCP1".to_owned());
        let version = || Value::Integer(1.into());
        let registrar = || Value::Text(CLASSIFIER_REGISTRAR_IDENTIFIER.to_owned());
        for fields in [
            vec![
                Value::Text("FCP2".to_owned()),
                version(),
                registrar(),
                rows.clone(),
            ],
            vec![
                marker(),
                Value::Integer(2.into()),
                registrar(),
                rows.clone(),
            ],
            vec![
                marker(),
                version(),
                Value::Text("another".to_owned()),
                rows.clone(),
            ],
            vec![marker(), Value::Float(1.0), registrar(), rows.clone()],
            vec![marker(), version(), registrar(), Value::Bytes(Vec::new())],
            vec![marker(), version(), registrar()],
            vec![marker(), version(), registrar(), rows, Value::Null],
        ] {
            assert_eq!(decode(&test_cbor(&Value::Array(fields))), INVALID);
        }
        Ok(())
    }

    #[test]
    fn profile_rejects_invalid_inner_fcs1_rows() -> Result<(), Box<dyn std::error::Error>> {
        let foreign_registrar = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: Hash::from_bytes([1; 32]),
            registrar_identifier: "another-registrar".to_owned(),
            routes: Vec::new(),
        })?;
        let mut noncanonical_inner = row(1)?.to_canonical_cbor();
        noncanonical_inner.push(0);
        for inner in [
            Value::Bytes(foreign_registrar.to_canonical_cbor()),
            Value::Bytes(noncanonical_inner),
            Value::Bytes(vec![0x80]),
            Value::Bytes(Vec::new()),
            Value::Text("FCS1".to_owned()),
        ] {
            assert_eq!(decode(&test_profile_value(vec![inner])), INVALID);
        }
        Ok(())
    }
}
