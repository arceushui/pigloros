//! The SPI1 CDDL and validation rules 2 to 9 (ADR-069 R11 §4.2 and §4.3).
//!
//! ```cddl
//! provider-installation-u = [
//!   "SPI1", 1,
//!   attempt-range: [ipv4-network: bytes .size 4, ipv4-prefix-length: 8..30,
//!                   ipv6-network: bytes .size 16, ipv6-prefix-length: 7..127],
//!   egress-probe: [network: bytes .size 4, port: 1..65535],
//!   staging-aggregate-bytes: 1..18446744073709551615,
//!   cleanup-budget: [grace, unit-kill, shutdown, unit-absent, released],
//!                   ; each 1..5000 milliseconds
//!   runtime-key-file: text .regexp "[a-z0-9][a-z0-9._-]{0,63}"]
//! provider-installation = [provider-installation-u, spi1-digest: bytes .size 32]
//! ```
//!
//! `spi1-digest` is `BLAKE3-256("PiglorOS.SPI1.v1\0" || U)`, the generic
//! self-digest of ADR-069 §10. The whole document must be its own
//! deterministic encoding, so it is decoded once and encoded again, and only
//! byte-identical input is accepted.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::time::Duration;

use ciborium::value::Value;

use super::ProviderInstallationError;
use crate::{CleanupBudget, EgressProbe, NetworkPlanError, NetworkRange};

/// The SPI1 self-digest domain.
const DIGEST_DOMAIN: &[u8] = b"PiglorOS.SPI1.v1\0";
/// The bounds of each cleanup phase, in milliseconds.
const CLEANUP_PHASE_MS: RangeInclusive<u64> = 1..=5000;
/// The longest runtime key file name.
const KEY_FILE_NAME_BYTES: usize = 64;

/// The validated SPI1 values.
#[derive(Debug)]
pub(super) struct Fields {
    pub(super) attempt_range: NetworkRange,
    pub(super) egress_probe: EgressProbe,
    pub(super) staging_aggregate_bytes: u64,
    pub(super) cleanup_budget: CleanupBudget,
    pub(super) runtime_key_file: String,
}

/// The SPI1 fields as decoded, before rules 4 to 9.
struct Decoded {
    ipv4: (Ipv4Addr, u8),
    ipv6: (Ipv6Addr, u8),
    probe: (Ipv4Addr, u16),
    staging_aggregate_bytes: u64,
    cleanup_ms: [u64; 5],
    runtime_key_file: String,
}

/// Decode `bytes` and apply rules 2 to 9 in order.
pub(super) fn decode(bytes: &[u8]) -> Result<Fields, ProviderInstallationError> {
    canonical(bytes)
        .and_then(|document| {
            let [unsigned, digest] = array::<2>(&document)?;
            let decoded = decode_unsigned(unsigned)?;
            verify_digest(unsigned, digest)?;
            Ok(decoded)
        })
        .and_then(validate)
}

/// The value `bytes` encode, if they are exactly its deterministic encoding.
fn canonical(bytes: &[u8]) -> Result<Value, ProviderInstallationError> {
    ciborium::from_reader::<Value, _>(bytes)
        .ok()
        .filter(|value| encode(value) == bytes)
        .ok_or(ProviderInstallationError::InvalidEncoding)
}

/// The deterministic encoding of `value`. Writing to memory cannot fail; a
/// failure would leave bytes that match neither the input nor its digest.
fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).ok();
    bytes
}

/// Rule 2 over the unsigned record.
fn decode_unsigned(unsigned: &Value) -> Result<Decoded, ProviderInstallationError> {
    let [magic, version, range, probe, cap, budget, key] = array::<7>(unsigned)?;
    if *magic != Value::Text("SPI1".to_owned()) || uint(version, 1..=1).is_err() {
        return Err(ProviderInstallationError::InvalidEncoding);
    }
    let [ipv4, ipv4_length, ipv6, ipv6_length] = array::<4>(range)?;
    let [probe_network, port] = array::<2>(probe)?;
    let cleanup = array::<5>(budget)?;
    let mut cleanup_ms = [0; 5];
    for (phase, value) in cleanup_ms.iter_mut().zip(cleanup) {
        *phase = uint(value, CLEANUP_PHASE_MS)?;
    }
    Ok(Decoded {
        ipv4: (
            Ipv4Addr::from(bytes::<4>(ipv4)?),
            narrow(uint(ipv4_length, 8..=30)?),
        ),
        ipv6: (
            Ipv6Addr::from(bytes::<16>(ipv6)?),
            narrow(uint(ipv6_length, 7..=127)?),
        ),
        probe: (
            Ipv4Addr::from(bytes::<4>(probe_network)?),
            narrow(uint(port, 1..=u64::from(u16::MAX))?),
        ),
        staging_aggregate_bytes: uint(cap, 1..=u64::MAX)?,
        cleanup_ms,
        runtime_key_file: key_file_name(key)?,
    })
}

/// Rule 3: the self-digest over the unsigned record.
fn verify_digest(unsigned: &Value, digest: &Value) -> Result<(), ProviderInstallationError> {
    let expected = bytes::<32>(digest)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(&encode(unsigned));
    if *hasher.finalize().as_bytes() == expected {
        Ok(())
    } else {
        Err(ProviderInstallationError::DigestMismatch)
    }
}

/// Rules 4 to 9, in order.
fn validate(decoded: Decoded) -> Result<Fields, ProviderInstallationError> {
    let Decoded {
        ipv4,
        ipv6,
        probe,
        staging_aggregate_bytes,
        cleanup_ms: [grace, unit_kill, shutdown, unit_absent, released],
        runtime_key_file,
    } = decoded;
    // Rules 4 and 5, in that order.
    let attempt_range =
        NetworkRange::new(ipv4.0, ipv4.1, ipv6.0, ipv6.1).map_err(|error| match error {
            NetworkPlanError::Ipv6Range => ProviderInstallationError::AttemptIpv6Range,
            _ => ProviderInstallationError::AttemptIpv4Range,
        })?;
    // Rule 6.
    let egress_probe = EgressProbe::new(probe.0, probe.1)?;
    // Rule 6b: an aligned /30 lies in one RFC 1918 block whenever its
    // network address does, since every block is a larger aligned network.
    if !probe.0.is_private() {
        return Err(ProviderInstallationError::EgressProbeNotPrivate);
    }
    // Rule 7: the range's prefix is at most /30, so the /30 shares an address
    // with it exactly when its network address lies inside it.
    let mask = u32::MAX << (32 - u32::from(ipv4.1));
    if probe.0.to_bits() & mask == ipv4.0.to_bits() {
        return Err(ProviderInstallationError::EgressProbeInAttemptRange);
    }
    // Rule 8 is the CDDL bound `1..`. Rule 9.
    let cleanup_budget = CleanupBudget::new(
        Duration::from_millis(grace),
        Duration::from_millis(unit_kill),
        Duration::from_millis(shutdown),
        Duration::from_millis(unit_absent),
        Duration::from_millis(released),
    )
    .map_err(|_| ProviderInstallationError::CleanupBudget)?;
    Ok(Fields {
        attempt_range,
        egress_probe,
        staging_aggregate_bytes,
        cleanup_budget,
        runtime_key_file,
    })
}

/// The `N` items of a definite array of exactly `N` items.
fn array<const N: usize>(value: &Value) -> Result<&[Value; N], ProviderInstallationError> {
    match value {
        Value::Array(items) => items.as_slice().try_into().ok(),
        _ => None,
    }
    .ok_or(ProviderInstallationError::InvalidEncoding)
}

/// An unsigned integer inside `bounds`.
fn uint(value: &Value, bounds: RangeInclusive<u64>) -> Result<u64, ProviderInstallationError> {
    match value {
        Value::Integer(integer) => u64::try_from(*integer).ok(),
        _ => None,
    }
    .filter(|number| bounds.contains(number))
    .ok_or(ProviderInstallationError::InvalidEncoding)
}

/// A byte string of exactly `N` bytes.
fn bytes<const N: usize>(value: &Value) -> Result<[u8; N], ProviderInstallationError> {
    match value {
        Value::Bytes(bytes) => bytes.as_slice().try_into().ok(),
        _ => None,
    }
    .ok_or(ProviderInstallationError::InvalidEncoding)
}

/// An integer that its CDDL bound already fits in the narrower type.
fn narrow<T: TryFrom<u64> + Default>(number: u64) -> T {
    T::try_from(number).unwrap_or_default()
}

/// A key file name: `[a-z0-9][a-z0-9._-]{0,63}`, so no `/`, no leading `.`
/// and no NUL.
fn key_file_name(value: &Value) -> Result<String, ProviderInstallationError> {
    match value {
        Value::Text(name)
            if (1..=KEY_FILE_NAME_BYTES).contains(&name.len())
                && name.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
                }) =>
        {
            Ok(name.clone())
        }
        _ => Err(ProviderInstallationError::InvalidEncoding),
    }
}
