//! ADR-069 R14 admits negative CBOR integers for the signed nftables
//! priority. Every unsigned field of the existing records still refuses
//! them, and a negative integer must still be in its shortest form.

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    KernelObservationEvidence, LaunchPolicy, RequestedConfigurationEvidence, SandboxAuditRecord,
    SandboxProviderProtocolError as ProtocolError, TerminationEvidence,
};

use super::network_readback::READBACK;
use super::oracle::{filled, integer, seal, text, unhex, with, TestResult};
use super::response::completed_audit;
use super::vectors::{KOE1_A, KOE1_C, RQE1_A, TME1_A};

fn negative(value: i64) -> Value {
    Value::Integer(value.into())
}

/// Replace the one occurrence of `from` in `bytes` with `to`.
fn replaced(bytes: &[u8], from: &[u8], to: &[u8]) -> TestResult<Vec<u8>> {
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .ok_or("pattern not found")?;
    assert!(
        bytes[at + 1..]
            .windows(from.len())
            .all(|window| window != from),
        "pattern is not unique"
    );
    let mut changed = bytes[..at].to_vec();
    changed.extend_from_slice(to);
    changed.extend_from_slice(&bytes[at + from.len()..]);
    Ok(changed)
}

/// One LPS1 whose only effective limit has `value`.
fn launch_policy(value: Value) -> TestResult<Vec<u8>> {
    seal(
        "LPS1",
        vec![
            text("LPS1"),
            integer(1),
            text("air-gapped"),
            integer(1),
            filled(0x03, 32),
            Value::Array(vec![Value::Array(vec![integer(9), value])]),
            Value::Array(Vec::new()),
        ],
    )
}

#[test]
fn a_negative_integer_in_an_unsigned_field_is_invalid() -> TestResult {
    let minus_one = negative(-1);
    // RQE1 `status`, KOE1 `status`, KOE1 `main-pid` and TME1 `progress`.
    assert_eq!(
        RequestedConfigurationEvidence::from_canonical_cbor(&with(
            &unhex(RQE1_A)?,
            &[4],
            minus_one.clone()
        )?)
        .map(|_| ()),
        Err(ProtocolError::InvalidEncoding)
    );
    for path in [[4].as_slice(), &[7, 1]] {
        assert_eq!(
            KernelObservationEvidence::from_canonical_cbor(&with(
                &unhex(KOE1_A)?,
                path,
                minus_one.clone()
            )?)
            .map(|_| ()),
            Err(ProtocolError::InvalidEncoding),
            "KOE1 {path:?}"
        );
    }
    assert_eq!(
        TerminationEvidence::from_canonical_cbor(&with(&unhex(TME1_A)?, &[6], minus_one.clone())?)
            .map(|_| ()),
        Err(ProtocolError::InvalidEncoding)
    );
    // SAU1 `sequence`: the first event's `0` after its attempt ID.
    let first = completed_audit()?.swap_remove(0);
    assert_eq!(
        SandboxAuditRecord::from_canonical_cbor(&first).map(|_| ()),
        Ok(())
    );
    let mut prefix = vec![0x50];
    prefix.extend_from_slice(&[0x11; 16]);
    let mut sequence = prefix.clone();
    sequence.push(0x00);
    prefix.push(0x20);
    let negative_sequence = replaced(&first, &sequence, &prefix)?;
    assert_eq!(
        SandboxAuditRecord::from_canonical_cbor(&negative_sequence).map(|_| ()),
        Err(ProtocolError::InvalidEncoding)
    );
    // ELM1 is only ever digested; its limit values are decoded from the
    // LPS1 `effective-limits` it copies.
    assert!(LaunchPolicy::from_canonical_cbor(&launch_policy(integer(0))?).is_ok());
    assert_eq!(
        LaunchPolicy::from_canonical_cbor(&launch_policy(minus_one)?).map(|_| ()),
        Err(ProtocolError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn a_negative_integer_must_be_in_its_shortest_form() -> TestResult {
    // KOE1-C with the `input` chain at priority -1, encoded `0x20`.
    let priority = [READBACK.as_slice(), &[10, 0, 1, 1]].concat();
    let canonical = with(&unhex(KOE1_C)?, &priority, negative(-1))?;
    let decode = |bytes: &[u8]| KernelObservationEvidence::from_canonical_cbor(bytes).map(|_| ());
    assert_eq!(decode(&canonical), Ok(()));
    // `[0, -1, 1]` with -1 as the two-byte `0x38 0x00`.
    let longer = replaced(
        &canonical,
        &[0x83, 0x00, 0x20, 0x01],
        &[0x83, 0x00, 0x38, 0x00, 0x01],
    )?;
    assert_eq!(decode(&longer), Err(ProtocolError::InvalidEncoding));
    Ok(())
}
