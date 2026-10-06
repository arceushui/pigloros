use pos_core::{
    OutputPolicyClosureEnvelopeErrorV1, OutputPolicyClosureEnvelopeV1,
    MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1,
};

fn encode_opc1(members: [&[u8]; 6]) -> Vec<u8> {
    let mut bytes = Vec::from(&b"OPC1"[..]);
    for member in members {
        let length = u64::try_from(member.len()).unwrap_or(u64::MAX);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(member);
    }
    bytes
}

#[test]
fn shared_decoder_borrows_the_exact_six_native_members() -> Result<(), Box<dyn std::error::Error>> {
    let members = [
        b"eop1".as_slice(),
        b"budget",
        b"implementation",
        b"config",
        b"profile",
        b"retention",
    ];
    let bytes = encode_opc1(members);
    let decoded = OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(&bytes, members[0])?;
    assert_eq!(decoded.eop1_bytes(), members[0]);
    assert_eq!(decoded.executable_budget_bytes(), members[1]);
    assert_eq!(decoded.implementation_artifact(), members[2]);
    assert_eq!(decoded.configuration_artifact(), members[3]);
    assert_eq!(decoded.execution_profile_artifact(), members[4]);
    assert_eq!(decoded.retention_policy_artifact(), members[5]);
    Ok(())
}

#[test]
fn shared_decoder_rejects_bad_magic_truncation_extra_bytes_and_eop_mismatch() {
    let members = [
        b"eop1".as_slice(),
        b"budget",
        b"implementation",
        b"config",
        b"profile",
        b"retention",
    ];
    let bytes = encode_opc1(members);
    let mut bad_magic = bytes.clone();
    bad_magic[0] = b'X';
    assert_eq!(
        OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(&bad_magic, members[0]),
        Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)
    );
    assert_eq!(
        OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(b"OPC1", members[0]),
        Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)
    );
    let mut incomplete_member = Vec::from(&b"OPC1"[..]);
    incomplete_member.extend_from_slice(&1_u64.to_be_bytes());
    assert_eq!(
        OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(&incomplete_member, b"x"),
        Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)
    );
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(
        OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(&extra, members[0]),
        Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)
    );
    assert_eq!(
        OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(&bytes, b"other"),
        Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)
    );
}

#[test]
fn shared_decoder_rejects_unrepresentable_lengths_and_oversized_envelopes() {
    let mut impossible_length = Vec::from(&b"OPC1"[..]);
    impossible_length.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(&impossible_length, b""),
        Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)
    );

    let oversized = vec![0; MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1 + 1];
    assert_eq!(
        OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(&oversized, b""),
        Err(OutputPolicyClosureEnvelopeErrorV1::BoundExceeded)
    );
}

#[test]
fn unbound_decoder_borrows_members_unbound() -> Result<(), Box<dyn std::error::Error>> {
    let members = [
        b"any eop1".as_slice(),
        b"budget",
        b"implementation",
        b"config",
        b"profile",
        b"retention",
    ];
    let bytes = encode_opc1(members);
    let unbound = OutputPolicyClosureEnvelopeV1::from_canonical_bytes_unbound_v1(&bytes)?;
    assert_eq!(unbound.eop1_bytes(), members[0]);
    assert_eq!(unbound.retention_policy_artifact(), members[5]);
    let bound = OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(&bytes, members[0])?;
    assert_eq!(unbound, bound);
    Ok(())
}

#[test]
fn unbound_decoder_keeps_every_framing_and_bound_check() {
    let members = [b"e".as_slice(), b"b", b"i", b"c", b"p", b"r"];
    let bytes = encode_opc1(members);
    let decode = OutputPolicyClosureEnvelopeV1::from_canonical_bytes_unbound_v1;
    let mut extra = bytes.clone();
    extra.push(0);
    let invalid = Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope);
    assert_eq!(decode(&extra), invalid);
    assert_eq!(decode(&bytes[..bytes.len() - 1]), invalid);
    assert_eq!(decode(b"OPC1"), invalid);
    assert_eq!(decode(b"XPC1"), invalid);
    let oversized = vec![0; MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1 + 1];
    let exceeded = Err(OutputPolicyClosureEnvelopeErrorV1::BoundExceeded);
    assert_eq!(decode(&oversized), exceeded);
}
