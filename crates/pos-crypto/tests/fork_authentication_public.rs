use ciborium::value::Value;
use pos_crypto::fork_authentication::{ForkAuthenticationSignatureErrorV1, ForkHostSigningKeyV1};

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn bytes(value: u8, length: usize) -> Value {
    Value::Bytes(vec![value; length])
}

#[test]
fn host_proof_decoders_reject_full_length_wrong_marker_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkHostSigningKeyV1::from_seed([4; 32])?;
    let initialize = encode(&Value::Array(vec![
        Value::Text("BAD1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        Value::Bytes(host.public_key().to_vec()),
        bytes(4, 32),
    ]))?;
    assert_eq!(initialize.len(), 143);
    assert_eq!(
        host.sign_initialize(&initialize),
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    );

    let open = encode(&Value::Array(vec![
        Value::Text("BAD1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
    ]))?;
    assert_eq!(open.len(), 109);
    assert_eq!(
        host.sign_open(&open),
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    );

    let recovery = encode(&Value::Array(vec![
        Value::Text("BAD1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        Value::Integer(1.into()),
        bytes(3, 32),
    ]))?;
    assert_eq!(recovery.len(), 110);
    assert_eq!(
        host.sign_recovery(&recovery),
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    );
    Ok(())
}
