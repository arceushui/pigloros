use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginTrustErrorV1, TrustedPluginRootAnchorV1,
};

mod plugin_trust_vectors {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/plugin_trust_vectors.rs"
    ));
}

#[test]
fn public_verifier_distinguishes_unknown_root_key_from_invalid_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let ptr1 = plugin_trust_vectors::hex_bytes(plugin_trust_vectors::PTR1_HEX)?;
    let prv1 = plugin_trust_vectors::hex_bytes(plugin_trust_vectors::PRV1_HEX)?;
    let baseline_anchor =
        TrustedPluginRootAnchorV1::new("trust.example", *blake3::hash(&ptr1).as_bytes())?;
    let evidence = verify_plugin_trust_v1(&baseline_anchor, &[&ptr1], &[&prv1], 0, 10)?;
    assert_eq!(
        evidence.verified_root_history().collect::<Vec<_>>(),
        vec![(42, *blake3::hash(&ptr1).as_bytes())]
    );
    assert_eq!(
        evidence.verified_revocation_history().collect::<Vec<_>>(),
        vec![(7, *blake3::hash(&prv1).as_bytes())]
    );
    let signature_start = ptr1.len() - 64;
    let signer_id_start = signature_start - 34;
    assert_eq!(&ptr1[signer_id_start - 2..signer_id_start], &[0x58, 0x20]);

    let mut unknown_signer = ptr1.clone();
    unknown_signer[signer_id_start] ^= 1;
    let unknown_anchor =
        TrustedPluginRootAnchorV1::new("trust.example", *blake3::hash(&unknown_signer).as_bytes())?;
    assert!(matches!(
        verify_plugin_trust_v1(&unknown_anchor, &[&unknown_signer], &[&prv1], 0, 10),
        Err(PluginTrustErrorV1::UnknownRootKey)
    ));

    let mut invalid_signature = ptr1;
    let last_signature_byte = invalid_signature.last_mut().ok_or("empty PTR1")?;
    *last_signature_byte ^= 1;
    let invalid_anchor = TrustedPluginRootAnchorV1::new(
        "trust.example",
        *blake3::hash(&invalid_signature).as_bytes(),
    )?;
    assert!(matches!(
        verify_plugin_trust_v1(&invalid_anchor, &[&invalid_signature], &[&prv1], 0, 10),
        Err(PluginTrustErrorV1::InvalidSignature)
    ));
    Ok(())
}
