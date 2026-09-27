use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginTrustErrorV1, TrustedPluginRootAnchorV1,
};

const PTR1_HEX: &str = "8c6450545231016d74727573742e6578616d706c65182a201a01e284fff601818258209d7043381b703609599e44f8e8c09abb52faad21b96b60306764dfcb160712935820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787378184697075626c697368657203095820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f081826c616c7068612f706c7567696e697075626c6973686572818258209d7043381b703609599e44f8e8c09abb52faad21b96b60306764dfcb16071293584008e30fd5d68f52f16af09657e58937789e4fbf37f306204d4bf0b6756eabd5a34bd445246cbdde58cdf8bd6e3a7d9b39010f93c79543fc6001f96cf979492407";

fn hex_bytes(value: &str) -> Result<Vec<u8>, &'static str> {
    let pairs = value.as_bytes().chunks_exact(2);
    if !pairs.remainder().is_empty() {
        return Err("hex input has an odd length");
    }
    pairs
        .map(|pair| {
            let nibble = |byte| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err("hex input contains a non-lowercase digit"),
            };
            Ok((nibble(pair[0])? << 4) | nibble(pair[1])?)
        })
        .collect()
}

#[test]
fn public_verifier_distinguishes_unknown_root_key_from_invalid_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let ptr1 = hex_bytes(PTR1_HEX)?;
    let signature_start = ptr1.len() - 64;
    let signer_id_start = signature_start - 34;
    assert_eq!(&ptr1[signer_id_start - 2..signer_id_start], &[0x58, 0x20]);

    let mut unknown_signer = ptr1.clone();
    unknown_signer[signer_id_start] ^= 1;
    let unknown_anchor =
        TrustedPluginRootAnchorV1::new("trust.example", *blake3::hash(&unknown_signer).as_bytes())?;
    assert!(matches!(
        verify_plugin_trust_v1(&unknown_anchor, &[&unknown_signer], &[], 0, 0),
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
        verify_plugin_trust_v1(&invalid_anchor, &[&invalid_signature], &[], 0, 0),
        Err(PluginTrustErrorV1::InvalidSignature)
    ));
    Ok(())
}
