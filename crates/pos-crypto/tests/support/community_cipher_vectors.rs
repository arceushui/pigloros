//! Published, readable AES-GCM-SIV known-answer corpus shared by both seams.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KnownAnswer {
    pub(super) id: String,
    reference: String,
    pub(super) key: [u8; 32],
    pub(super) nonce: [u8; 12],
    pub(super) aad: Vec<u8>,
    pub(super) plaintext: Vec<u8>,
    pub(super) ciphertext_and_tag: Vec<u8>,
}

/// Pin the independent values, exact case inventory and upstream provenance.
/// The corpus is test input, never a production key/nonce configuration.
pub(super) fn load() -> Result<[KnownAnswer; 3], Box<dyn std::error::Error>> {
    let encoded = include_bytes!("../vectors/community-aes-gcm-siv.json");
    let cases: [KnownAnswer; 3] = serde_json::from_slice(encoded)?;
    // Pin values independently of JSON whitespace or formatting.
    let canonical = serde_json::to_vec(&cases)?;
    let digest: [u8; 32] = Sha256::digest(&canonical).into();
    assert_eq!(
        digest,
        [
            0xd2, 0x3f, 0xbd, 0xee, 0x3a, 0x0d, 0x40, 0x06, 0x8d, 0x16, 0x9b, 0x8d, 0x60, 0xdf,
            0x22, 0x55, 0x75, 0x20, 0x67, 0x71, 0xd8, 0xd9, 0xc2, 0x9b, 0x6c, 0x2d, 0x1a, 0x35,
            0xd0, 0x95, 0xe2, 0xf2
        ]
    );
    assert_eq!(
        cases.each_ref().map(|case| case.id.as_str()),
        [
            "rfc8452-c2-empty",
            "rfc8452-c2-eight-bytes",
            "wycheproof-139"
        ]
    );
    for case in &cases[..2] {
        assert_eq!(
            case.reference,
            "https://www.rfc-editor.org/rfc/rfc8452#appendix-C.2"
        );
    }
    assert_eq!(cases[2].reference, "https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/aes_gcm_siv_test.json");
    Ok(cases)
}
