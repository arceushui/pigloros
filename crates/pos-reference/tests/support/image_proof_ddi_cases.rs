// systemd-repart offline-signed DDI fixtures from `vectors/sim1-ddi`.
//
// The proofs were produced outside the Rust verifier by systemd-repart's
// offline signing workflow (see the vector README). These cases prove the
// accepted CMS profile interoperates with that producer on both supported
// architectures; they do not prove SIM1 admission or systemd/kernel activation.

struct DdiVector {
    architecture: &'static str,
    signature_type: [u8; 16],
    proof: &'static [u8],
    signer: &'static [u8],
    root_hash: &'static [u8],
    image: &'static [u8],
    partitions: &'static [u8],
}

macro_rules! ddi_vector {
    ($architecture:literal, $signature_type:expr_2021) => {
        DdiVector {
            architecture: $architecture,
            signature_type: $signature_type,
            proof: include_bytes!(concat!("../vectors/sim1-ddi/", $architecture, "/proof.der")),
            signer: include_bytes!(concat!(
                "../vectors/sim1-ddi/",
                $architecture,
                "/signer.der"
            )),
            root_hash: include_bytes!(concat!(
                "../vectors/sim1-ddi/",
                $architecture,
                "/root-hash.txt"
            )),
            image: include_bytes!(concat!(
                "../vectors/sim1-ddi/",
                $architecture,
                "/image.raw.gz"
            )),
            partitions: include_bytes!(concat!(
                "../vectors/sim1-ddi/",
                $architecture,
                "/partitions.json"
            )),
        }
    };
}

// Directory names use systemd-repart's `--architecture` names for x86_64 and
// aarch64; the signature type is the DPS root-verity-sig type for each.
const DDI_VECTORS: [DdiVector; 2] = [
    ddi_vector!("x86-64", ROOT_SIGNATURE_X86_64),
    ddi_vector!("arm64", ROOT_PARTITIONS_AARCH64[2]),
];

fn ddi_root_hash(vector: &DdiVector) -> TestResult<[u8; 32]> {
    let text = std::str::from_utf8(vector.root_hash)?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "{}: root hash is not 64 lowercase hex bytes",
            vector.architecture
        )
        .into());
    }
    let mut root_hash = [0; 32];
    for (index, byte) in root_hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
    }
    Ok(root_hash)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]
        })
        .map(char::from)
        .collect()
}

fn standard_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or_default();
        let third = chunk.get(2).copied().unwrap_or_default();
        let indexes = [
            first >> 2,
            ((first & 3) << 4) | (second >> 4),
            ((second & 15) << 2) | (third >> 6),
            third & 63,
        ];
        for (position, index) in indexes.into_iter().enumerate() {
            encoded.push(if position <= chunk.len() {
                char::from(ALPHABET[usize::from(index)])
            } else {
                '='
            });
        }
    }
    encoded
}

#[test]
fn public_proof_verification_accepts_systemd_repart_offline_signatures() -> TestResult {
    for vector in &DDI_VECTORS {
        let fixture = fixture_for_root(vector.proof, vector.signer, ddi_root_hash(vector)?)?;
        verify(&fixture, NOW)?.map_err(|error| format!("{}: {error}", vector.architecture))?;
    }
    let [x86_64, aarch64] = &DDI_VECTORS;
    // Each producer signature authorizes only its own root hash and signer pin.
    for (own, other) in [(x86_64, aarch64), (aarch64, x86_64)] {
        assert_eq!(
            verify(
                &fixture_for_root(own.proof, own.signer, ddi_root_hash(other)?)?,
                NOW
            )?,
            Err(SandboxImageProofError::InvalidSignature),
            "{}",
            own.architecture
        );
        assert_eq!(
            verify(
                &fixture_for_root(own.proof, other.signer, ddi_root_hash(own)?)?,
                NOW
            )?,
            Err(SandboxImageProofError::UnauthorizedSigner),
            "{}",
            own.architecture
        );
    }
    Ok(())
}

#[test]
fn systemd_signature_partitions_embed_the_independently_verified_proof() -> TestResult {
    use std::io::Read as _;

    for vector in &DDI_VECTORS {
        let mut image = Vec::new();
        flate2::read::GzDecoder::new(vector.image).read_to_end(&mut image)?;
        let partitions: [([u8; 16], [u8; 16], u64, u64); 3] =
            serde_json::from_slice(vector.partitions)?;
        let (kind, _, start, length) = partitions[2];
        assert_eq!(kind, vector.signature_type, "{}", vector.architecture);
        let start = usize::try_from(start)?;
        let content = image
            .get(start..start + usize::try_from(length)?)
            .ok_or("signature partition extent")?;
        let used = content
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |last| last + 1);
        let embedded: serde_json::Value = serde_json::from_slice(&content[..used])?;
        assert_eq!(embedded["rootHash"], std::str::from_utf8(vector.root_hash)?);
        assert_eq!(
            embedded["certificateFingerprint"],
            lowercase_hex(&Sha256::digest(vector.signer))
        );
        assert_eq!(embedded["signature"], standard_base64(vector.proof));
    }
    Ok(())
}
