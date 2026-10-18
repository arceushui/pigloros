// systemd-repart offline-signed DDI fixtures from `vectors/sim1-ddi`.
//
// The proofs were produced outside the Rust verifier by systemd-repart's
// offline signing workflow (see the vector README). These cases prove the
// accepted CMS profile interoperates with that producer on both supported
// architectures; they do not prove SIM1 admission or systemd/kernel activation.

struct DdiVector {
    architecture: &'static str,
    architecture_code: u64,
    signature_type: [u8; 16],
    proof: &'static [u8],
    signer: &'static [u8],
    root_hash: &'static [u8],
    image: &'static [u8],
    partitions: &'static [u8],
    verity: &'static [u8],
}

macro_rules! ddi_vector {
    ($architecture:literal, $code:literal, $signature_type:expr_2021) => {
        DdiVector {
            architecture: $architecture,
            architecture_code: $code,
            signature_type: $signature_type,
            verity: include_bytes!(concat!(
                "../vectors/sim1-ddi/",
                $architecture,
                "/verity.json"
            )),
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
    ddi_vector!("x86-64", 0, ROOT_SIGNATURE_X86_64),
    ddi_vector!("arm64", 1, ROOT_PARTITIONS_AARCH64[2]),
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

fn ddi_image(vector: &DdiVector) -> TestResult<Vec<u8>> {
    use std::io::Read as _;

    let mut image = Vec::new();
    flate2::read::GzDecoder::new(vector.image).read_to_end(&mut image)?;
    Ok(image)
}

fn ddi_salt(vector: &DdiVector) -> TestResult<[u8; 32]> {
    let verity: serde_json::Value = serde_json::from_slice(vector.verity)?;
    let text = verity["salt"].as_str().ok_or("verity salt is not text")?;
    let mut salt = [0; 32];
    if text.len() != 64 {
        return Err(format!("{}: salt is not 32 bytes", vector.architecture).into());
    }
    for (index, byte) in salt.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
    }
    Ok(salt)
}

// The kernel's x509 key description for these CN-only certificates: the
// subject common name, ": ", then the lowercase subject key identifier.
fn kernel_key_description(certificate: &[u8]) -> TestResult<String> {
    const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
    let certificate = Certificate::from_der(certificate)?;
    let common_name = certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|name| name.0.iter())
        .find(|attribute| attribute.oid == COMMON_NAME)
        .ok_or("certificate has no common name")?
        .value
        .decode_as::<der::asn1::Utf8StringRef<'_>>()?
        .as_str()
        .to_owned();
    let (_, key_id) = certificate
        .tbs_certificate
        .get::<SubjectKeyIdentifier>()?
        .ok_or("certificate has no subject key identifier")?;
    Ok(format!(
        "{common_name}: {}",
        lowercase_hex(key_id.0.as_bytes())
    ))
}

fn ddi_partitions(vector: &DdiVector, image: &[u8]) -> TestResult<Value> {
    let declared: [([u8; 16], [u8; 16], u64, u64); 3] = serde_json::from_slice(vector.partitions)?;
    let mut partitions = Vec::new();
    for (role, (kind, instance, start, length)) in (0_u64..).zip(declared) {
        let first = usize::try_from(start)?;
        let content = image
            .get(first..first + usize::try_from(length)?)
            .ok_or("partition extent")?;
        partitions.push(Value::Array(vec![
            integer(role),
            Value::Bytes(kind.to_vec()),
            Value::Bytes(instance.to_vec()),
            integer(start),
            integer(length),
            bytes(*blake3::hash(content).as_bytes()),
        ]));
    }
    Ok(Value::Array(partitions))
}

/// A complete SIM1 for one real systemd-repart image, signed by the fixture
/// image-project key and authorized by a TRS1 binding its real certificate.
fn ddi_fixture(vector: &DdiVector, salt: [u8; 32]) -> TestResult<Fixture> {
    let mut fixture = Fixture::with_architecture(vector.architecture_code)?;
    let fingerprint: [u8; 32] = Sha256::digest(vector.signer).into();
    let description = kernel_key_description(vector.signer)?;
    fixture.trust = fixture
        .authority
        .trust_with_key(fingerprint, &description)?;
    fixture.revocation = revocation(&fixture.trust, &fixture.authority, vec![], vec![])?;
    let image = ddi_image(vector)?;
    fixture.sim1 = resign_unsigned_fields(
        &fixture.sim1,
        "SIM1",
        &[
            (4, integer(u64::try_from(image.len())?)),
            (5, bytes(*blake3::hash(&image).as_bytes())),
            (6, ddi_partitions(vector, &image)?),
            (7, bytes(ddi_root_hash(vector)?)),
            (11, bytes(salt)),
            (
                12,
                Value::Array(vec![
                    integer(u64::try_from(vector.proof.len())?),
                    Value::Bytes(Sha256::digest(vector.proof).to_vec()),
                    Value::Bytes(vector.proof.to_vec()),
                ]),
            ),
            (13, bytes(fingerprint)),
            (14, Value::Text(description)),
        ],
        &fixture.authority.image,
    )?;
    fixture.root_image = image;
    fixture.lps1 = launch_policy(wrapped_digest(&fixture.sim1)?)?;
    fixture.policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
    Ok(fixture)
}

#[test]
fn public_admission_accepts_a_sim1_describing_each_systemd_repart_image() -> TestResult {
    for vector in &DDI_VECTORS {
        let salt = ddi_salt(vector)?;
        let fixture = ddi_fixture(vector, salt)?;
        let provider = fixture.admit()?;
        let image =
            provider.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
        assert_eq!(
            image.manifest().verity_salt,
            salt,
            "{}",
            vector.architecture
        );
        assert_eq!(
            image.manifest().kernel_key_description,
            kernel_key_description(vector.signer)?
        );
        provider
            .verify_image_proof(&image, NOW)
            .map_err(|error| format!("{}: {error}", vector.architecture))?;
    }
    Ok(())
}

#[test]
fn public_admission_requires_the_trs1_kernel_key_description() -> TestResult {
    for vector in &DDI_VECTORS {
        let mut fixture = ddi_fixture(vector, ddi_salt(vector)?)?;
        // Same signed fingerprint, but a different built-in key description.
        fixture.trust = fixture
            .authority
            .trust_with_key(Sha256::digest(vector.signer).into(), "PiglorOS other: 00")?;
        fixture.revocation = revocation(&fixture.trust, &fixture.authority, vec![], vec![])?;
        fixture.policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
        assert_eq!(
            fixture
                .admit()?
                .admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable),
            Err(SandboxAdmissionError::CertificateMismatch),
            "{}",
            vector.architecture
        );
    }
    Ok(())
}
