//! ADR-087 dependency interoperability evidence, not production SIM1 admission.

use cms::{
    cert::CertificateChoices,
    content_info::{CmsVersion, ContentInfo},
    signed_data::{SignedData, SignerIdentifier},
};
use der::{Decode, Encode};

const PROOF: &[u8] = include_bytes!("vectors/sim1-pkcs7/proof.der");
const CERTIFICATE: &[u8] = include_bytes!("vectors/sim1-pkcs7/signer.der");
const CONTENT: &[u8] = include_bytes!("vectors/sim1-pkcs7/root-hash.txt");

#[test]
fn openssl_detached_fixture_matches_the_accepted_algorithm_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let outer = ContentInfo::from_der(PROOF)?;
    assert_eq!(outer.to_der()?, PROOF);
    assert_eq!(outer.content_type.to_string(), "1.2.840.113549.1.7.2");
    let signed: SignedData = outer.content.decode_as()?;
    assert_eq!(signed.version, CmsVersion::V1);
    assert_eq!(
        signed.encap_content_info.econtent_type.to_string(),
        "1.2.840.113549.1.7.1"
    );
    assert!(signed.encap_content_info.econtent.is_none());
    assert!(signed.crls.is_none());
    assert_eq!(signed.digest_algorithms.len(), 1);
    let digest = signed.digest_algorithms.get(0).ok_or("missing digest")?;
    assert_eq!(digest.oid.to_string(), "2.16.840.1.101.3.4.2.1");
    assert_eq!(
        digest
            .parameters
            .as_ref()
            .ok_or("missing digest parameters")?
            .to_der()?,
        [5, 0]
    );

    let certificate = x509_cert::Certificate::from_der(CERTIFICATE)?;
    assert_eq!(certificate.to_der()?, CERTIFICATE);
    let certificates = signed.certificates.as_ref().ok_or("missing certificates")?;
    assert_eq!(certificates.0.len(), 1);
    assert_eq!(
        certificates.0.get(0),
        Some(&CertificateChoices::Certificate(certificate.clone()))
    );
    assert_eq!(signed.signer_infos.0.len(), 1);
    let signer = signed.signer_infos.0.get(0).ok_or("missing signer")?;
    assert_eq!(signer.version, CmsVersion::V1);
    let SignerIdentifier::IssuerAndSerialNumber(sid) = &signer.sid else {
        return Err("fixture must use issuer and serial".into());
    };
    assert_eq!(sid.issuer, certificate.tbs_certificate.issuer);
    assert_eq!(sid.serial_number, certificate.tbs_certificate.serial_number);
    assert_eq!(&signer.digest_alg, digest);
    assert!(signer.signed_attrs.is_none());
    assert!(signer.unsigned_attrs.is_none());
    assert_eq!(
        signer.signature_algorithm.oid.to_string(),
        "1.2.840.113549.1.1.1"
    );
    assert_eq!(
        signer
            .signature_algorithm
            .parameters
            .as_ref()
            .ok_or("missing signature parameters")?
            .to_der()?,
        [5, 0]
    );
    Ok(())
}

#[test]
fn selected_webpki_and_ring_algorithms_verify_the_external_fixture(
) -> Result<(), Box<dyn std::error::Error>> {
    let outer = ContentInfo::from_der(PROOF)?;
    let signed: SignedData = outer.content.decode_as()?;
    let signer = signed.signer_infos.0.get(0).ok_or("missing signer")?;
    let certificate = x509_cert::Certificate::from_der(CERTIFICATE)?;
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    assert_eq!(spki.algorithm, signer.signature_algorithm);
    assert_eq!(
        certificate.signature_algorithm.oid.to_string(),
        "1.2.840.113549.1.1.11"
    );
    assert_eq!(
        certificate.signature_algorithm,
        certificate.tbs_certificate.signature
    );
    assert_eq!(
        certificate
            .signature_algorithm
            .parameters
            .as_ref()
            .ok_or("missing certificate parameters")?
            .to_der()?,
        [5, 0]
    );

    assert_eq!(
        CONTENT,
        b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    assert_eq!(signer.signature.as_bytes().len(), 256);
    let certificate_der = CERTIFICATE.into();
    let verifier = webpki::EndEntityCert::try_from(&certificate_der)?;
    verifier.verify_signature(
        webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        CONTENT,
        signer.signature.as_bytes(),
    )?;
    verifier.verify_signature(
        webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        &certificate.tbs_certificate.to_der()?,
        certificate
            .signature
            .as_bytes()
            .ok_or("unaligned certificate signature")?,
    )?;
    // Pin and exercise the selected backend directly as well as through webpki.
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        spki.subject_public_key
            .as_bytes()
            .ok_or("unaligned public key")?,
    )
    .verify(CONTENT, signer.signature.as_bytes())
    .map_err(|_| "ring rejected fixture")?;
    Ok(())
}

#[test]
fn dependency_verifier_rejects_changed_content_signature_and_invalid_der(
) -> Result<(), Box<dyn std::error::Error>> {
    let outer = ContentInfo::from_der(PROOF)?;
    let signed: SignedData = outer.content.decode_as()?;
    let signer = signed.signer_infos.0.get(0).ok_or("missing signer")?;
    let certificate_der = CERTIFICATE.into();
    let verifier = webpki::EndEntityCert::try_from(&certificate_der)?;
    let mut changed_content = CONTENT.to_vec();
    changed_content[0] = b'1';
    assert!(verifier
        .verify_signature(
            webpki::ring::RSA_PKCS1_2048_8192_SHA256,
            &changed_content,
            signer.signature.as_bytes()
        )
        .is_err());
    let mut changed_signature = signer.signature.as_bytes().to_vec();
    changed_signature[0] ^= 1;
    assert!(verifier
        .verify_signature(
            webpki::ring::RSA_PKCS1_2048_8192_SHA256,
            CONTENT,
            &changed_signature
        )
        .is_err());
    let mut trailing = PROOF.to_vec();
    trailing.push(0);
    assert!(ContentInfo::from_der(&trailing).is_err());
    assert!(ContentInfo::from_der(&PROOF[..PROOF.len() - 1]).is_err());
    Ok(())
}
