// Certificate attacks enter through the public provider operation. Rebinding
// the test SIM1 pin ensures rejection is due to the certificate rule itself.
fn edited_certificate(
    edit: impl FnOnce(&mut Certificate) -> TestResult,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let mut certificate = Certificate::from_der(CERTIFICATE)?;
    edit(&mut certificate)?;
    let encoded = certificate.to_der()?;
    let proof = edit_cms(PROOF, |cms_data| {
        cms_data.certificates =
            Some(vec![CertificateChoices::Certificate(certificate)].try_into()?);
        Ok(())
    })?;
    Ok((proof, encoded))
}

fn replace_extension(certificate: &mut Certificate, oid: &str, value: &[u8]) -> TestResult {
    let oid = ObjectIdentifier::new(oid)?;
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_mut()
        .ok_or("missing extensions")?;
    extensions.retain(|extension| extension.extn_id != oid);
    extensions.push(Extension {
        extn_id: oid,
        critical: true,
        extn_value: OctetString::new(value)?,
    });
    Ok(())
}

#[test]
fn public_proof_verification_rejects_certificate_extension_violations() -> TestResult {
    for (oid, value, expected) in [
        // Unknown critical extension; malformed and empty SAN; signer NC;
        // KU granting only keyCertSign; serverAuth instead of codeSigning.
        (
            "1.2.3.4",
            &[5, 0][..],
            SandboxImageProofError::UnsupportedProfile,
        ),
        ("2.5.29.17", &[5, 0][..], SandboxImageProofError::Malformed),
        ("2.5.29.19", &[5, 0][..], SandboxImageProofError::Malformed),
        ("2.5.29.30", &[5, 0][..], SandboxImageProofError::Malformed),
        ("2.5.29.15", &[5, 0][..], SandboxImageProofError::Malformed),
        ("2.5.29.37", &[5, 0][..], SandboxImageProofError::Malformed),
        (
            "2.5.29.17",
            &[0x30, 0][..],
            SandboxImageProofError::Malformed,
        ),
        (
            "2.5.29.30",
            &[0x30, 0][..],
            SandboxImageProofError::InvalidPath,
        ),
        (
            "2.5.29.15",
            &[3, 2, 2, 4][..],
            SandboxImageProofError::InvalidPath,
        ),
        (
            "2.5.29.37",
            &[0x30, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1][..],
            SandboxImageProofError::InvalidPath,
        ),
    ] {
        let (proof, certificate) =
            edited_certificate(|certificate| replace_extension(certificate, oid, value))?;
        assert_eq!(
            verify(&fixture(&proof, &certificate)?, NOW)?,
            Err(expected),
            "{oid}"
        );
    }
    let (proof, certificate) = edited_certificate(|certificate| {
        let extensions = certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .ok_or("missing extensions")?;
        extensions.push(extensions.first().ok_or("no extension")?.clone());
        Ok(())
    })?;
    assert_eq!(
        verify(&fixture(&proof, &certificate)?, NOW)?,
        Err(SandboxImageProofError::Malformed)
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum CertificateDefect {
    SignatureAlgorithm,
    TbsAlgorithm,
    PublicKeyAlgorithm,
    AlgorithmParameterMismatch,
    MalformedPublicKey,
    ShortModulus,
    InvalidSelfSignature,
    IncoherentTime,
    UnmatchedSerial,
}

fn certificate_defect(certificate: &mut Certificate, defect: CertificateDefect) -> TestResult {
    let other = ObjectIdentifier::new("1.2.3.4")?;
    match defect {
        CertificateDefect::SignatureAlgorithm => certificate.signature_algorithm.oid = other,
        CertificateDefect::TbsAlgorithm => certificate.tbs_certificate.signature.oid = other,
        CertificateDefect::PublicKeyAlgorithm => {
            certificate
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .oid = other;
        }
        CertificateDefect::AlgorithmParameterMismatch => {
            certificate.signature_algorithm.parameters = None;
        }
        CertificateDefect::MalformedPublicKey => {
            certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key = der::asn1::BitString::from_bytes(&[0])?;
        }
        CertificateDefect::ShortModulus => {
            // A canonical RSA key with a one-byte modulus and exponent 3.
            certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key =
                der::asn1::BitString::from_bytes(&[0x30, 6, 2, 1, 127, 2, 1, 3])?;
        }
        CertificateDefect::InvalidSelfSignature => {
            certificate.signature = der::asn1::BitString::from_bytes(&[0; 256])?;
        }
        CertificateDefect::IncoherentTime => {
            let validity = &mut certificate.tbs_certificate.validity;
            std::mem::swap(&mut validity.not_before, &mut validity.not_after);
        }
        CertificateDefect::UnmatchedSerial => {
            certificate.tbs_certificate.serial_number =
                x509_cert::serial_number::SerialNumber::new(&[99])?;
        }
    }
    Ok(())
}

#[test]
fn public_proof_verification_rejects_invalid_certificate_identity_and_crypto() -> TestResult {
    for (defect, expected) in [
        (
            CertificateDefect::SignatureAlgorithm,
            SandboxImageProofError::UnsupportedProfile,
        ),
        (
            CertificateDefect::TbsAlgorithm,
            SandboxImageProofError::UnsupportedProfile,
        ),
        (
            CertificateDefect::PublicKeyAlgorithm,
            SandboxImageProofError::UnsupportedProfile,
        ),
        (
            CertificateDefect::AlgorithmParameterMismatch,
            SandboxImageProofError::UnsupportedProfile,
        ),
        (
            CertificateDefect::MalformedPublicKey,
            SandboxImageProofError::Malformed,
        ),
        (
            CertificateDefect::ShortModulus,
            SandboxImageProofError::UnsupportedProfile,
        ),
        (
            CertificateDefect::InvalidSelfSignature,
            SandboxImageProofError::InvalidSignature,
        ),
        (
            CertificateDefect::IncoherentTime,
            SandboxImageProofError::CertificateTime,
        ),
        (
            CertificateDefect::UnmatchedSerial,
            SandboxImageProofError::UnauthorizedSigner,
        ),
    ] {
        let (proof, certificate) =
            edited_certificate(|certificate| certificate_defect(certificate, defect))?;
        assert_eq!(
            verify(&fixture(&proof, &certificate)?, NOW)?,
            Err(expected),
            "{defect:?}"
        );
    }
    Ok(())
}

#[test]
fn public_proof_verification_rejects_ambiguous_and_excessive_certificate_sets() -> TestResult {
    for (count, expected) in [
        (2, SandboxImageProofError::UnauthorizedSigner),
        (9, SandboxImageProofError::ResourceLimit),
    ] {
        let proof = edit_cms(PROOF, |cms_data| {
            let mut choices = Vec::new();
            for marker in 0_u8..count {
                let mut certificate = Certificate::from_der(CERTIFICATE)?;
                // Retain the same SID while giving each certificate unique DER.
                certificate.signature = der::asn1::BitString::from_bytes(&[marker; 256])?;
                choices.push(CertificateChoices::Certificate(certificate));
            }
            cms_data.certificates = Some(choices.try_into()?);
            Ok(())
        })?;
        assert_eq!(verify(&fixture(&proof, CERTIFICATE)?, NOW)?, Err(expected));
    }
    Ok(())
}

#[test]
fn public_proof_verification_rejects_non_x509_certificate_choices() -> TestResult {
    let proof = edit_cms(PROOF, |cms_data| {
        cms_data.certificates = Some(
            vec![CertificateChoices::Other(
                cms::cert::OtherCertificateFormat {
                    other_cert_format: ObjectIdentifier::new("1.2.3.4")?,
                    other_cert: der::Any::null(),
                },
            )]
            .try_into()?,
        );
        Ok(())
    })?;
    assert_eq!(
        verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
        Err(SandboxImageProofError::UnsupportedProfile)
    );
    Ok(())
}

#[test]
fn public_proof_verification_rejects_unused_key_and_signature_bits() -> TestResult {
    for key in [true, false] {
        let (proof, certificate) = edited_certificate(|certificate| {
            let bits = der::asn1::BitString::new(1, vec![0; 256])?;
            if key {
                certificate
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key = bits;
            } else {
                certificate.signature = bits;
            }
            Ok(())
        })?;
        assert_eq!(
            verify(&fixture(&proof, &certificate)?, NOW)?,
            Err(SandboxImageProofError::Malformed)
        );
    }
    Ok(())
}

#[test]
fn public_proof_verification_rejects_malformed_subject_key_identifier() -> TestResult {
    let original = Certificate::from_der(CERTIFICATE)?;
    let (_, key_id) = original
        .tbs_certificate
        .get::<SubjectKeyIdentifier>()?
        .ok_or("missing SKI")?;
    let (proof, certificate) = edited_certificate(|certificate| {
        let extension = certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .ok_or("missing extensions")?
            .iter_mut()
            .find(|extension| extension.extn_id.to_string() == "2.5.29.14")
            .ok_or("missing SKI extension")?;
        extension.extn_value = OctetString::new([5, 0])?;
        Ok(())
    })?;
    let proof = edit_cms(&proof, |cms_data| {
        let mut signer = cms_data
            .signer_infos
            .0
            .get(0)
            .ok_or("missing signer")?
            .clone();
        signer.sid = SignerIdentifier::SubjectKeyIdentifier(key_id);
        signer.version = CmsVersion::V3;
        cms_data.version = CmsVersion::V3;
        cms_data.signer_infos = vec![signer].try_into()?;
        Ok(())
    })?;
    assert_eq!(
        verify(&fixture(&proof, &certificate)?, NOW)?,
        Err(SandboxImageProofError::Malformed)
    );
    Ok(())
}
