//! Bounded signer selection and explicit certificate checks around webpki.

use std::{collections::BTreeSet, time::Duration};

use cms::{
    cert::CertificateChoices,
    signed_data::{SignedData, SignerIdentifier},
};
use der::{asn1::UintRef, Decode, Encode};
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use x509_cert::{
    ext::pkix::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, NameConstraints, SubjectAltName,
        SubjectKeyIdentifier,
    },
    Certificate,
};

use super::{algorithm, SandboxImageProofError as Error, RSA, RSA_SHA256};

pub(super) struct ProofCertificate<'a> {
    parsed: &'a Certificate,
    public_key: &'a [u8],
    der: Vec<u8>,
}

pub(super) fn decode(signed: &SignedData) -> Result<Vec<ProofCertificate<'_>>, Error> {
    let certificates = signed
        .certificates
        .as_ref()
        .ok_or(Error::UnauthorizedSigner)?;
    // The borrowed envelope check already bounded and ordered this set and
    // every certificate's encoded size before the allocating CMS decode.
    certificates
        .0
        .iter()
        .map(|choice| {
            let CertificateChoices::Certificate(parsed) = choice else {
                return Err(Error::UnsupportedProfile);
            };
            let public_key = validate_certificate_syntax(parsed)?;
            parsed
                .to_der()
                .map_err(Error::from)
                .map(|der| ProofCertificate {
                    parsed,
                    public_key,
                    der,
                })
        })
        .collect()
}

pub(super) fn select_signer(
    certificates: &[ProofCertificate<'_>],
    sid: &SignerIdentifier,
    fingerprint: &[u8; 32],
) -> Result<usize, Error> {
    let mut selected = None;
    for (index, certificate) in certificates.iter().enumerate() {
        let tbs = &certificate.parsed.tbs_certificate;
        let matches = match sid {
            SignerIdentifier::IssuerAndSerialNumber(sid) => {
                sid.issuer == tbs.issuer && sid.serial_number == tbs.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(sid) => tbs
                .get::<SubjectKeyIdentifier>()?
                .is_some_and(|(_, key)| key == *sid),
        };
        if matches && selected.replace(index).is_some() {
            return Err(Error::UnauthorizedSigner);
        }
    }
    let selected = selected.ok_or(Error::UnauthorizedSigner)?;
    let actual: [u8; 32] = Sha256::digest(&certificates[selected].der).into();
    if &actual != fingerprint {
        return Err(Error::UnauthorizedSigner);
    }
    Ok(selected)
}

fn validate_certificate_syntax(certificate: &Certificate) -> Result<&[u8], Error> {
    let tbs = &certificate.tbs_certificate;
    if !algorithm(&certificate.signature_algorithm, RSA_SHA256)
        || !algorithm(&tbs.signature, RSA_SHA256)
        || !algorithm(&tbs.subject_public_key_info.algorithm, RSA)
        || certificate.signature_algorithm != tbs.signature
    {
        return Err(Error::UnsupportedProfile);
    }
    let key_bytes = tbs
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(Error::Malformed)?;
    let [modulus, _exponent] = <[UintRef<'_>; 2]>::from_der(key_bytes)?;
    if modulus.as_bytes().len() != 256 || modulus.as_bytes()[0] < 128 {
        return Err(Error::UnsupportedProfile);
    }
    let mut extensions = BTreeSet::new();
    for extension in tbs.extensions.iter().flatten() {
        if !extensions.insert(extension.extn_id) {
            return Err(Error::Malformed);
        }
        // These are the extensions used below or enforced by the selected
        // webpki path. All other critical extensions remain unsupported.
        if extension.critical
            && !matches!(
                extension.extn_id.to_string().as_str(),
                "2.5.29.15" | "2.5.29.17" | "2.5.29.19" | "2.5.29.30" | "2.5.29.37"
            )
        {
            return Err(Error::UnsupportedProfile);
        }
    }
    Ok(key_bytes)
}

fn validate_usage(certificate: &Certificate, signer: bool) -> Result<(), Error> {
    let tbs = &certificate.tbs_certificate;
    let constraints = tbs.get::<BasicConstraints>()?;
    if tbs
        .get::<SubjectAltName>()?
        .is_some_and(|(_, names)| names.0.is_empty())
    {
        return Err(Error::Malformed);
    }
    if tbs.get::<NameConstraints>()?.is_some() && signer {
        return Err(Error::InvalidPath);
    }
    if let Some((_, usage)) = tbs.get::<KeyUsage>()? {
        let allowed = if signer {
            usage.digital_signature()
        } else {
            usage.key_cert_sign()
        };
        if !allowed {
            return Err(Error::InvalidPath);
        }
    }
    if signer {
        if let Some((_, usage)) = tbs.get::<ExtendedKeyUsage>()? {
            if !usage
                .0
                .iter()
                .any(|oid| oid.to_string() == "1.3.6.1.5.5.7.3.3")
            {
                return Err(Error::InvalidPath);
            }
        }
    } else if !constraints.is_some_and(|(_, constraints)| constraints.ca) {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

fn validate_time(certificate: &Certificate, now: Option<u64>) -> Result<(), Error> {
    let validity = &certificate.tbs_certificate.validity;
    let start = validity.not_before.to_unix_duration().as_secs();
    let end = validity.not_after.to_unix_duration().as_secs();
    if start > end || now.is_some_and(|time| time < start || time > end) {
        return Err(Error::CertificateTime);
    }
    Ok(())
}

fn self_issued(certificate: &ProofCertificate<'_>) -> bool {
    certificate.parsed.tbs_certificate.issuer == certificate.parsed.tbs_certificate.subject
}

fn verify_self_signature(certificate: &ProofCertificate<'_>) -> Result<(), Error> {
    let parsed = certificate.parsed;
    let signature = parsed.signature.as_bytes().ok_or(Error::Malformed)?;
    parsed
        .tbs_certificate
        .to_der()
        .map_err(Error::from)
        .and_then(|tbs| {
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                certificate.public_key,
            )
            .verify(&tbs, signature)
            .map_err(|_| Error::InvalidSignature)
        })
}

pub(super) fn verify_message(
    certificate: &ProofCertificate<'_>,
    content: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let der = CertificateDer::from(certificate.der.as_slice());
    webpki::EndEntityCert::try_from(&der)
        .and_then(|cert| {
            cert.verify_signature(webpki::ring::RSA_PKCS1_2048_8192_SHA256, content, signature)
        })
        .map_err(|_| Error::InvalidSignature)
}

pub(super) fn verify_path(
    certificates: &[ProofCertificate<'_>],
    selected: usize,
    admission_time: u64,
) -> Result<(), Error> {
    let signer = &certificates[selected];
    validate_usage(signer.parsed, true)?;
    validate_time(signer.parsed, Some(admission_time))?;
    if self_issued(signer) {
        if certificates.len() != 1 {
            return Err(Error::InvalidPath);
        }
        return verify_self_signature(signer);
    }
    let anchors: Vec<_> = certificates
        .iter()
        .enumerate()
        .filter(|(_, certificate)| self_issued(certificate))
        .map(|(index, _)| index)
        .collect();
    // Extra roots and certificates not used by the unique complete path are
    // not part of the closed proof profile.
    if anchors.len() != 1 {
        return Err(Error::InvalidPath);
    }
    let root = anchors[0];
    for (index, certificate) in certificates.iter().enumerate() {
        if index != selected {
            validate_usage(certificate.parsed, false)?;
            validate_time(
                certificate.parsed,
                (index != root).then_some(admission_time),
            )?;
        }
    }
    // Trust-anchor extraction does not enforce EKU. A critical root EKU is
    // therefore unsupported rather than silently treated as understood.
    if certificates[root]
        .parsed
        .tbs_certificate
        .get::<ExtendedKeyUsage>()?
        .is_some_and(|(critical, _)| critical)
    {
        return Err(Error::UnsupportedProfile);
    }
    let root_der = CertificateDer::from(certificates[root].der.as_slice());
    let anchor = webpki::anchor_from_trusted_cert(&root_der).map_err(|_| Error::InvalidPath)?;
    verify_self_signature(&certificates[root])?;
    let anchors = [anchor];
    let intermediates: Vec<_> = certificates
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != selected && *index != root)
        .map(|(_, certificate)| CertificateDer::from(certificate.der.as_slice()))
        .collect();
    let leaf_der = CertificateDer::from(signer.der.as_slice());
    let leaf = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| Error::InvalidPath)?;
    let path = leaf
        .verify_for_usage(
            &[
                webpki::ring::RSA_PKCS1_2048_8192_SHA256,
                webpki::ring::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
            ],
            &anchors,
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(admission_time)),
            webpki::KeyUsage::required_if_present(&[43, 6, 1, 5, 5, 7, 3, 3]),
            None,
            None,
        )
        .map_err(|_| Error::InvalidPath)?;
    if path.intermediate_certificates().count() != intermediates.len() {
        return Err(Error::InvalidPath);
    }
    Ok(())
}
