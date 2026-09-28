//! Independent verification of the closed ADR-087 SIM1 CMS profile.

mod certificates;

use cms::{
    content_info::{CmsVersion, ContentInfo},
    signed_data::{SignedData, SignerIdentifier, SignerInfo},
};
use der::{asn1::ObjectIdentifier, Decode, Encode};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::sandbox_provider_protocol::AdmittedSandboxImage;

const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// Bounded failures from independent SIM1 proof verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SandboxImageProofError {
    /// The proof or a certificate is not one complete canonical DER value.
    #[error("malformed image proof")]
    Malformed,
    /// The CMS or certificate algorithm/profile is unsupported.
    #[error("unsupported image proof profile")]
    UnsupportedProfile,
    /// No unique signer matches the authenticated SIM1 certificate pin.
    #[error("unauthorized image proof signer")]
    UnauthorizedSigner,
    /// The detached signature or certificate self-signature is invalid.
    #[error("invalid image proof signature")]
    InvalidSignature,
    /// The bounded certificate set cannot form the required valid path.
    #[error("invalid image proof certificate path")]
    InvalidPath,
    /// Certificate validity is incoherent or excludes the supplied admission time.
    #[error("invalid image proof certificate time")]
    CertificateTime,
    /// The image is not authorized by this provider's authenticated snapshots.
    #[error("image proof authority mismatch")]
    AuthorityMismatch,
    /// The proof exceeds the accepted certificate resource limits.
    #[error("image proof resource limit")]
    ResourceLimit,
}

impl From<der::Error> for SandboxImageProofError {
    fn from(_: der::Error) -> Self {
        Self::Malformed
    }
}

pub(crate) fn verify(
    image: &AdmittedSandboxImage,
    admission_time: u64,
) -> Result<(), SandboxImageProofError> {
    // The immutable admitted image already enforces SIM1's proof length,
    // SHA-256 and 1 MiB cap before this DER decoder can allocate.
    let manifest = image.manifest();
    let outer = ContentInfo::from_der(&manifest.root_hash_signature.der_bytes)?;
    if outer.to_der()? != manifest.root_hash_signature.der_bytes {
        return Err(SandboxImageProofError::Malformed);
    }
    if outer.content_type != SIGNED_DATA {
        return Err(SandboxImageProofError::UnsupportedProfile);
    }
    let cms_data: SignedData = outer.content.decode_as()?;
    if cms_data.to_der()? != outer.content.to_der()? {
        return Err(SandboxImageProofError::Malformed);
    }
    let signer = validate_profile(&cms_data)?;
    let certificates = certificates::decode(&cms_data)?;
    let selected = certificates::select_signer(
        &certificates,
        &signer.sid,
        &manifest.signing_certificate_sha256,
    )?;
    certificates::verify_path(&certificates, selected, admission_time)?;
    let content = root_hash_hex(&manifest.root_hash_sha256);
    certificates::verify_message(
        &certificates[selected],
        &content,
        signer.signature.as_bytes(),
    )
}

fn validate_profile(cms_data: &SignedData) -> Result<&SignerInfo, SandboxImageProofError> {
    if cms_data.encap_content_info.econtent_type != DATA
        || cms_data.encap_content_info.econtent.is_some()
        || cms_data.crls.is_some()
    {
        return Err(SandboxImageProofError::UnsupportedProfile);
    }
    let [digest] = cms_data.digest_algorithms.as_slice() else {
        return Err(SandboxImageProofError::UnsupportedProfile);
    };
    let [signer] = cms_data.signer_infos.0.as_slice() else {
        return Err(SandboxImageProofError::UnsupportedProfile);
    };
    let version = match signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
        SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
    };
    // With only X.509 certificates, id-data and no CRLs, RFC 5652 derives the
    // SignedData version directly from its sole SignerInfo's SID form.
    if cms_data.version != version
        || signer.version != version
        || signer.signed_attrs.is_some()
        || signer.unsigned_attrs.is_some()
        || !algorithm(digest, SHA256)
        || !algorithm(&signer.digest_alg, SHA256)
        || !algorithm(&signer.signature_algorithm, RSA)
    {
        return Err(SandboxImageProofError::UnsupportedProfile);
    }
    Ok(signer)
}

fn algorithm(value: &AlgorithmIdentifierOwned, oid: ObjectIdentifier) -> bool {
    value.oid == oid && value.parameters.as_ref().is_none_or(der::Any::is_null)
}

fn root_hash_hex(hash: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0; 64];
    for (byte, pair) in hash.iter().zip(encoded.chunks_exact_mut(2)) {
        pair[0] = HEX[usize::from(byte >> 4)];
        pair[1] = HEX[usize::from(byte & 15)];
    }
    encoded
}
