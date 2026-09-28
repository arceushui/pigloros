//! Purpose-limited Ed25519 operations for ADR-106 Fork authentication.
//!
//! This module performs portable cryptographic validation only. Credential
//! custody, trusted authentication production, and durable Fork-admission
//! orchestration remain owned by the Gateway and store adapters.

use std::io::Cursor;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pos_core::{
    fork_authentication::{
        AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
        ForkAuthenticationPolicyV1, MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1,
    },
    OwnerIdV1, Signature,
};
use thiserror::Error;
use zeroize::Zeroize;

const ADAPTER_DOMAIN: &[u8] = b"pigloros/authenticated-principal-result/v1";
const INITIALIZE_DOMAIN: &[u8] = b"pigloros/fork-admission-host-bootstrap/v1";
const OPEN_DOMAIN: &[u8] = b"pigloros/fork-admission-host-open/v1";
const COMMAND_DOMAIN: &[u8] = b"pigloros/fork-admission-host-command/v1";
const RECOVERY_DOMAIN: &[u8] = b"pigloros/fork-admission-recovery/v1";

const MAX_POC1_BYTES: usize = 307;
const MAX_FCC1_BYTES: usize = 412;
const FAI1_BYTES: usize = 143;
const FAO1_BYTES: usize = 109;
const FRC1_BYTES: usize = 110;

/// Closed failures for Fork-authentication signatures and typed host proofs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForkAuthenticationSignatureErrorV1 {
    #[error("Fork authentication signing seed is invalid")]
    InvalidSeed,
    #[error("Fork authentication policy does not authorize the evidence")]
    PolicyMismatch,
    #[error("Fork authentication verification key is invalid")]
    InvalidVerifyingKey,
    #[error("Fork authentication signature is invalid")]
    InvalidSignature,
    #[error("Fork authentication record is invalid")]
    InvalidRecord,
}

/// A verified APS1 whose policy provenance has been checked.
///
/// The host signing API requires this type so a caller cannot substitute a
/// merely decodable APS1 for policy-verified authentication evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthenticatedPrincipalEvidenceV1(AuthenticatedPrincipalEvidenceV1);

impl VerifiedAuthenticatedPrincipalEvidenceV1 {
    /// Return the exact policy-verified APS1.
    #[must_use]
    pub const fn evidence(&self) -> &AuthenticatedPrincipalEvidenceV1 {
        &self.0
    }
}

/// Verify APS1 against the selected FAP1 adapter policy.
///
/// This verifies only the exact ADR-106 adapter signature and policy facts. It
/// does not resolve an Owner, check expiry, or grant durable authority.
///
/// # Errors
/// Rejects missing or insufficient adapter policy, malformed verification key,
/// and a signature that does not cover the exact canonical APR1 bytes.
pub fn verify_authenticated_principal_evidence_v1(
    policy: &ForkAuthenticationPolicyV1,
    evidence: AuthenticatedPrincipalEvidenceV1,
) -> Result<VerifiedAuthenticatedPrincipalEvidenceV1, ForkAuthenticationSignatureErrorV1> {
    let record = evidence.record();
    let Some(adapter) = policy.adapter(&record.adapter_id) else {
        return Err(ForkAuthenticationSignatureErrorV1::PolicyMismatch);
    };
    if record.assurance < adapter.minimum_assurance
        || !adapter.registry_bindings.contains(&record.registry_binding)
    {
        return Err(ForkAuthenticationSignatureErrorV1::PolicyMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&adapter.verifying_key)
        .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)?;
    let record_bytes = record
        .to_canonical_cbor()
        .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)?;
    verify_signature(
        &verifying_key,
        ADAPTER_DOMAIN,
        &record_bytes,
        evidence.signature(),
    )?;
    Ok(VerifiedAuthenticatedPrincipalEvidenceV1(evidence))
}

/// Non-cloneable Ed25519 material that can sign only a typed APR1.
pub struct ForkAuthenticationAdapterSigningKeyV1 {
    signing_key: Box<SigningKey>,
    public_key: [u8; 32],
}

impl ForkAuthenticationAdapterSigningKeyV1 {
    /// Construct adapter signing material from one nonzero Ed25519 seed.
    ///
    /// The local seed copy is zeroized after the signing key has been built.
    ///
    /// # Errors
    /// Rejects the all-zero seed required to fail closed by ADR-107.
    pub fn from_seed(mut seed: [u8; 32]) -> Result<Self, ForkAuthenticationSignatureErrorV1> {
        if seed == [0; 32] {
            seed.zeroize();
            return Err(ForkAuthenticationSignatureErrorV1::InvalidSeed);
        }
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self {
            public_key: signing_key.verifying_key().to_bytes(),
            signing_key: Box::new(signing_key),
        })
    }

    /// Return the corresponding public verification key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Sign exactly one validated APR1 into APS1.
    ///
    /// # Errors
    /// Rejects an APR1 that fails its core structural validation.
    pub fn sign_authenticated_principal(
        &self,
        record: AuthenticatedPrincipalRecordV1,
    ) -> Result<AuthenticatedPrincipalEvidenceV1, ForkAuthenticationSignatureErrorV1> {
        record
            .validate()
            .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)?;
        let record_bytes = record
            .to_canonical_cbor()
            .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)?;
        let signature = sign_preimage(&self.signing_key, ADAPTER_DOMAIN, &record_bytes);
        AuthenticatedPrincipalEvidenceV1::new(record, *signature.as_bytes())
            .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)
    }
}

/// Non-cloneable Ed25519 material for ADR-106 host proofs.
///
/// It offers no generic signing operation and never exposes the raw seed.
pub struct ForkHostSigningKeyV1 {
    signing_key: Box<SigningKey>,
    public_key: [u8; 32],
}

impl ForkHostSigningKeyV1 {
    /// Construct host signing material from one nonzero Ed25519 seed.
    ///
    /// The local seed copy is zeroized after the signing key has been built.
    ///
    /// # Errors
    /// Rejects the all-zero seed required to fail closed by ADR-107.
    pub fn from_seed(mut seed: [u8; 32]) -> Result<Self, ForkAuthenticationSignatureErrorV1> {
        if seed == [0; 32] {
            seed.zeroize();
            return Err(ForkAuthenticationSignatureErrorV1::InvalidSeed);
        }
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self {
            public_key: signing_key.verifying_key().to_bytes(),
            signing_key: Box::new(signing_key),
        })
    }

    /// Return the corresponding public verification key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Sign one exact canonical FAI1 initialize challenge.
    ///
    /// # Errors
    /// Rejects a noncanonical or structurally invalid FAI1 payload.
    pub fn sign_initialize(
        &self,
        challenge: &[u8],
    ) -> Result<Signature, ForkAuthenticationSignatureErrorV1> {
        validate_fai1(challenge, &self.public_key)?;
        Ok(sign_preimage(
            &self.signing_key,
            INITIALIZE_DOMAIN,
            challenge,
        ))
    }

    /// Sign one exact canonical FAO1 open challenge.
    ///
    /// # Errors
    /// Rejects a noncanonical or structurally invalid FAO1 payload.
    pub fn sign_open(
        &self,
        challenge: &[u8],
    ) -> Result<Signature, ForkAuthenticationSignatureErrorV1> {
        validate_fao1(challenge)?;
        Ok(sign_preimage(&self.signing_key, OPEN_DOMAIN, challenge))
    }

    /// Sign one exact POC1 or FCC1 plus policy-verified APS1.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical command bytes. The typed evidence cannot
    /// be constructed without an earlier FAP1 policy and Ed25519 check.
    pub fn sign_command(
        &self,
        command: &[u8],
        evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
    ) -> Result<Signature, ForkAuthenticationSignatureErrorV1> {
        validate_command(command)?;
        let evidence_bytes = evidence
            .evidence()
            .to_canonical_cbor()
            .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)?;
        if evidence_bytes.len() > MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1 {
            return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
        }
        let mut preimage =
            Vec::with_capacity(COMMAND_DOMAIN.len() + command.len() + evidence_bytes.len());
        preimage.extend_from_slice(COMMAND_DOMAIN);
        preimage.extend_from_slice(command);
        preimage.extend_from_slice(&evidence_bytes);
        Ok(Signature::from_bytes(
            self.signing_key.sign(&preimage).to_bytes(),
        ))
    }

    /// Sign one exact canonical FRC1 recovery command.
    ///
    /// # Errors
    /// Rejects a noncanonical or structurally invalid FRC1 payload.
    pub fn sign_recovery(
        &self,
        command: &[u8],
    ) -> Result<Signature, ForkAuthenticationSignatureErrorV1> {
        validate_frc1(command)?;
        Ok(sign_preimage(&self.signing_key, RECOVERY_DOMAIN, command))
    }
}

fn sign_preimage(signing_key: &SigningKey, domain: &[u8], payload: &[u8]) -> Signature {
    let mut preimage = Vec::with_capacity(domain.len() + payload.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(payload);
    Signature::from_bytes(signing_key.sign(&preimage).to_bytes())
}

fn verify_signature(
    verifying_key: &VerifyingKey,
    domain: &[u8],
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    let mut preimage = Vec::with_capacity(domain.len() + payload.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(payload);
    verifying_key
        .verify(&preimage, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidSignature)
}

fn canonical_array(
    bytes: &[u8],
    maximum: usize,
    marker: &str,
    fields: usize,
) -> Result<Vec<Value>, ForkAuthenticationSignatureErrorV1> {
    if bytes.len() > maximum {
        return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)?;
    if cursor.position()
        != u64::try_from(bytes.len())
            .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)?
    {
        return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
    }
    let Value::Array(values) = value else {
        return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
    };
    if values.len() != fields
        || !matches!(values.first(), Some(Value::Text(value)) if value == marker)
        || !matches!(values.get(1), Some(Value::Integer(value)) if *value == 1.into())
    {
        return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
    }
    let mut encoded = Vec::new();
    ciborium::into_writer(&Value::Array(values.clone()), &mut encoded)
        .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)?;
    if encoded != bytes {
        return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
    }
    Ok(values)
}

fn fixed_nonzero(value: &Value, length: usize) -> bool {
    matches!(value, Value::Bytes(bytes) if bytes.len() == length && bytes.iter().any(|byte| *byte != 0))
}

fn bounded_text(value: &Value) -> bool {
    matches!(value, Value::Text(text) if (1..=128).contains(&text.len()) && !text.contains('\0'))
}

fn unsigned(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(value) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn validate_fai1(
    bytes: &[u8],
    host_public_key: &[u8; 32],
) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    if bytes.len() != FAI1_BYTES {
        return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
    }
    let values = canonical_array(bytes, FAI1_BYTES, "FAI1", 6)?;
    if values[2..].iter().all(|value| fixed_nonzero(value, 32))
        && matches!(&values[4], Value::Bytes(value) if value.as_slice() == host_public_key)
    {
        Ok(())
    } else {
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    }
}

fn validate_fao1(bytes: &[u8]) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    if bytes.len() != FAO1_BYTES {
        return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
    }
    let values = canonical_array(bytes, FAO1_BYTES, "FAO1", 5)?;
    if values[2..].iter().all(|value| fixed_nonzero(value, 32)) {
        Ok(())
    } else {
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    }
}

fn validate_command(bytes: &[u8]) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    if let Ok(value) = canonical_array(bytes, MAX_POC1_BYTES, "POC1", 8) {
        return if value[2..7].iter().all(|field| fixed_nonzero(field, 32))
            && matches!(&value[7], Value::Text(owner) if OwnerIdV1::new(owner.as_str()).is_ok())
        {
            Ok(())
        } else {
            Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
        };
    }
    let value = canonical_array(bytes, MAX_FCC1_BYTES, "FCC1", 14)?;
    if value[2..7].iter().all(|field| fixed_nonzero(field, 32))
        && matches!(&value[7], Value::Bytes(value) if value.len() == 16)
        && matches!((unsigned(&value[8]), unsigned(&value[9])), (Some(a), Some(b)) if a == b)
        && fixed_nonzero(&value[10], 32)
        && fixed_nonzero(&value[11], 32)
        && matches!(&value[12], Value::Integer(value) if *value == 0.into() || *value == 1.into())
        && bounded_text(&value[13])
    {
        Ok(())
    } else {
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    }
}

fn validate_frc1(bytes: &[u8]) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    if bytes.len() != FRC1_BYTES {
        return Err(ForkAuthenticationSignatureErrorV1::InvalidRecord);
    }
    let value = canonical_array(bytes, FRC1_BYTES, "FRC1", 6)?;
    if value[2..4].iter().all(|field| fixed_nonzero(field, 32))
        && matches!(&value[4], Value::Integer(value) if *value == 1.into() || *value == 2.into())
        && fixed_nonzero(&value[5], 32)
    {
        Ok(())
    } else {
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{fork_authentication::ForkAuthenticationAdapterPolicyV1, Hash, PrincipalRefV1};

    const ADAPTER_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn encode(value: Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).expect("test CBOR serializes");
        bytes
    }

    fn bytes(value: u8, length: usize) -> Value {
        Value::Bytes(vec![value; length])
    }

    fn record() -> AuthenticatedPrincipalRecordV1 {
        AuthenticatedPrincipalRecordV1 {
            principal: PrincipalRefV1::try_new([1; 16], "unix-user").expect("valid principal"),
            adapter_id: "local-unix".to_owned(),
            assurance: 2,
            issued_at: 1,
            expires_at: 2,
            registry_binding: Hash::from_bytes([2; 32]),
            operation_nonce: [3; 32],
        }
    }

    fn policy(key: [u8; 32]) -> ForkAuthenticationPolicyV1 {
        ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "local-unix".to_owned(),
            verifying_key: key,
            minimum_assurance: 2,
            registry_bindings: vec![Hash::from_bytes([2; 32])],
        }])
        .expect("valid policy")
    }

    fn verified_evidence() -> VerifiedAuthenticatedPrincipalEvidenceV1 {
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)
            .expect("RFC seed is nonzero");
        let evidence = adapter
            .sign_authenticated_principal(record())
            .expect("record is valid");
        verify_authenticated_principal_evidence_v1(&policy(adapter.public_key()), evidence)
            .expect("adapter evidence verifies")
    }

    fn verify_host_signature(
        public_key: [u8; 32],
        domain: &[u8],
        bytes: &[u8],
        signature: &Signature,
    ) {
        let verifying_key = VerifyingKey::from_bytes(&public_key).expect("host key is valid");
        verify_signature(&verifying_key, domain, bytes, signature.as_bytes())
            .expect("signature matches exact domain and bytes");
    }

    #[test]
    fn adapter_signing_uses_rfc8032_key_and_policy_pinned_preimage() {
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)
            .expect("RFC seed is nonzero");
        assert_eq!(adapter.public_key(), RFC8032_PUBLIC_KEY);
        let evidence = adapter
            .sign_authenticated_principal(record())
            .expect("record is valid");
        let verified = verify_authenticated_principal_evidence_v1(
            &policy(RFC8032_PUBLIC_KEY),
            evidence.clone(),
        );
        assert!(verified.is_ok());
        let verifying_key =
            VerifyingKey::from_bytes(&RFC8032_PUBLIC_KEY).expect("RFC key is valid");
        let record_bytes = evidence.record().to_canonical_cbor().expect("APR1 CBOR");
        assert!(verify_signature(
            &verifying_key,
            ADAPTER_DOMAIN,
            &record_bytes,
            evidence.signature(),
        )
        .is_ok());
        assert!(verify_signature(
            &verifying_key,
            OPEN_DOMAIN,
            &record_bytes,
            evidence.signature(),
        )
        .is_err());
    }

    #[test]
    fn policy_verification_rejects_wrong_assurance_binding_and_signature() {
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)
            .expect("RFC seed is nonzero");
        let evidence = adapter
            .sign_authenticated_principal(record())
            .expect("record is valid");
        let insufficient = policy(adapter.public_key());
        let entry = insufficient
            .adapter("local-unix")
            .expect("adapter is present");
        assert_eq!(entry.minimum_assurance, 2);
        let wrong_assurance =
            ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "local-unix".to_owned(),
                verifying_key: adapter.public_key(),
                minimum_assurance: 3,
                registry_bindings: vec![Hash::from_bytes([2; 32])],
            }])
            .expect("valid policy");
        assert_eq!(
            verify_authenticated_principal_evidence_v1(&wrong_assurance, evidence.clone()),
            Err(ForkAuthenticationSignatureErrorV1::PolicyMismatch)
        );
        let wrong_binding =
            ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "local-unix".to_owned(),
                verifying_key: adapter.public_key(),
                minimum_assurance: 2,
                registry_bindings: vec![Hash::from_bytes([9; 32])],
            }])
            .expect("valid policy");
        assert_eq!(
            verify_authenticated_principal_evidence_v1(&wrong_binding, evidence.clone()),
            Err(ForkAuthenticationSignatureErrorV1::PolicyMismatch)
        );
        let mut altered = evidence.to_canonical_cbor().expect("APS1 CBOR");
        let last = altered.last_mut().expect("APS1 is nonempty");
        *last ^= 1;
        let altered = AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&altered)
            .expect("signature bytes remain structurally valid");
        assert_eq!(
            verify_authenticated_principal_evidence_v1(&insufficient, altered),
            Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
        );
    }

    #[test]
    fn host_signing_is_purpose_limited_and_accepts_exact_adr106_shapes() {
        let host = ForkHostSigningKeyV1::from_seed([4; 32]).expect("nonzero host seed");
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)
            .expect("RFC seed is nonzero");
        assert_ne!(host.public_key(), adapter.public_key());

        let fai1 = encode(Value::Array(vec![
            Value::Text("FAI1".to_owned()),
            Value::Integer(1.into()),
            bytes(1, 32),
            bytes(2, 32),
            Value::Bytes(host.public_key().to_vec()),
            bytes(4, 32),
        ]));
        assert_eq!(fai1.len(), FAI1_BYTES);
        let initialize = host.sign_initialize(&fai1).expect("FAI1 is valid");
        verify_host_signature(host.public_key(), INITIALIZE_DOMAIN, &fai1, &initialize);
        assert!(verify_signature(
            &VerifyingKey::from_bytes(&host.public_key()).expect("valid host key"),
            OPEN_DOMAIN,
            &fai1,
            initialize.as_bytes()
        )
        .is_err());

        let fao1 = encode(Value::Array(vec![
            Value::Text("FAO1".to_owned()),
            Value::Integer(1.into()),
            bytes(1, 32),
            bytes(2, 32),
            bytes(3, 32),
        ]));
        assert_eq!(fao1.len(), FAO1_BYTES);
        let open = host.sign_open(&fao1).expect("FAO1 is valid");
        verify_host_signature(host.public_key(), OPEN_DOMAIN, &fao1, &open);

        let poc1 = encode(Value::Array(vec![
            Value::Text("POC1".to_owned()),
            Value::Integer(1.into()),
            bytes(1, 32),
            bytes(2, 32),
            bytes(3, 32),
            bytes(4, 32),
            bytes(5, 32),
            Value::Text("owner".to_owned()),
        ]));
        let evidence = verified_evidence();
        let command = host.sign_command(&poc1, &evidence).expect("POC1 is valid");
        let evidence_bytes = evidence.evidence().to_canonical_cbor().expect("APS1 CBOR");
        let mut command_input = poc1.clone();
        command_input.extend_from_slice(&evidence_bytes);
        verify_host_signature(host.public_key(), COMMAND_DOMAIN, &command_input, &command);

        let fcc1 = encode(Value::Array(vec![
            Value::Text("FCC1".to_owned()),
            Value::Integer(1.into()),
            bytes(1, 32),
            bytes(2, 32),
            bytes(3, 32),
            bytes(4, 32),
            bytes(5, 32),
            bytes(6, 16),
            Value::Integer(7.into()),
            Value::Integer(7.into()),
            bytes(8, 32),
            bytes(9, 32),
            Value::Integer(1.into()),
            Value::Text("child".to_owned()),
        ]));
        let fcc_signature = host.sign_command(&fcc1, &evidence).expect("FCC1 is valid");
        let mut fcc_input = fcc1.clone();
        fcc_input.extend_from_slice(&evidence_bytes);
        verify_host_signature(
            host.public_key(),
            COMMAND_DOMAIN,
            &fcc_input,
            &fcc_signature,
        );

        let frc1 = encode(Value::Array(vec![
            Value::Text("FRC1".to_owned()),
            Value::Integer(1.into()),
            bytes(1, 32),
            bytes(2, 32),
            Value::Integer(1.into()),
            bytes(3, 32),
        ]));
        assert_eq!(frc1.len(), FRC1_BYTES);
        let recovery = host.sign_recovery(&frc1).expect("FRC1 is valid");
        verify_host_signature(host.public_key(), RECOVERY_DOMAIN, &frc1, &recovery);
    }

    #[test]
    fn host_signing_rejects_zero_seeds_noncanonical_and_wrong_purpose_shapes() {
        assert!(matches!(
            ForkAuthenticationAdapterSigningKeyV1::from_seed([0; 32]),
            Err(ForkAuthenticationSignatureErrorV1::InvalidSeed)
        ));
        assert!(matches!(
            ForkHostSigningKeyV1::from_seed([0; 32]),
            Err(ForkAuthenticationSignatureErrorV1::InvalidSeed)
        ));
        let host = ForkHostSigningKeyV1::from_seed([4; 32]).expect("nonzero host seed");
        let wrong = encode(Value::Array(vec![
            Value::Text("FAO1".to_owned()),
            Value::Integer(1.into()),
            bytes(1, 32),
            bytes(2, 32),
            bytes(3, 32),
        ]));
        assert_eq!(
            host.sign_initialize(&wrong),
            Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
        );
        let foreign_host = encode(Value::Array(vec![
            Value::Text("FAI1".to_owned()),
            Value::Integer(1.into()),
            bytes(1, 32),
            bytes(2, 32),
            bytes(3, 32),
            bytes(4, 32),
        ]));
        assert_eq!(
            host.sign_initialize(&foreign_host),
            Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
        );
        let malformed_fcc1 = encode(Value::Array(vec![
            Value::Text("FCC1".to_owned()),
            Value::Integer(1.into()),
            bytes(1, 32),
            bytes(2, 32),
            bytes(3, 32),
            bytes(4, 32),
            bytes(5, 32),
            bytes(6, 16),
            Value::Text("invalid cursor".to_owned()),
            Value::Text("invalid cursor".to_owned()),
            bytes(8, 32),
            bytes(9, 32),
            Value::Integer(1.into()),
            Value::Text("child".to_owned()),
        ]));
        assert_eq!(
            host.sign_command(&malformed_fcc1, &verified_evidence()),
            Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
        );
        let noncanonical = [0x98, 0x05, b'F', b'A', b'O', b'1'];
        assert_eq!(
            host.sign_open(&noncanonical),
            Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
        );
        assert_eq!(
            host.sign_recovery(&wrong),
            Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
        );
    }
}
