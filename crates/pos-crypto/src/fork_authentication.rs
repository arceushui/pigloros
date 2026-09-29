//! Purpose-limited Ed25519 operations for ADR-106 Fork authentication.
//!
//! This module performs portable cryptographic validation only. Credential
//! custody, trusted authentication production, and durable Fork-admission
//! orchestration remain owned by the Gateway and store adapters.

use std::{io::Cursor, ops::RangeInclusive};

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pos_core::{
    fork_authentication::{
        principal_digest_v1, AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
        ForkAuthenticationPolicyV1,
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
const MAX_FCC1_BYTES: usize = 411;
const FAI1_BYTES: usize = 143;
const FAO1_BYTES: usize = 109;
const FRC1_BYTES: usize = 110;

// ADR-106 field positions. Every record starts with marker (0) and version (1).
const FIRST_PAYLOAD_FIELD: usize = 2;
const FAI1_FIELDS: usize = 6;
const FAI1_HOST_KEY: usize = 4;
const FAO1_FIELDS: usize = 5;
// POC1 and FCC1 share fields 2..=6: store, session, operation, and digests.
const COMMAND_EVIDENCE_DIGEST: usize = 5;
const COMMAND_PRINCIPAL_DIGEST: usize = 6;
const POC1_FIELDS: usize = 8;
const POC1_OWNER: usize = 7;
const FCC1_FIELDS: usize = 14;
const FCC1_PARENT_TIMELINE: usize = 7;
const FCC1_FOLD_CURSOR: usize = 8;
const FCC1_TICK_BOUNDARY: usize = 9;
const FCC1_DESCRIPTOR_HASH: usize = 10;
const FCC1_COMPOSITION_HASH: usize = 11;
const FCC1_ATTRIBUTION_REQUIRED: usize = 12;
const FCC1_CHILD_NAME: usize = 13;
const FRC1_FIELDS: usize = 6;
const FRC1_OPERATION_KIND: usize = 4;
const FRC1_OPERATION_ID: usize = 5;

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

/// A verified FAE1 whose policy provenance has been checked.
///
/// The host signing API requires this type so a caller cannot substitute a
/// merely decodable FAE1 for policy-verified authentication evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthenticatedPrincipalEvidenceV1(AuthenticatedPrincipalEvidenceV1);

impl VerifiedAuthenticatedPrincipalEvidenceV1 {
    /// Return the exact policy-verified FAE1.
    #[must_use]
    pub const fn evidence(&self) -> &AuthenticatedPrincipalEvidenceV1 {
        &self.0
    }
}

/// Verify FAE1 against the selected FAP1 adapter policy.
///
/// This verifies only the exact ADR-106 adapter signature and policy facts. It
/// does not resolve an Owner, check expiry, or grant durable authority.
///
/// # Errors
/// Rejects missing or insufficient adapter policy, a malformed or small-order
/// (weak) verification key, and any signature that is not a strict Ed25519
/// signature over the exact canonical APR1 bytes.
pub fn verify_authenticated_principal_evidence_v1(
    policy: &ForkAuthenticationPolicyV1,
    evidence: AuthenticatedPrincipalEvidenceV1,
) -> Result<VerifiedAuthenticatedPrincipalEvidenceV1, ForkAuthenticationSignatureErrorV1> {
    let record = evidence.record();
    policy
        .adapter(&record.adapter_id)
        .filter(|adapter| {
            record.assurance >= adapter.minimum_assurance
                && adapter.registry_bindings.contains(&record.registry_binding)
        })
        .ok_or(ForkAuthenticationSignatureErrorV1::PolicyMismatch)
        .and_then(|adapter| {
            VerifyingKey::from_bytes(&adapter.verifying_key)
                .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)
        })
        .and_then(|verifying_key| {
            record
                .to_canonical_cbor()
                .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)
                .and_then(|record_bytes| {
                    verify_signature(
                        &verifying_key,
                        ADAPTER_DOMAIN,
                        &record_bytes,
                        evidence.signature(),
                    )
                })
        })
        .map(|()| VerifiedAuthenticatedPrincipalEvidenceV1(evidence))
}

/// Non-cloneable nonzero-seed Ed25519 material shared by the purpose-limited
/// public signing keys. It never exposes the raw seed or a generic signer.
struct SeedSigningKeyV1 {
    signing_key: Box<SigningKey>,
    public_key: [u8; 32],
}

impl SeedSigningKeyV1 {
    fn from_seed(mut seed: [u8; 32]) -> Result<Self, ForkAuthenticationSignatureErrorV1> {
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

    fn sign(&self, domain: &[u8], parts: &[&[u8]]) -> Signature {
        Signature::from_bytes(self.signing_key.sign(&preimage(domain, parts)).to_bytes())
    }
}

/// Non-cloneable Ed25519 material that can sign only a typed APR1.
pub struct ForkAuthenticationAdapterSigningKeyV1(SeedSigningKeyV1);

impl ForkAuthenticationAdapterSigningKeyV1 {
    /// Construct adapter signing material from one nonzero Ed25519 seed.
    ///
    /// The local seed copy is zeroized after the signing key has been built.
    ///
    /// # Errors
    /// Rejects the all-zero seed required to fail closed by ADR-107.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, ForkAuthenticationSignatureErrorV1> {
        SeedSigningKeyV1::from_seed(seed).map(Self)
    }

    /// Return the corresponding public verification key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.0.public_key
    }

    /// Sign exactly one validated APR1 into FAE1.
    ///
    /// # Errors
    /// Rejects an APR1 that fails its core structural validation.
    pub fn sign_authenticated_principal(
        &self,
        record: AuthenticatedPrincipalRecordV1,
    ) -> Result<AuthenticatedPrincipalEvidenceV1, ForkAuthenticationSignatureErrorV1> {
        record
            .validate()
            .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)
            .and_then(|()| {
                record
                    .to_canonical_cbor()
                    .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)
            })
            .and_then(|record_bytes| {
                let signature = self.0.sign(ADAPTER_DOMAIN, &[&record_bytes]);
                AuthenticatedPrincipalEvidenceV1::new(record, *signature.as_bytes())
                    .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)
            })
    }
}

/// Non-cloneable Ed25519 material for ADR-106 host proofs.
///
/// It offers no generic signing operation and never exposes the raw seed.
pub struct ForkHostSigningKeyV1(SeedSigningKeyV1);

impl ForkHostSigningKeyV1 {
    /// Construct host signing material from one nonzero Ed25519 seed.
    ///
    /// The local seed copy is zeroized after the signing key has been built.
    ///
    /// # Errors
    /// Rejects the all-zero seed required to fail closed by ADR-107.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, ForkAuthenticationSignatureErrorV1> {
        SeedSigningKeyV1::from_seed(seed).map(Self)
    }

    /// Return the corresponding public verification key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.0.public_key
    }

    /// Sign one exact canonical FAI1 initialize challenge.
    ///
    /// # Errors
    /// Rejects a noncanonical or structurally invalid FAI1 payload.
    pub fn sign_initialize(
        &self,
        challenge: &[u8],
    ) -> Result<Signature, ForkAuthenticationSignatureErrorV1> {
        validate_fai1(challenge, &self.0.public_key)
            .map(|()| self.0.sign(INITIALIZE_DOMAIN, &[challenge]))
    }

    /// Sign one exact canonical FAO1 open challenge.
    ///
    /// # Errors
    /// Rejects a noncanonical or structurally invalid FAO1 payload.
    pub fn sign_open(
        &self,
        challenge: &[u8],
    ) -> Result<Signature, ForkAuthenticationSignatureErrorV1> {
        validate_fao1(challenge).map(|()| self.0.sign(OPEN_DOMAIN, &[challenge]))
    }

    /// Sign one exact POC1 or FCC1 plus policy-verified FAE1.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical command bytes. The typed evidence cannot
    /// be constructed without an earlier FAP1 policy and Ed25519 check.
    pub fn sign_command(
        &self,
        command: &[u8],
        evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
    ) -> Result<Signature, ForkAuthenticationSignatureErrorV1> {
        validate_command(command, evidence)
            .and_then(|()| {
                evidence
                    .evidence()
                    .to_canonical_cbor()
                    .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidRecord)
            })
            .map(|evidence_bytes| self.0.sign(COMMAND_DOMAIN, &[command, &evidence_bytes]))
    }

    /// Sign one exact canonical FRC1 recovery command.
    ///
    /// # Errors
    /// Rejects a noncanonical or structurally invalid FRC1 payload.
    pub fn sign_recovery(
        &self,
        command: &[u8],
    ) -> Result<Signature, ForkAuthenticationSignatureErrorV1> {
        validate_frc1(command).map(|()| self.0.sign(RECOVERY_DOMAIN, &[command]))
    }
}

/// Build the ADR-106 signature preimage `domain || parts...`.
fn preimage(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut preimage =
        Vec::with_capacity(domain.len() + parts.iter().map(|part| part.len()).sum::<usize>());
    preimage.extend_from_slice(domain);
    for part in parts {
        preimage.extend_from_slice(part);
    }
    preimage
}

fn verify_signature(
    verifying_key: &VerifyingKey,
    domain: &[u8],
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    // A small-order key admits signatures over arbitrary messages, so it can
    // never be a pinned Fork-authentication identity.
    if verifying_key.is_weak() {
        Err(ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)
    } else {
        verifying_key
            .verify_strict(
                &preimage(domain, &[payload]),
                &ed25519_dalek::Signature::from_bytes(signature),
            )
            .map_err(|_| ForkAuthenticationSignatureErrorV1::InvalidSignature)
    }
}

const fn require(valid: bool) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    if valid {
        Ok(())
    } else {
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    }
}

/// Strictly decode one canonical `[marker, 1, ...]` array whose complete
/// encoding length lies in `lengths`.
fn canonical_array(
    bytes: &[u8],
    lengths: &RangeInclusive<usize>,
    marker: &str,
    fields: usize,
) -> Result<Vec<Value>, ForkAuthenticationSignatureErrorV1> {
    Some(bytes)
        .filter(|bytes| lengths.contains(&bytes.len()))
        .and_then(decode_exact)
        .and_then(|value| value.into_array().ok())
        .filter(|values| {
            values.len() == fields
                && matches!(values.first(), Some(Value::Text(value)) if value == marker)
                && matches!(values.get(1), Some(Value::Integer(value)) if *value == 1.into())
        })
        .filter(|values| {
            let mut encoded = Vec::with_capacity(bytes.len());
            ciborium::into_writer(&Value::Array(values.clone()), &mut encoded)
                .is_ok_and(|()| encoded == bytes)
        })
        .ok_or(ForkAuthenticationSignatureErrorV1::InvalidRecord)
}

fn decode_exact(bytes: &[u8]) -> Option<Value> {
    let mut cursor = Cursor::new(bytes);
    ciborium::from_reader(&mut cursor)
        .ok()
        .filter(|_| cursor.position() == bytes.len() as u64)
}

fn fixed_nonzero(value: &Value, length: usize) -> bool {
    matches!(value, Value::Bytes(bytes) if bytes.len() == length && bytes.iter().any(|byte| *byte != 0))
}

fn all_fixed_nonzero(values: &[Value]) -> bool {
    values.iter().all(|value| fixed_nonzero(value, 32))
}

fn bytes_equal(value: &Value, expected: &[u8]) -> bool {
    matches!(value, Value::Bytes(bytes) if bytes.as_slice() == expected)
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
    canonical_array(bytes, &(FAI1_BYTES..=FAI1_BYTES), "FAI1", FAI1_FIELDS).and_then(|values| {
        require(
            all_fixed_nonzero(&values[FIRST_PAYLOAD_FIELD..])
                && bytes_equal(&values[FAI1_HOST_KEY], host_public_key),
        )
    })
}

fn validate_fao1(bytes: &[u8]) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    canonical_array(bytes, &(FAO1_BYTES..=FAO1_BYTES), "FAO1", FAO1_FIELDS)
        .and_then(|values| require(all_fixed_nonzero(&values[FIRST_PAYLOAD_FIELD..])))
}

/// Validate POC1 or FCC1 structure first, then bind it to the verified FAE1.
fn validate_command(
    bytes: &[u8],
    evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    poc1_values(bytes)
        .or_else(|_| fcc1_values(bytes))
        .and_then(|values| require(binds_evidence(&values, evidence)))
}

fn poc1_values(bytes: &[u8]) -> Result<Vec<Value>, ForkAuthenticationSignatureErrorV1> {
    canonical_array(bytes, &(0..=MAX_POC1_BYTES), "POC1", POC1_FIELDS).and_then(|values| {
        require(
            all_fixed_nonzero(&values[FIRST_PAYLOAD_FIELD..=COMMAND_PRINCIPAL_DIGEST])
                && matches!(
                    &values[POC1_OWNER],
                    Value::Text(owner) if OwnerIdV1::new(owner.as_str()).is_ok()
                ),
        )
        .map(|()| values)
    })
}

fn fcc1_values(bytes: &[u8]) -> Result<Vec<Value>, ForkAuthenticationSignatureErrorV1> {
    canonical_array(bytes, &(0..=MAX_FCC1_BYTES), "FCC1", FCC1_FIELDS).and_then(|values| {
        require(
            all_fixed_nonzero(&values[FIRST_PAYLOAD_FIELD..=COMMAND_PRINCIPAL_DIGEST])
                && matches!(
                    &values[FCC1_PARENT_TIMELINE],
                    Value::Bytes(parent) if parent.len() == 16
                )
                && matches!(
                    (unsigned(&values[FCC1_FOLD_CURSOR]), unsigned(&values[FCC1_TICK_BOUNDARY])),
                    (Some(cursor), Some(boundary)) if cursor == boundary
                )
                && fixed_nonzero(&values[FCC1_DESCRIPTOR_HASH], 32)
                && fixed_nonzero(&values[FCC1_COMPOSITION_HASH], 32)
                && matches!(
                    &values[FCC1_ATTRIBUTION_REQUIRED],
                    Value::Integer(flag) if *flag == 0.into() || *flag == 1.into()
                )
                && bounded_text(&values[FCC1_CHILD_NAME]),
        )
        .map(|()| values)
    })
}

fn binds_evidence(values: &[Value], evidence: &VerifiedAuthenticatedPrincipalEvidenceV1) -> bool {
    evidence
        .evidence()
        .digest()
        .is_ok_and(|digest| bytes_equal(&values[COMMAND_EVIDENCE_DIGEST], digest.as_bytes()))
        && principal_digest_v1(&evidence.evidence().record().principal)
            .is_ok_and(|digest| bytes_equal(&values[COMMAND_PRINCIPAL_DIGEST], digest.as_bytes()))
}

fn validate_frc1(bytes: &[u8]) -> Result<(), ForkAuthenticationSignatureErrorV1> {
    canonical_array(bytes, &(FRC1_BYTES..=FRC1_BYTES), "FRC1", FRC1_FIELDS).and_then(|values| {
        require(
            all_fixed_nonzero(&values[FIRST_PAYLOAD_FIELD..FRC1_OPERATION_KIND])
                && matches!(
                    &values[FRC1_OPERATION_KIND],
                    Value::Integer(kind) if *kind == 1.into() || *kind == 2.into()
                )
                && fixed_nonzero(&values[FRC1_OPERATION_ID], 32),
        )
    })
}
