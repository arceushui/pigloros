use super::super::codec::{
    array, bounded_text, decode, digest, fixed, optional_fixed, sign, text, uint, validate_magic,
    value_bytes, value_optional_bytes, value_text, value_uint, verify,
};
use super::super::{
    SandboxContractErrorV1, MAX_SANDBOX_IDENTIFIER_BYTES_V1, MAX_SANDBOX_PROVIDER_ENTRIES_V1,
};
use super::{decode_digest_list, encode_signed, validate_signed_bytes};
use ciborium::value::Value;

const SPR1: &str = "SPR1";

/// Exact signed SPR1 attempt receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderReceiptV1 {
    /// Nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Named admission, provider, image, and policy identities.
    pub authority: ReceiptAuthorityV1,
    /// Independent trust epoch.
    pub trust_epoch: u64,
    /// Independent revocation epoch.
    pub revocation_epoch: u64,
    /// Independent policy epoch.
    pub policy_epoch: u64,
    /// Exact HCP1 digest.
    pub hcp1_digest: [u8; 32],
    /// Exact ELM1 digest.
    pub elm1_digest: [u8; 32],
    /// Ordered NXT1 transcript digests.
    pub network_transcript_digests: Vec<[u8; 32]>,
    /// Exact `ReadyV1` digest, once a valid ready message existed.
    pub ready1_digest: Option<[u8; 32]>,
    /// Exact `ReleaseV1` digest, once a valid release was issued.
    pub release1_digest: Option<[u8; 32]>,
    /// Final requested-configuration evidence digest.
    pub requested_configuration_evidence: [u8; 32],
    /// Final kernel-observation evidence digest.
    pub kernel_observation_evidence: [u8; 32],
    /// Final trusted-negative-probe evidence digest.
    pub negative_probe_evidence: [u8; 32],
    /// Final termination evidence digest.
    pub termination_evidence: [u8; 32],
    /// Terminal SAU1 digest.
    pub sau1_digest: [u8; 32],
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact SPR1-U array.
    pub receipt_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

/// Provider-neutral authority identities bound by SPR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAuthorityV1 {
    /// Exact AGR1 digest.
    pub agr1_digest: [u8; 32],
    /// Exact SPM1 digest.
    pub spm1_digest: [u8; 32],
    /// Exact provider-binary digest.
    pub provider_binary_digest: [u8; 32],
    /// Exact LPS1 digest.
    pub lps1_digest: [u8; 32],
    /// Exact SIM1 digest.
    pub sim1_digest: [u8; 32],
    /// Exact APT1 digest.
    pub apt1_digest: [u8; 32],
    /// Exact TRS1 digest.
    pub trs1_digest: [u8; 32],
    /// Exact RVS1 digest.
    pub rvs1_digest: [u8; 32],
}

impl SandboxProviderReceiptV1 {
    /// Seal this receipt with the supplied runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.receipt_digest = digest(SPR1, &self.unsigned_value())?;
        self.signature = sign(SPR1, &self.receipt_digest, key);
        Ok(self)
    }

    /// Validate evidence bindings, bounds, and self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid receipt data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        validate_signed_bytes(&self.signature)?;
        (self.receipt_digest == digest(SPR1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Verify this receipt with an authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed error when shape, digest, or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        verify(SPR1, &self.receipt_digest, &self.signature, key)
    }

    /// Encode exact deterministic-CBOR SPR1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode_signed(
            &self.unsigned_value(),
            &self.receipt_digest,
            &self.signature,
        )
    }

    /// Decode exact deterministic-CBOR SPR1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<3>(&value)?;
        let unsigned = array::<25>(&fields[0])?;
        validate_magic(unsigned, SPR1)?;
        let receipt = Self {
            attempt_id: fixed(&unsigned[2])?,
            authority: ReceiptAuthorityV1::from_fields(&unsigned[3..11])?,
            trust_epoch: uint(&unsigned[11])?,
            revocation_epoch: uint(&unsigned[12])?,
            policy_epoch: uint(&unsigned[13])?,
            hcp1_digest: fixed(&unsigned[14])?,
            elm1_digest: fixed(&unsigned[15])?,
            network_transcript_digests: decode_digest_list(&unsigned[16])?,
            ready1_digest: optional_fixed(&unsigned[17])?,
            release1_digest: optional_fixed(&unsigned[18])?,
            requested_configuration_evidence: fixed(&unsigned[19])?,
            kernel_observation_evidence: fixed(&unsigned[20])?,
            negative_probe_evidence: fixed(&unsigned[21])?,
            termination_evidence: fixed(&unsigned[22])?,
            sau1_digest: fixed(&unsigned[23])?,
            runtime_attestation_key_id: text(&unsigned[24])?.to_owned(),
            receipt_digest: fixed(&fields[1])?,
            signature: fixed(&fields[2])?,
        };
        receipt.validate().map(|()| receipt)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        let evidence = [
            self.hcp1_digest,
            self.elm1_digest,
            self.requested_configuration_evidence,
            self.kernel_observation_evidence,
            self.negative_probe_evidence,
            self.termination_evidence,
            self.sau1_digest,
        ];
        if self.attempt_id == [0; 16]
            || self.authority.has_zero_digest()
            || evidence.contains(&[0; 32])
            || self.network_transcript_digests.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self.network_transcript_digests.contains(&[0; 32])
            || self.ready1_digest == Some([0; 32])
            || self.release1_digest == Some([0; 32])
            || !bounded_text(
                &self.runtime_attestation_key_id,
                MAX_SANDBOX_IDENTIFIER_BYTES_V1,
            )
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        if self.release1_digest.is_some() && self.ready1_digest.is_none() {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        Ok(())
    }

    fn unsigned_value(&self) -> Value {
        let mut fields = vec![
            value_text(SPR1),
            value_uint(1),
            value_bytes(&self.attempt_id),
        ];
        fields.extend(self.authority.values());
        fields.extend([
            value_uint(self.trust_epoch),
            value_uint(self.revocation_epoch),
            value_uint(self.policy_epoch),
            value_bytes(&self.hcp1_digest),
            value_bytes(&self.elm1_digest),
            Value::Array(
                self.network_transcript_digests
                    .iter()
                    .map(|value| value_bytes(value))
                    .collect(),
            ),
            value_optional_bytes(self.ready1_digest.as_ref()),
            value_optional_bytes(self.release1_digest.as_ref()),
            value_bytes(&self.requested_configuration_evidence),
            value_bytes(&self.kernel_observation_evidence),
            value_bytes(&self.negative_probe_evidence),
            value_bytes(&self.termination_evidence),
            value_bytes(&self.sau1_digest),
            value_text(&self.runtime_attestation_key_id),
        ]);
        Value::Array(fields)
    }
}

impl ReceiptAuthorityV1 {
    fn from_fields(fields: &[Value]) -> Result<Self, SandboxContractErrorV1> {
        let fields: &[Value; 8] = fields
            .try_into()
            .map_err(|_| SandboxContractErrorV1::InvalidEncoding)?;
        Ok(Self {
            agr1_digest: fixed(&fields[0])?,
            spm1_digest: fixed(&fields[1])?,
            provider_binary_digest: fixed(&fields[2])?,
            lps1_digest: fixed(&fields[3])?,
            sim1_digest: fixed(&fields[4])?,
            apt1_digest: fixed(&fields[5])?,
            trs1_digest: fixed(&fields[6])?,
            rvs1_digest: fixed(&fields[7])?,
        })
    }

    const fn digests(&self) -> [[u8; 32]; 8] {
        [
            self.agr1_digest,
            self.spm1_digest,
            self.provider_binary_digest,
            self.lps1_digest,
            self.sim1_digest,
            self.apt1_digest,
            self.trs1_digest,
            self.rvs1_digest,
        ]
    }

    fn has_zero_digest(&self) -> bool {
        self.digests().contains(&[0; 32])
    }

    fn values(&self) -> Vec<Value> {
        self.digests()
            .into_iter()
            .map(|value| value_bytes(&value))
            .collect()
    }
}
