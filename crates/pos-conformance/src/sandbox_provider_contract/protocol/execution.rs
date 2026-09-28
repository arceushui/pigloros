use super::super::codec::{
    array, bounded_text, decode, digest, digest_with_domain, encode, fixed, sign, text, uint,
    validate_magic, value_bytes, value_text, value_uint, verify,
};
use super::super::{
    SandboxContractErrorV1, MAX_SANDBOX_IDENTIFIER_BYTES_V1, MAX_SANDBOX_PAYLOAD_BYTES_V1,
    MAX_SANDBOX_PROVIDER_ENTRIES_V1,
};
use super::{
    decode_digest_list, decode_request_authority, encode_signed, request_authority_value,
    validate_request_authority, validate_signed_bytes, RequestAuthorityV1,
};
use crate::identifier;
use ciborium::value::Value;
use std::collections::BTreeMap;

use super::payload::{
    decode_payload_descriptor, payload_descriptor_value, PayloadDescriptorV1, PayloadDirectionV1,
};

const SPX1: &str = "SPX1";
const AGR1: &str = "AGR1";
const NXP1: &str = "NXP1";
const NXP1_DIGEST_DOMAIN: &[u8] = b"PiglorOS.NetworkExchangePlan.v1\0";

/// Exact NXP1 planned network exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkExchangePlanV1 {
    /// Nonzero exchange identity.
    pub exchange_id: [u8; 16],
    /// Zero-based occurrence for this exchange identity.
    pub occurrence: u64,
    /// Exact admitted network capability identifier.
    pub capability_id: String,
    /// Exact request byte length.
    pub request_length: u64,
    /// Domain-separated request-byte digest.
    pub request_digest: [u8; 32],
    /// Maximum accepted response bytes.
    pub response_maximum: u64,
    /// Domain-separated expected response digest.
    pub expected_response_digest: [u8; 32],
    /// Exact NRP1 retention-policy digest.
    pub retention_policy_digest: [u8; 32],
    /// Self-digest over fields zero through nine.
    pub plan_digest: [u8; 32],
}

impl NetworkExchangePlanV1 {
    /// Compute and install the exact NXP1 plan digest.
    ///
    /// # Errors
    /// Returns a closed error when a plan field is invalid.
    pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        digest_with_domain(NXP1_DIGEST_DOMAIN, &self.unsigned_value()).map(|digest| {
            self.plan_digest = digest;
            self
        })
    }

    fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        digest_with_domain(NXP1_DIGEST_DOMAIN, &self.unsigned_value()).and_then(|digest| {
            (self.plan_digest == digest)
                .then_some(())
                .ok_or(SandboxContractErrorV1::DigestMismatch)
        })
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        if self.exchange_id == [0; 16]
            || !identifier(&self.capability_id, MAX_SANDBOX_IDENTIFIER_BYTES_V1)
            || self.request_length > MAX_SANDBOX_PAYLOAD_BYTES_V1
            || self.request_digest == [0; 32]
            || !(1..=MAX_SANDBOX_PAYLOAD_BYTES_V1).contains(&self.response_maximum)
            || self.expected_response_digest == [0; 32]
            || self.retention_policy_digest == [0; 32]
        {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_fields(&self) -> Vec<Value> {
        vec![
            value_text(NXP1),
            value_uint(1),
            value_bytes(&self.exchange_id),
            value_uint(self.occurrence),
            value_text(&self.capability_id),
            value_uint(self.request_length),
            value_bytes(&self.request_digest),
            value_uint(self.response_maximum),
            value_bytes(&self.expected_response_digest),
            value_bytes(&self.retention_policy_digest),
        ]
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(self.unsigned_fields())
    }

    fn value(&self) -> Value {
        let mut fields = self.unsigned_fields();
        fields.push(value_bytes(&self.plan_digest));
        Value::Array(fields)
    }

    fn from_value(value: &Value) -> Result<Self, SandboxContractErrorV1> {
        let fields = array::<11>(value)?;
        validate_magic(fields, NXP1)?;
        let plan = Self {
            exchange_id: fixed(&fields[2])?,
            occurrence: uint(&fields[3])?,
            capability_id: text(&fields[4])?.to_owned(),
            request_length: uint(&fields[5])?,
            request_digest: fixed(&fields[6])?,
            response_maximum: uint(&fields[7])?,
            expected_response_digest: fixed(&fields[8])?,
            retention_policy_digest: fixed(&fields[9])?,
            plan_digest: fixed(&fields[10])?,
        };
        plan.validate().map(|()| plan)
    }
}

/// Exact self-digested SPX1 execute request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxExecuteRequestV1 {
    /// Common request authority.
    pub authority: RequestAuthorityV1,
    /// Nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Exact EVR1 digest.
    pub evr1_digest: [u8; 32],
    /// Exact CPF1 digest.
    pub cpf1_digest: [u8; 32],
    /// Exact CFB1 digest.
    pub cfb1_digest: [u8; 32],
    /// Exact fixture-contract digest.
    pub fixture_contract_digest: [u8; 32],
    /// Exact fixture digest.
    pub fixture_digest: [u8; 32],
    /// Exact execution-profile digest.
    pub execution_profile_digest: [u8; 32],
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
    /// Exact selected SPM1 digest.
    pub spm1_digest: [u8; 32],
    /// Exact PCF1 digest.
    pub pcf1_digest: [u8; 32],
    /// Exact PCR1 digest.
    pub pcr1_digest: [u8; 32],
    /// Exact HCP1 digest.
    pub hcp1_digest: [u8; 32],
    /// Strictly canonically ordered exact capability identifiers.
    pub capability_ids: Vec<String>,
    /// Exact bounded adapter input.
    pub adapter_input: PayloadDescriptorV1,
    /// Caller-ordered exchange plans.
    pub network_plans: Vec<NetworkExchangePlanV1>,
    /// Self-digest of the exact SPX1-U array.
    pub request_digest: [u8; 32],
}

/// Exact signed AGR1 admission grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionGrantV1 {
    /// Nonzero request identity.
    pub request_id: [u8; 16],
    /// Nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Named authority and artifact identities bound by the admission decision.
    pub authority: AdmissionAuthorityV1,
    /// Independent trust epoch.
    pub trust_epoch: u64,
    /// Independent revocation epoch.
    pub revocation_epoch: u64,
    /// Independent policy epoch.
    pub policy_epoch: u64,
    /// Exact ELM1 digest.
    pub elm1_digest: [u8; 32],
    /// Exact adapter-input digest.
    pub input_digest: [u8; 32],
    /// Ordered NXP1 plan digests.
    pub exchange_plan_digests: Vec<[u8; 32]>,
    /// Expected launch-policy digest.
    pub expected_launch_policy_digest: [u8; 32],
    /// Expected readback-set digest.
    pub expected_readback_set_digest: [u8; 32],
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact AGR1-U array.
    pub grant_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

/// Provider-neutral authority identities bound by AGR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionAuthorityV1 {
    /// Exact EVR1 digest.
    pub evr1_digest: [u8; 32],
    /// Exact fixture-contract digest.
    pub fixture_contract_digest: [u8; 32],
    /// Exact fixture digest.
    pub fixture_digest: [u8; 32],
    /// Exact execution-profile digest.
    pub execution_profile_digest: [u8; 32],
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
    /// Exact SPM1 digest.
    pub spm1_digest: [u8; 32],
    /// Exact PCF1 digest.
    pub pcf1_digest: [u8; 32],
    /// Exact PCR1 digest.
    pub pcr1_digest: [u8; 32],
    /// Exact HCP1 digest.
    pub hcp1_digest: [u8; 32],
}

impl SandboxExecuteRequestV1 {
    /// Compute and install the exact SPX1 request digest.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.request_digest = digest(SPX1, &self.unsigned_value())?;
        Ok(self)
    }

    /// Validate shape, relationships local to SPX1, ordering, and self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid request data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        (self.request_digest == digest(SPX1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Encode exact deterministic-CBOR SPX1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode(&Value::Array(vec![
            self.unsigned_value(),
            value_bytes(&self.request_digest),
        ]))
    }

    /// Decode exact deterministic-CBOR SPX1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<2>(&value)?;
        let unsigned = array::<22>(&fields[0])?;
        validate_magic(unsigned, SPX1)?;
        let request = Self {
            authority: decode_request_authority(&unsigned[2])?,
            attempt_id: fixed(&unsigned[3])?,
            evr1_digest: fixed(&unsigned[4])?,
            cpf1_digest: fixed(&unsigned[5])?,
            cfb1_digest: fixed(&unsigned[6])?,
            fixture_contract_digest: fixed(&unsigned[7])?,
            fixture_digest: fixed(&unsigned[8])?,
            execution_profile_digest: fixed(&unsigned[9])?,
            lps1_digest: fixed(&unsigned[10])?,
            sim1_digest: fixed(&unsigned[11])?,
            apt1_digest: fixed(&unsigned[12])?,
            trs1_digest: fixed(&unsigned[13])?,
            rvs1_digest: fixed(&unsigned[14])?,
            spm1_digest: fixed(&unsigned[15])?,
            pcf1_digest: fixed(&unsigned[16])?,
            pcr1_digest: fixed(&unsigned[17])?,
            hcp1_digest: fixed(&unsigned[18])?,
            capability_ids: decode_identifiers(&unsigned[19])?,
            adapter_input: decode_payload_descriptor(&unsigned[20])?,
            network_plans: decode_network_plans(&unsigned[21])?,
            request_digest: fixed(&fields[1])?,
        };
        request.validate().map(|()| request)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        validate_request_authority(&self.authority)?;
        let digests = self.bound_digests();
        if self.attempt_id == [0; 16]
            || digests.contains(&[0; 32])
            || self.authority.apt1_digest != self.apt1_digest
            || self.capability_ids.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self
                .capability_ids
                .iter()
                .any(|value| !identifier(value, MAX_SANDBOX_IDENTIFIER_BYTES_V1))
            || self.network_plans.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        self.adapter_input
            .validate_for_direction(PayloadDirectionV1::Input)?;
        if !self
            .capability_ids
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        {
            return Err(SandboxContractErrorV1::NonCanonicalOrder);
        }
        self.network_plans
            .iter()
            .try_for_each(NetworkExchangePlanV1::validate)?;
        let mut next_occurrence = BTreeMap::new();
        for plan in &self.network_plans {
            let expected = next_occurrence.entry(plan.exchange_id).or_insert(0);
            if plan.occurrence != *expected {
                return Err(SandboxContractErrorV1::InconsistentFields);
            }
            *expected += 1;
        }
        Ok(())
    }

    const fn bound_digests(&self) -> [[u8; 32]; 15] {
        [
            self.evr1_digest,
            self.cpf1_digest,
            self.cfb1_digest,
            self.fixture_contract_digest,
            self.fixture_digest,
            self.execution_profile_digest,
            self.lps1_digest,
            self.sim1_digest,
            self.apt1_digest,
            self.trs1_digest,
            self.rvs1_digest,
            self.spm1_digest,
            self.pcf1_digest,
            self.pcr1_digest,
            self.hcp1_digest,
        ]
    }

    fn unsigned_value(&self) -> Value {
        let mut fields = vec![
            value_text(SPX1),
            value_uint(1),
            request_authority_value(&self.authority),
            value_bytes(&self.attempt_id),
        ];
        fields.extend(self.bound_digests().iter().map(|value| value_bytes(value)));
        fields.push(Value::Array(
            self.capability_ids
                .iter()
                .map(|value| value_text(value))
                .collect(),
        ));
        fields.push(payload_descriptor_value(&self.adapter_input));
        fields.push(Value::Array(
            self.network_plans
                .iter()
                .map(NetworkExchangePlanV1::value)
                .collect(),
        ));
        Value::Array(fields)
    }
}

fn decode_identifiers(value: &Value) -> Result<Vec<String>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(|value| text(value).map(ToOwned::to_owned))
        .collect()
}

fn decode_network_plans(
    value: &Value,
) -> Result<Vec<NetworkExchangePlanV1>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(NetworkExchangePlanV1::from_value)
        .collect()
}

impl AdmissionGrantV1 {
    /// Seal this grant with the supplied runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        digest(AGR1, &self.unsigned_value()).map(|digest| {
            self.grant_digest = digest;
            self.signature = sign(AGR1, &self.grant_digest, key);
            self
        })
    }

    /// Validate shape, ordering, and self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid grant data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        validate_signed_bytes(&self.signature)?;
        (self.grant_digest == digest(AGR1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Verify this grant with an authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed error when shape, digest, or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        verify(AGR1, &self.grant_digest, &self.signature, key)
    }

    /// Encode exact deterministic-CBOR AGR1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode_signed(&self.unsigned_value(), &self.grant_digest, &self.signature)
    }

    /// Decode exact deterministic-CBOR AGR1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<3>(&value)?;
        let unsigned = array::<26>(&fields[0])?;
        validate_magic(unsigned, AGR1)?;
        let grant = Self {
            request_id: fixed(&unsigned[2])?,
            attempt_id: fixed(&unsigned[3])?,
            authority: AdmissionAuthorityV1::from_fields(&unsigned[4..17])?,
            trust_epoch: uint(&unsigned[17])?,
            revocation_epoch: uint(&unsigned[18])?,
            policy_epoch: uint(&unsigned[19])?,
            elm1_digest: fixed(&unsigned[20])?,
            input_digest: fixed(&unsigned[21])?,
            exchange_plan_digests: decode_digest_list(&unsigned[22])?,
            expected_launch_policy_digest: fixed(&unsigned[23])?,
            expected_readback_set_digest: fixed(&unsigned[24])?,
            runtime_attestation_key_id: text(&unsigned[25])?.to_owned(),
            grant_digest: fixed(&fields[1])?,
            signature: fixed(&fields[2])?,
        };
        grant.validate().map(|()| grant)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        let trailing = [
            self.elm1_digest,
            self.input_digest,
            self.expected_launch_policy_digest,
            self.expected_readback_set_digest,
        ];
        if self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || self.authority.has_zero_digest()
            || trailing.contains(&[0; 32])
            || self.exchange_plan_digests.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self.exchange_plan_digests.contains(&[0; 32])
            || !bounded_text(
                &self.runtime_attestation_key_id,
                MAX_SANDBOX_IDENTIFIER_BYTES_V1,
            )
        {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_value(&self) -> Value {
        let mut fields = vec![
            value_text(AGR1),
            value_uint(1),
            value_bytes(&self.request_id),
            value_bytes(&self.attempt_id),
        ];
        fields.extend(self.authority.values());
        fields.extend([
            value_uint(self.trust_epoch),
            value_uint(self.revocation_epoch),
            value_uint(self.policy_epoch),
            value_bytes(&self.elm1_digest),
            value_bytes(&self.input_digest),
            Value::Array(
                self.exchange_plan_digests
                    .iter()
                    .map(|value| value_bytes(value))
                    .collect(),
            ),
            value_bytes(&self.expected_launch_policy_digest),
            value_bytes(&self.expected_readback_set_digest),
            value_text(&self.runtime_attestation_key_id),
        ]);
        Value::Array(fields)
    }
}

impl AdmissionAuthorityV1 {
    fn from_fields(fields: &[Value]) -> Result<Self, SandboxContractErrorV1> {
        let fields: &[Value; 13] = fields
            .try_into()
            .map_err(|_| SandboxContractErrorV1::InvalidEncoding)?;
        Ok(Self {
            evr1_digest: fixed(&fields[0])?,
            fixture_contract_digest: fixed(&fields[1])?,
            fixture_digest: fixed(&fields[2])?,
            execution_profile_digest: fixed(&fields[3])?,
            lps1_digest: fixed(&fields[4])?,
            sim1_digest: fixed(&fields[5])?,
            apt1_digest: fixed(&fields[6])?,
            trs1_digest: fixed(&fields[7])?,
            rvs1_digest: fixed(&fields[8])?,
            spm1_digest: fixed(&fields[9])?,
            pcf1_digest: fixed(&fields[10])?,
            pcr1_digest: fixed(&fields[11])?,
            hcp1_digest: fixed(&fields[12])?,
        })
    }

    const fn digests(&self) -> [[u8; 32]; 13] {
        [
            self.evr1_digest,
            self.fixture_contract_digest,
            self.fixture_digest,
            self.execution_profile_digest,
            self.lps1_digest,
            self.sim1_digest,
            self.apt1_digest,
            self.trs1_digest,
            self.rvs1_digest,
            self.spm1_digest,
            self.pcf1_digest,
            self.pcr1_digest,
            self.hcp1_digest,
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
