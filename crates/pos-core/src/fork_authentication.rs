//! Canonical, ephemeral Fork admission authentication records (ADR-106/107).
//!
//! These values describe policy and evidence. Possession and authority are
//! established by the protected local adapter and store proof, not by decoding.

use std::io::Cursor;

use ciborium::value::Value;

use crate::{CanonicalBytes, Hash, OwnerIdV1, PrincipalRefV1};

/// Maximum complete FAP1 encoding, including its outer CBOR array.
pub const MAX_FORK_AUTH_POLICY_BYTES_V1: usize = 37_528;
/// Maximum accepted LAR1 encoding reconstructed from a protected FACR1 credential.
pub const MAX_LOCAL_ACCOUNT_REGISTRY_BYTES_V1: usize = 65_536;
/// Maximum complete APR1 encoding.
pub const MAX_AUTHENTICATED_PRINCIPAL_RECORD_BYTES_V1: usize = 381;
/// Maximum complete FAE1 encoding.
pub const MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1: usize = 457;

const POLICY_DOMAIN: &[u8] = b"pigloros/fork-admission-auth-policy/v1";
const REGISTRY_DOMAIN: &[u8] = b"pigloros/local-account-auth-registry/v1";
const EVIDENCE_DOMAIN: &[u8] = b"pigloros/authenticated-principal-evidence/v1";
const PRINCIPAL_DOMAIN: &[u8] = b"pigloros/principal-ref/v1";

/// Strict authentication record codec errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAuthenticationCodecErrorV1 {
    #[error("invalid Fork authentication encoding")]
    InvalidEncoding,
    #[error("noncanonical Fork authentication encoding")]
    NonCanonical,
    #[error("unsupported Fork authentication version")]
    UnsupportedVersion,
    #[error("Fork authentication field is out of bounds")]
    FieldOutOfBounds,
    #[error("Fork authentication fields do not agree")]
    FieldMismatch,
}

/// One exact FAP1 adapter and its accepted registry commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAuthenticationAdapterPolicyV1 {
    pub adapter_id: String,
    pub verifying_key: [u8; 32],
    pub minimum_assurance: u8,
    pub registry_bindings: Vec<Hash>,
}

impl ForkAuthenticationAdapterPolicyV1 {
    fn validate(&self) -> Result<(), ForkAuthenticationCodecErrorV1> {
        valid_text(&self.adapter_id)?;
        if self.verifying_key == [0; 32]
            || self.minimum_assurance == 0
            || !(1..=64).contains(&self.registry_bindings.len())
            || self
                .registry_bindings
                .iter()
                .any(|hash| *hash == Hash::zero())
            || !self
                .registry_bindings
                .windows(2)
                .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        {
            return Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds);
        }
        Ok(())
    }

    fn value(&self) -> Value {
        Value::Array(vec![
            text(&self.adapter_id),
            bytes(&self.verifying_key),
            uint(self.minimum_assurance),
            Value::Array(
                self.registry_bindings
                    .iter()
                    .map(|hash| bytes(hash.as_bytes()))
                    .collect(),
            ),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ForkAuthenticationCodecErrorV1> {
        let fields = array(value, 4)?;
        let bindings = nonempty_array(&fields[3], 64)?;
        let result = Self {
            adapter_id: string(&fields[0])?,
            verifying_key: fixed(&fields[1])?,
            minimum_assurance: number::<u8>(&fields[2])?,
            registry_bindings: bindings
                .iter()
                .map(|binding| fixed(binding).map(Hash::from_bytes))
                .collect::<Result<_, _>>()?,
        };
        result.validate()?;
        Ok(result)
    }
}

/// The immutable deployment policy pinned by FAH1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAuthenticationPolicyV1 {
    adapters: Vec<ForkAuthenticationAdapterPolicyV1>,
}

impl ForkAuthenticationPolicyV1 {
    /// Validate a complete policy and its required ordering.
    ///
    /// # Errors
    /// Rejects absent, duplicate, unsorted, malformed, or excessive adapters.
    pub fn new(
        adapters: Vec<ForkAuthenticationAdapterPolicyV1>,
    ) -> Result<Self, ForkAuthenticationCodecErrorV1> {
        if !(1..=16).contains(&adapters.len())
            || !adapters
                .windows(2)
                .all(|pair| pair[0].adapter_id < pair[1].adapter_id)
        {
            return Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds);
        }
        for adapter in &adapters {
            adapter.validate()?;
        }
        Ok(Self { adapters })
    }

    /// Decode exact deterministic CBOR and validate every FAP1 bound.
    ///
    /// # Errors
    /// Rejects any noncanonical, malformed, or out-of-policy bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAuthenticationCodecErrorV1> {
        let value = decode(bytes_in, MAX_FORK_AUTH_POLICY_BYTES_V1)?;
        let fields = array(&value, 3)?;
        header(fields, "FAP1")?;
        let entries = nonempty_array(&fields[2], 16)?;
        let policy = Self::new(
            entries
                .iter()
                .map(ForkAuthenticationAdapterPolicyV1::from_value)
                .collect::<Result<_, _>>()?,
        )?;
        policy
            .to_canonical_cbor()
            .and_then(|encoded| canonical(bytes_in, &encoded))
            .map(|()| policy)
    }

    /// Encode the exact FAP1 array.
    ///
    /// # Errors
    /// Returns a closed codec error if serialization fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ForkAuthenticationCodecErrorV1> {
        encode(&Value::Array(vec![
            text("FAP1"),
            uint(1_u8),
            Value::Array(
                self.adapters
                    .iter()
                    .map(ForkAuthenticationAdapterPolicyV1::value)
                    .collect(),
            ),
        ]))
    }

    /// Complete FAP1 byte commitment pinned by FAH1.
    ///
    /// # Errors
    /// Returns a closed codec error if serialization fails.
    pub fn digest(&self) -> Result<Hash, ForkAuthenticationCodecErrorV1> {
        self.to_canonical_cbor()
            .map(|encoded| digest(POLICY_DOMAIN, &encoded))
    }

    #[must_use]
    pub fn adapter(&self, id: &str) -> Option<&ForkAuthenticationAdapterPolicyV1> {
        self.adapters.iter().find(|entry| entry.adapter_id == id)
    }

    #[must_use]
    pub fn adapters(&self) -> &[ForkAuthenticationAdapterPolicyV1] {
        &self.adapters
    }
}

/// One UID to canonical Principal and Owner mapping from protected FACR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAccountBindingV1 {
    pub uid: u32,
    pub principal: PrincipalRefV1,
    pub owner: OwnerIdV1,
}

/// The exact LAR1 commitment reconstructed from FACR1 fields 4–6.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAccountRegistryV1 {
    adapter_id: String,
    assurance: u8,
    bindings: Vec<LocalAccountBindingV1>,
}

impl LocalAccountRegistryV1 {
    /// Validate the complete immutable UID registry.
    ///
    /// # Errors
    /// Rejects forbidden UIDs, duplicate Principals, and unsorted rows.
    pub fn new(
        adapter_id: String,
        assurance: u8,
        bindings: Vec<LocalAccountBindingV1>,
        service_uid: u32,
    ) -> Result<Self, ForkAuthenticationCodecErrorV1> {
        valid_text(&adapter_id)?;
        if assurance == 0 || !(1..=64).contains(&bindings.len()) {
            return Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds);
        }
        for binding in &bindings {
            if binding.uid == 0
                || binding.uid == 65_534
                || binding.uid == service_uid
                || binding.uid == u32::MAX
            {
                return Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds);
            }
        }
        if !bindings.windows(2).all(|pair| pair[0].uid < pair[1].uid) {
            return Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds);
        }
        bindings
            .iter()
            .try_fold(Vec::with_capacity(bindings.len()), |mut seen, binding| {
                principal_digest_v1(&binding.principal).and_then(|current_digest| {
                    if seen.contains(&current_digest) {
                        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
                    } else {
                        seen.push(current_digest);
                        Ok(seen)
                    }
                })
            })
            .map(|_| Self {
                adapter_id,
                assurance,
                bindings,
            })
    }

    /// Decode exact LAR1 bytes under the local service UID policy.
    ///
    /// # Errors
    /// Rejects a malformed row, duplicate or forbidden identity, or noncanonical bytes.
    pub fn from_canonical_cbor(
        bytes_in: &[u8],
        service_uid: u32,
    ) -> Result<Self, ForkAuthenticationCodecErrorV1> {
        let value = decode(bytes_in, MAX_LOCAL_ACCOUNT_REGISTRY_BYTES_V1)?;
        let fields = array(&value, 5)?;
        header(fields, "LAR1")?;
        let entries = nonempty_array(&fields[4], 64)?;
        let bindings = entries
            .iter()
            .map(|entry| {
                let fields = array(entry, 3)?;
                let uid = number::<u32>(&fields[0])?;
                let principal = principal(&fields[1])?;
                OwnerIdV1::new(string(&fields[2])?)
                    .map_err(|_| ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
                    .map(|owner| LocalAccountBindingV1 {
                        uid,
                        principal,
                        owner,
                    })
            })
            .collect::<Result<_, ForkAuthenticationCodecErrorV1>>()?;
        let registry = Self::new(
            string(&fields[2])?,
            number::<u8>(&fields[3])?,
            bindings,
            service_uid,
        )?;
        registry
            .to_canonical_cbor()
            .and_then(|encoded| canonical(bytes_in, &encoded))
            .map(|()| registry)
    }

    /// Encode the exact LAR1 registry.
    ///
    /// # Errors
    /// Returns a closed codec error if a Principal or CBOR value cannot encode.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ForkAuthenticationCodecErrorV1> {
        self.bindings
            .iter()
            .map(binding_value)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|bindings| {
                encode(&Value::Array(vec![
                    text("LAR1"),
                    uint(1_u8),
                    text(&self.adapter_id),
                    uint(self.assurance),
                    Value::Array(bindings),
                ]))
            })
    }

    /// Commit the exact LAR1 bytes.
    ///
    /// # Errors
    /// Returns a closed codec error if serialization fails.
    pub fn digest(&self) -> Result<Hash, ForkAuthenticationCodecErrorV1> {
        self.to_canonical_cbor()
            .map(|encoded| digest(REGISTRY_DOMAIN, &encoded))
    }

    #[must_use]
    pub fn lookup_uid(&self, uid: u32) -> Option<&LocalAccountBindingV1> {
        self.bindings.iter().find(|entry| entry.uid == uid)
    }

    #[must_use]
    pub fn lookup_principal(&self, principal: &PrincipalRefV1) -> Option<OwnerIdV1> {
        self.bindings
            .iter()
            .find(|entry| &entry.principal == principal)
            .map(|entry| entry.owner)
    }

    #[must_use]
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    #[must_use]
    pub const fn assurance(&self) -> u8 {
        self.assurance
    }

    #[must_use]
    pub fn bindings(&self) -> &[LocalAccountBindingV1] {
        &self.bindings
    }
}

fn binding_value(binding: &LocalAccountBindingV1) -> Result<Value, ForkAuthenticationCodecErrorV1> {
    binding
        .principal
        .encode()
        .map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)
        .map(|principal| {
            Value::Array(vec![
                uint(binding.uid),
                bytes(principal.as_slice()),
                text(binding.owner.as_str()),
            ])
        })
}

/// Exact unsigned APR1 content before adapter signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipalRecordV1 {
    pub principal: PrincipalRefV1,
    pub adapter_id: String,
    pub assurance: u8,
    pub issued_at: u64,
    pub expires_at: u64,
    pub registry_binding: Hash,
    pub operation_nonce: [u8; 32],
}

impl AuthenticatedPrincipalRecordV1 {
    /// Validate an APR1 construction input.
    ///
    /// # Errors
    /// Rejects invalid text, time interval, binding, or nonce.
    pub fn validate(&self) -> Result<(), ForkAuthenticationCodecErrorV1> {
        valid_text(&self.adapter_id)?;
        if self.assurance == 0
            || self.issued_at >= self.expires_at
            || self.registry_binding == Hash::zero()
            || self.operation_nonce == [0; 32]
        {
            return Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds);
        }
        Ok(())
    }

    /// Encode the exact APR1 content.
    ///
    /// # Errors
    /// Rejects invalid record fields or a Principal or CBOR value that cannot encode.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ForkAuthenticationCodecErrorV1> {
        self.validate()?;
        self.principal
            .encode()
            .map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)
            .and_then(|principal| {
                encode(&Value::Array(vec![
                    text("APR1"),
                    uint(1_u8),
                    bytes(principal.as_slice()),
                    text(&self.adapter_id),
                    uint(self.assurance),
                    uint(self.issued_at),
                    uint(self.expires_at),
                    bytes(self.registry_binding.as_bytes()),
                    bytes(&self.operation_nonce),
                ]))
            })
    }

    /// Decode exact canonical APR1.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, and out-of-bounds bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAuthenticationCodecErrorV1> {
        let value = decode(bytes_in, MAX_AUTHENTICATED_PRINCIPAL_RECORD_BYTES_V1)?;
        let fields = array(&value, 9)?;
        header(fields, "APR1")?;
        let result = Self {
            principal: principal(&fields[2])?,
            adapter_id: string(&fields[3])?,
            assurance: number::<u8>(&fields[4])?,
            issued_at: number::<u64>(&fields[5])?,
            expires_at: number::<u64>(&fields[6])?,
            registry_binding: Hash::from_bytes(fixed(&fields[7])?),
            operation_nonce: fixed(&fields[8])?,
        };
        result.validate()?;
        result
            .to_canonical_cbor()
            .and_then(|encoded| canonical(bytes_in, &encoded))
            .map(|()| result)
    }
}

/// Complete FAE1 adapter signature and its canonical APR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipalEvidenceV1 {
    record: AuthenticatedPrincipalRecordV1,
    signature: [u8; 64],
}

impl AuthenticatedPrincipalEvidenceV1 {
    /// Combine a validated APR1 with an adapter signature; provenance still needs verification.
    ///
    /// # Errors
    /// Rejects an invalid APR1.
    pub fn new(
        record: AuthenticatedPrincipalRecordV1,
        signature: [u8; 64],
    ) -> Result<Self, ForkAuthenticationCodecErrorV1> {
        record.validate()?;
        Ok(Self { record, signature })
    }

    #[must_use]
    pub const fn record(&self) -> &AuthenticatedPrincipalRecordV1 {
        &self.record
    }

    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Encode the complete signed authentication evidence.
    ///
    /// # Errors
    /// Returns a closed codec error if a nested value cannot encode.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ForkAuthenticationCodecErrorV1> {
        self.record.to_canonical_cbor().and_then(|record| {
            encode(&Value::Array(vec![
                text("FAE1"),
                uint(1_u8),
                bytes(&record),
                bytes(&self.signature),
            ]))
        })
    }

    /// Decode exact canonical FAE1 and its canonical APR1.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, and out-of-bounds bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAuthenticationCodecErrorV1> {
        let value = decode(bytes_in, MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1)?;
        let fields = array(&value, 4)?;
        header(fields, "FAE1")?;
        let record = AuthenticatedPrincipalRecordV1::from_canonical_cbor(bounded_bytes(
            &fields[2],
            MAX_AUTHENTICATED_PRINCIPAL_RECORD_BYTES_V1,
        )?)?;
        Self::new(record, fixed(&fields[3])?).and_then(|result| {
            result
                .to_canonical_cbor()
                .and_then(|encoded| canonical(bytes_in, &encoded))
                .map(|()| result)
        })
    }

    /// Commit the complete evidence bytes.
    ///
    /// # Errors
    /// Returns a closed codec error if serialization fails.
    pub fn digest(&self) -> Result<Hash, ForkAuthenticationCodecErrorV1> {
        self.to_canonical_cbor()
            .map(|encoded| digest(EVIDENCE_DOMAIN, &encoded))
    }
}

fn principal(value: &Value) -> Result<PrincipalRefV1, ForkAuthenticationCodecErrorV1> {
    let bytes_in = bounded_bytes(value, 256)?;
    if bytes_in.is_empty() {
        return Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds);
    }
    PrincipalRefV1::decode(&CanonicalBytes::from_vec(bytes_in.to_vec()))
        .map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)
}

/// Exact ADR-099 Principal digest used by POB1 and Fork admission commands.
///
/// # Errors
/// Returns a closed codec error if the Principal cannot encode.
pub fn principal_digest_v1(
    principal: &PrincipalRefV1,
) -> Result<Hash, ForkAuthenticationCodecErrorV1> {
    principal
        .encode()
        .map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)
        .map(|encoded| digest(PRINCIPAL_DOMAIN, encoded.as_slice()))
}

fn digest(domain: &[u8], content: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(content);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn valid_text(value: &str) -> Result<(), ForkAuthenticationCodecErrorV1> {
    if (1..=128).contains(&value.len()) && !value.contains('\0') {
        Ok(())
    } else {
        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
    }
}

fn decode(bytes_in: &[u8], maximum: usize) -> Result<Value, ForkAuthenticationCodecErrorV1> {
    if bytes_in.len() > maximum {
        return Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds);
    }
    let mut cursor = Cursor::new(bytes_in);
    let value: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)?;
    if cursor.position() != bytes_in.len() as u64 {
        return Err(ForkAuthenticationCodecErrorV1::InvalidEncoding);
    }
    encode(&value)
        .and_then(|encoded| canonical(bytes_in, &encoded))
        .map(|()| value)
}

fn encode(value: &Value) -> Result<Vec<u8>, ForkAuthenticationCodecErrorV1> {
    let mut result = Vec::new();
    ciborium::into_writer(value, &mut result)
        .map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)
        .map(|()| result)
}

fn canonical(actual: &[u8], expected: &[u8]) -> Result<(), ForkAuthenticationCodecErrorV1> {
    if actual == expected {
        Ok(())
    } else {
        Err(ForkAuthenticationCodecErrorV1::NonCanonical)
    }
}

fn array(value: &Value, length: usize) -> Result<&[Value], ForkAuthenticationCodecErrorV1> {
    match value {
        Value::Array(fields) if fields.len() == length => Ok(fields),
        _ => Err(ForkAuthenticationCodecErrorV1::InvalidEncoding),
    }
}

fn nonempty_array(
    value: &Value,
    maximum: usize,
) -> Result<&[Value], ForkAuthenticationCodecErrorV1> {
    match value {
        Value::Array(fields) if (1..=maximum).contains(&fields.len()) => Ok(fields),
        _ => Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds),
    }
}

fn header(fields: &[Value], magic: &str) -> Result<(), ForkAuthenticationCodecErrorV1> {
    if fields[0] != text(magic) {
        return Err(ForkAuthenticationCodecErrorV1::InvalidEncoding);
    }
    match number::<u8>(&fields[1])? {
        1 => Ok(()),
        _ => Err(ForkAuthenticationCodecErrorV1::UnsupportedVersion),
    }
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], ForkAuthenticationCodecErrorV1> {
    match value {
        Value::Bytes(content) => content
            .as_slice()
            .try_into()
            .map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding),
        _ => Err(ForkAuthenticationCodecErrorV1::InvalidEncoding),
    }
}

fn bounded_bytes(value: &Value, maximum: usize) -> Result<&[u8], ForkAuthenticationCodecErrorV1> {
    match value {
        Value::Bytes(content) if content.len() <= maximum => Ok(content),
        _ => Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds),
    }
}

fn string(value: &Value) -> Result<String, ForkAuthenticationCodecErrorV1> {
    match value {
        Value::Text(content) => {
            valid_text(content)?;
            Ok(content.clone())
        }
        _ => Err(ForkAuthenticationCodecErrorV1::InvalidEncoding),
    }
}

fn number<T>(value: &Value) -> Result<T, ForkAuthenticationCodecErrorV1>
where
    T: TryFrom<ciborium::value::Integer>,
{
    match value {
        Value::Integer(content) => {
            T::try_from(*content).map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)
        }
        _ => Err(ForkAuthenticationCodecErrorV1::InvalidEncoding),
    }
}

fn text(content: &str) -> Value {
    Value::Text(content.to_owned())
}
fn bytes(content: &[u8]) -> Value {
    Value::Bytes(content.to_vec())
}
fn uint<T: Into<ciborium::value::Integer>>(content: T) -> Value {
    Value::Integer(content.into())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{
        AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
        ForkAuthenticationAdapterPolicyV1, ForkAuthenticationCodecErrorV1,
        ForkAuthenticationPolicyV1, LocalAccountBindingV1, LocalAccountRegistryV1,
        MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1, MAX_AUTHENTICATED_PRINCIPAL_RECORD_BYTES_V1,
        MAX_FORK_AUTH_POLICY_BYTES_V1,
    };
    use crate::{Hash, OwnerIdV1, PrincipalRefV1};

    fn principal(id: u8) -> Result<PrincipalRefV1, crate::AuthorityErrorV1> {
        PrincipalRefV1::try_new([id; 16], "local.test")
    }

    fn adapter() -> ForkAuthenticationAdapterPolicyV1 {
        ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "local".to_owned(),
            verifying_key: [7; 32],
            minimum_assurance: 2,
            registry_bindings: vec![Hash::from_bytes([1; 32]), Hash::from_bytes([2; 32])],
        }
    }

    fn record() -> Result<AuthenticatedPrincipalRecordV1, crate::AuthorityErrorV1> {
        Ok(AuthenticatedPrincipalRecordV1 {
            principal: principal(1)?,
            adapter_id: "local".to_owned(),
            assurance: 2,
            issued_at: 100,
            expires_at: 30_000_100,
            registry_binding: Hash::from_bytes([1; 32]),
            operation_nonce: [3; 32],
        })
    }

    #[test]
    fn policy_round_trip_and_rejects_noncanonical_and_unsorted_inputs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = ForkAuthenticationPolicyV1::new(vec![adapter()])?;
        let bytes = policy.to_canonical_cbor()?;
        assert_eq!(
            ForkAuthenticationPolicyV1::from_canonical_cbor(&bytes),
            Ok(policy.clone())
        );
        assert_ne!(policy.digest()?, Hash::zero());
        assert!(policy.adapter("local").is_some());
        assert!(policy.adapter("other").is_none());
        assert_eq!(policy.adapters().len(), 1);

        let mut noncanonical = bytes.clone();
        noncanonical.splice(6..7, [0x18, 0x01]);
        assert_eq!(
            ForkAuthenticationPolicyV1::from_canonical_cbor(&noncanonical),
            Err(ForkAuthenticationCodecErrorV1::NonCanonical)
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            ForkAuthenticationPolicyV1::from_canonical_cbor(&trailing),
            Err(ForkAuthenticationCodecErrorV1::InvalidEncoding)
        );
        assert_eq!(
            ForkAuthenticationPolicyV1::from_canonical_cbor(&vec![
                0;
                MAX_FORK_AUTH_POLICY_BYTES_V1 + 1
            ]),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );

        let mut duplicate = adapter();
        duplicate.registry_bindings = vec![Hash::from_bytes([1; 32]); 2];
        assert_eq!(
            ForkAuthenticationPolicyV1::new(vec![duplicate]),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            ForkAuthenticationPolicyV1::new(vec![adapter(), adapter()]),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            ForkAuthenticationPolicyV1::new(Vec::new()),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        Ok(())
    }

    #[test]
    fn normative_fap1_maximum_vector_is_exact() -> Result<(), Box<dyn std::error::Error>> {
        let key = hex_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?;
        let adapters = (0..16_u8)
            .map(|i| ForkAuthenticationAdapterPolicyV1 {
                adapter_id: format!("{}{:02x}", "a".repeat(126), i),
                verifying_key: key,
                minimum_assurance: 255,
                registry_bindings: (0..64_u8)
                    .map(|j| {
                        let mut value = [0; 32];
                        value[30] = i + 1;
                        value[31] = j + 1;
                        Hash::from_bytes(value)
                    })
                    .collect(),
            })
            .collect();
        let policy = ForkAuthenticationPolicyV1::new(adapters)?;
        let bytes = policy.to_canonical_cbor()?;
        assert_eq!(bytes.len(), MAX_FORK_AUTH_POLICY_BYTES_V1);
        assert_eq!(
            &bytes[..8],
            &[0x83, 0x64, b'F', b'A', b'P', b'1', 0x01, 0x90]
        );
        assert_eq!(
            &Sha256::digest(&bytes)[..],
            &hex_bytes::<32>("658d17498b51bb0b6c218077737daab5648df1d48c435e6c0cf9335fd6fa1fb3")?
        );
        let mut extra_adapter = policy.adapters().to_vec();
        let mut seventeenth = extra_adapter[15].clone();
        seventeenth.adapter_id = "b".to_owned();
        extra_adapter.push(seventeenth);
        assert_eq!(
            ForkAuthenticationPolicyV1::new(extra_adapter),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );

        let mut extra_binding = policy.adapters().to_vec();
        extra_binding[0]
            .registry_bindings
            .push(Hash::from_bytes([0xff; 32]));
        assert_eq!(
            ForkAuthenticationPolicyV1::new(extra_binding),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );

        let mut extra_text_byte = policy.adapters()[0].clone();
        extra_text_byte.adapter_id.push('a');
        assert_eq!(
            ForkAuthenticationPolicyV1::new(vec![extra_text_byte]),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            ForkAuthenticationPolicyV1::from_canonical_cbor(&bytes),
            Ok(policy)
        );
        Ok(())
    }

    fn hex_bytes<const N: usize>(source: &str) -> Result<[u8; N], std::num::ParseIntError> {
        assert_eq!(source.len(), N * 2);
        let mut out = [0; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&source[index * 2..index * 2 + 2], 16)?;
        }
        Ok(out)
    }

    #[test]
    fn registry_round_trip_and_forbidden_mappings() -> Result<(), Box<dyn std::error::Error>> {
        let bindings = vec![
            LocalAccountBindingV1 {
                uid: 1001,
                principal: principal(1)?,
                owner: OwnerIdV1::from_static("alice"),
            },
            LocalAccountBindingV1 {
                uid: 1002,
                principal: principal(2)?,
                owner: OwnerIdV1::from_static("alice"),
            },
        ];
        let registry = LocalAccountRegistryV1::new("local".to_owned(), 2, bindings.clone(), 1000)?;
        let bytes = registry.to_canonical_cbor()?;
        assert_eq!(
            LocalAccountRegistryV1::from_canonical_cbor(&bytes, 1000),
            Ok(registry.clone())
        );
        assert_eq!(registry.adapter_id(), "local");
        assert_eq!(registry.assurance(), 2);
        assert_eq!(registry.bindings().len(), 2);
        assert_eq!(registry.lookup_uid(1001), Some(&bindings[0]));
        assert_eq!(registry.lookup_uid(2000), None);
        assert_eq!(
            registry.lookup_principal(&principal(2)?),
            Some(OwnerIdV1::from_static("alice"))
        );
        assert_eq!(registry.lookup_principal(&principal(3)?), None);
        assert_ne!(registry.digest()?, Hash::zero());
        assert_ne!(super::principal_digest_v1(&principal(1)?)?, Hash::zero());

        for forbidden in [0, 65_534, 1000, u32::MAX] {
            let mut rows = bindings.clone();
            rows[0].uid = forbidden;
            assert_eq!(
                LocalAccountRegistryV1::new("local".to_owned(), 2, rows, 1000),
                Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
            );
        }
        let mut duplicate = bindings.clone();
        duplicate[1].principal = duplicate[0].principal.clone();
        assert_eq!(
            LocalAccountRegistryV1::new("local".to_owned(), 2, duplicate, 1000),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        let mut unsorted = bindings;
        unsorted.reverse();
        assert_eq!(
            LocalAccountRegistryV1::new("local".to_owned(), 2, unsorted, 1000),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        Ok(())
    }

    #[test]
    fn apr1_and_fae1_round_trip_with_rejected_timestamp_and_nonce(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let record = record()?;
        let apr = record.to_canonical_cbor()?;
        assert!(apr.len() <= MAX_AUTHENTICATED_PRINCIPAL_RECORD_BYTES_V1);
        assert_eq!(
            AuthenticatedPrincipalRecordV1::from_canonical_cbor(&apr),
            Ok(record.clone())
        );
        let evidence = AuthenticatedPrincipalEvidenceV1::new(record.clone(), [9; 64])?;
        let fae = evidence.to_canonical_cbor()?;
        assert!(fae.len() <= MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1);
        assert_eq!(
            AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&fae),
            Ok(evidence.clone())
        );
        assert_eq!(evidence.record(), &record);
        assert_eq!(evidence.signature(), &[9; 64]);
        assert_ne!(evidence.digest()?, Hash::zero());

        let mut expired = record.clone();
        expired.expires_at = expired.issued_at;
        assert_eq!(
            expired.validate(),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        let mut zero_nonce = record.clone();
        zero_nonce.operation_nonce = [0; 32];
        assert_eq!(
            zero_nonce.validate(),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        let mut zero_binding = record;
        zero_binding.registry_binding = Hash::zero();
        assert_eq!(
            zero_binding.validate(),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        Ok(())
    }

    #[test]
    fn normative_prn1_apr1_fae1_maximum_vectors_are_exact() -> Result<(), Box<dyn std::error::Error>>
    {
        let principal = PrincipalRefV1::try_new([0xff; 16], "a".repeat(128))?;
        let prn = principal.encode()?;
        assert_eq!(prn.as_slice().len(), 154);
        assert_eq!(
            &prn.as_slice()[..8],
            &[0x84, 0x44, b'P', b'R', b'N', b'1', 0x01, 0x50]
        );
        assert_eq!(
            &Sha256::digest(prn.as_slice())[..],
            &hex_bytes::<32>("d272f30cfebd664ce92337a0dd28bb8c219e15658812ad7c329024a94ec49e92")?
        );
        assert_eq!(PrincipalRefV1::decode(&prn), Ok(principal.clone()));

        let record = AuthenticatedPrincipalRecordV1 {
            principal,
            adapter_id: "b".repeat(128),
            assurance: 255,
            issued_at: u64::MAX - 1,
            expires_at: u64::MAX,
            registry_binding: Hash::from_bytes([0xff; 32]),
            operation_nonce: [0xff; 32],
        };
        let apr = record.to_canonical_cbor()?;
        assert_eq!(apr.len(), MAX_AUTHENTICATED_PRINCIPAL_RECORD_BYTES_V1);
        assert_eq!(&apr[..8], &[0x89, 0x64, b'A', b'P', b'R', b'1', 0x01, 0x58]);
        assert_eq!(
            &Sha256::digest(&apr)[..],
            &hex_bytes::<32>("73ea583c8d8c0705ed2e3a5088399753471eaed2a93ff22616f0b6c77398afe9")?
        );
        assert_eq!(
            AuthenticatedPrincipalRecordV1::from_canonical_cbor(&apr),
            Ok(record.clone())
        );
        let mut oversized_apr = apr;
        oversized_apr.push(0);
        assert_eq!(
            AuthenticatedPrincipalRecordV1::from_canonical_cbor(&oversized_apr),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );

        let evidence = AuthenticatedPrincipalEvidenceV1::new(record, [0xaa; 64])?;
        let fae = evidence.to_canonical_cbor()?;
        assert_eq!(fae.len(), MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1);
        assert_eq!(&fae[..8], &[0x84, 0x64, b'F', b'A', b'E', b'1', 0x01, 0x59]);
        assert_eq!(
            &Sha256::digest(&fae)[..],
            &hex_bytes::<32>("03815978b5a2cdf79f7ff9809104c80a8f02bc9005ddbad89e8c9eabe09965dc")?
        );
        assert_eq!(
            AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&fae),
            Ok(evidence)
        );
        let mut oversized_fae = fae.clone();
        oversized_fae.push(0);
        assert_eq!(
            AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&oversized_fae),
            Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
        );
        let mut old_marker = fae;
        old_marker[2..6].copy_from_slice(b"APS1");
        assert!(AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&old_marker).is_err());
        Ok(())
    }
}
