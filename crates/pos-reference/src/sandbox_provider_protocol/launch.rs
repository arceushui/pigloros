//! ADR-069 launcher barrier records: LPV1, `ReadyV1` (`RDY1`) and `ReleaseV1` (`RLS1`).
//!
//! LPV1 and `RDY1` are self-digested; `RLS1` is signed by the provider
//! runtime-attestation key. Every constructor validates the same rules as the
//! decoder. Fields are public, like the sibling records, so the encoder does
//! not revalidate a mutated value; every decoder does, so bytes that violate a
//! rule are never accepted.

use ciborium::value::Value;

use super::codec::{
    array, bytes_value, decode_document, decode_text_list, digest32, encode, fixed_bytes, id16,
    key_id, normalized_absolute_path, record_digest, require_signature, self_digested,
    signature_message, signed, text_value, uint, uint_value, valid_key_id, verify_digest,
    verify_signature,
};
use super::SandboxProviderProtocolError;

/// LPV1 is limited to 64 KiB before the provider-private hexadecimal encoding.
const MAX_LAUNCH_PARAMETER_BYTES: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 256;

/// Mount ID and inode of one held descriptor (`fd-identity`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdIdentity {
    /// Kernel mount ID of the descriptor's mount.
    pub mount_id: u64,
    /// Inode number; never zero.
    pub inode: u64,
}

impl FdIdentity {
    fn decode(value: &Value) -> Result<Self, SandboxProviderProtocolError> {
        let pair = array::<2>(value)?;
        Ok(Self {
            mount_id: uint(&pair[0])?,
            inode: uint(&pair[1])?,
        })
    }

    fn value(self) -> Value {
        Value::Array(vec![uint_value(self.mount_id), uint_value(self.inode)])
    }

    const fn valid(self) -> bool {
        self.inode != 0
    }
}

fn nonzero(digests: &[[u8; 32]]) -> bool {
    digests.iter().all(|digest| digest != &[0; 32])
}

fn finish_self_digested(
    magic: &str,
    unsigned: &[Value],
) -> Result<([u8; 32], Vec<u8>), SandboxProviderProtocolError> {
    let unsigned = Value::Array(unsigned.to_vec());
    record_digest(magic, &unsigned).and_then(|digest| {
        encode(&Value::Array(vec![unsigned, bytes_value(&digest)])).map(|bytes| (digest, bytes))
    })
}

/// Exact launch parameters the provider hands the launcher (LPV1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchParameters {
    /// Attempt the launch belongs to.
    pub attempt_id: [u8; 16],
    /// Provider-issued single-use nonce.
    pub nonce: [u8; 32],
    /// Admitted SIM1 digest.
    pub sim1_digest: [u8; 32],
    /// Normalized adapter path inside the activated root.
    pub adapter_path: String,
    /// Fixed adapter argument vector from SIM1.
    pub arguments: Vec<String>,
    /// Expected FDL1 digest for the execution mode.
    pub expected_fdl1_digest: [u8; 32],
    /// LPV1 self-digest, which `ReadyV1` binds as the launch-parameter digest.
    pub digest: [u8; 32],
}

impl LaunchParameters {
    /// Build one LPV1 record and compute its self-digest.
    ///
    /// # Errors
    /// Rejects zero identities, a non-normalized path, an unrepresentable
    /// argument, or a record larger than 64 KiB.
    pub fn new(
        attempt_id: [u8; 16],
        nonce: [u8; 32],
        sim1_digest: [u8; 32],
        adapter_path: String,
        arguments: Vec<String>,
        expected_fdl1_digest: [u8; 32],
    ) -> Result<Self, SandboxProviderProtocolError> {
        let mut record = Self {
            attempt_id,
            nonce,
            sim1_digest,
            adapter_path,
            arguments,
            expected_fdl1_digest,
            digest: [0; 32],
        };
        record.validate_fields()?;
        finish_self_digested("LPV1", &record.unsigned_value()).and_then(|(digest, bytes)| {
            if bytes.len() > MAX_LAUNCH_PARAMETER_BYTES {
                Err(SandboxProviderProtocolError::FieldOutOfBounds)
            } else {
                record.digest = digest;
                Ok(record)
            }
        })
    }

    /// Exact canonical LPV1 bytes.
    ///
    /// # Errors
    /// Returns an encoding error if the record cannot be serialized.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        finish_self_digested("LPV1", &self.unsigned_value()).map(|(_, bytes)| bytes)
    }

    /// Decode and validate exact canonical LPV1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        if bytes.len() > MAX_LAUNCH_PARAMETER_BYTES {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        let document = decode_document(bytes)?;
        let (fields, digest) = self_digested::<8>(&document, "LPV1")?;
        let record = Self {
            attempt_id: id16(&fields[2])?,
            nonce: fixed_bytes(&fields[3])?,
            sim1_digest: digest32(&fields[4])?,
            adapter_path: super::codec::text(&fields[5])?.to_owned(),
            arguments: decode_text_list(&fields[6])?,
            expected_fdl1_digest: digest32(&fields[7])?,
            digest,
        };
        record.validate_fields()?;
        verify_digest("LPV1", fields, digest).map(|()| record)
    }

    fn validate_fields(&self) -> Result<(), SandboxProviderProtocolError> {
        let arguments_valid = self.arguments.len() <= MAX_ARGUMENTS
            && self.arguments.iter().all(|argument| {
                !argument.is_empty()
                    && argument.len() <= MAX_ARGUMENT_BYTES
                    && !argument.contains('\0')
            });
        if self.attempt_id == [0; 16]
            || !nonzero(&[self.nonce, self.sim1_digest, self.expected_fdl1_digest])
            || !normalized_absolute_path(&self.adapter_path)
            || !arguments_valid
        {
            Err(SandboxProviderProtocolError::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_value(&self) -> [Value; 8] {
        [
            text_value("LPV1"),
            uint_value(1),
            bytes_value(&self.attempt_id),
            bytes_value(&self.nonce),
            bytes_value(&self.sim1_digest),
            text_value(&self.adapter_path),
            Value::Array(self.arguments.iter().map(|a| text_value(a)).collect()),
            bytes_value(&self.expected_fdl1_digest),
        ]
    }
}

/// The body of a `ReadyV1` before its self-digest exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherReadyFields {
    /// Attempt the launcher serves.
    pub attempt_id: [u8; 16],
    /// Provider-issued single-use nonce echoed from LPV1.
    pub nonce: [u8; 32],
    /// Provider-launch-instance ID decoded from systemd's `INVOCATION_ID`.
    pub launch_instance_id: [u8; 16],
    /// BLAKE3 digest of the launcher executable.
    pub launcher_digest: [u8; 32],
    /// `/proc/<MainPID>/exe` mount and inode identity.
    pub launcher_identity: FdIdentity,
    /// Admitted SIM1 digest.
    pub sim1_digest: [u8; 32],
    /// BLAKE3 digest of the held adapter executable descriptor.
    pub adapter_digest: [u8; 32],
    /// Held adapter descriptor mount and inode identity.
    pub adapter_identity: FdIdentity,
    /// LPV1 self-digest.
    pub launch_parameter_digest: [u8; 32],
    /// Expected FDL1 digest.
    pub expected_fdl1_digest: [u8; 32],
    /// FDL1 digest of the descriptors the launcher actually observed.
    pub observed_fdl1_digest: [u8; 32],
}

/// Launcher readiness evidence (`ReadyV1`, `RDY1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherReady {
    /// Digested body.
    pub fields: LauncherReadyFields,
    /// `RDY1` self-digest.
    pub digest: [u8; 32],
}

impl LauncherReady {
    /// Build one `RDY1` record and compute its self-digest.
    ///
    /// # Errors
    /// Rejects zero identities, digests or inodes.
    pub fn new(fields: LauncherReadyFields) -> Result<Self, SandboxProviderProtocolError> {
        validate_ready_fields(&fields)?;
        finish_self_digested("RDY1", &ready_unsigned_value(&fields))
            .map(|(digest, _)| Self { fields, digest })
    }

    /// Exact canonical `RDY1` bytes.
    ///
    /// # Errors
    /// Returns an encoding error if the record cannot be serialized.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        finish_self_digested("RDY1", &ready_unsigned_value(&self.fields)).map(|(_, bytes)| bytes)
    }

    /// Decode and validate exact canonical `RDY1` bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let document = decode_document(bytes)?;
        let (values, digest) = self_digested::<13>(&document, "RDY1")?;
        let fields = LauncherReadyFields {
            attempt_id: id16(&values[2])?,
            nonce: fixed_bytes(&values[3])?,
            launch_instance_id: id16(&values[4])?,
            launcher_digest: digest32(&values[5])?,
            launcher_identity: FdIdentity::decode(&values[6])?,
            sim1_digest: digest32(&values[7])?,
            adapter_digest: digest32(&values[8])?,
            adapter_identity: FdIdentity::decode(&values[9])?,
            launch_parameter_digest: digest32(&values[10])?,
            expected_fdl1_digest: digest32(&values[11])?,
            observed_fdl1_digest: digest32(&values[12])?,
        };
        validate_ready_fields(&fields)?;
        verify_digest("RDY1", values, digest).map(|()| Self { fields, digest })
    }
}

fn validate_ready_fields(fields: &LauncherReadyFields) -> Result<(), SandboxProviderProtocolError> {
    if fields.attempt_id == [0; 16]
        || fields.launch_instance_id == [0; 16]
        || !fields.launcher_identity.valid()
        || !fields.adapter_identity.valid()
        || !nonzero(&[
            fields.nonce,
            fields.launcher_digest,
            fields.sim1_digest,
            fields.adapter_digest,
            fields.launch_parameter_digest,
            fields.expected_fdl1_digest,
            fields.observed_fdl1_digest,
        ])
    {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn ready_unsigned_value(fields: &LauncherReadyFields) -> [Value; 13] {
    [
        text_value("RDY1"),
        uint_value(1),
        bytes_value(&fields.attempt_id),
        bytes_value(&fields.nonce),
        bytes_value(&fields.launch_instance_id),
        bytes_value(&fields.launcher_digest),
        fields.launcher_identity.value(),
        bytes_value(&fields.sim1_digest),
        bytes_value(&fields.adapter_digest),
        fields.adapter_identity.value(),
        bytes_value(&fields.launch_parameter_digest),
        bytes_value(&fields.expected_fdl1_digest),
        bytes_value(&fields.observed_fdl1_digest),
    ]
}

/// The signed body of a `ReleaseV1` before its digest and signature exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReleaseFields {
    /// Attempt being released.
    pub attempt_id: [u8; 16],
    /// Nonce of the matching LPV1 and `ReadyV1`.
    pub nonce: [u8; 32],
    /// `RDY1` self-digest this release answers.
    pub ready1_digest: [u8; 32],
    /// Current TRS1 digest.
    pub trs1_digest: [u8; 32],
    /// Current RVS1 digest.
    pub rvs1_digest: [u8; 32],
    /// Current APT1 digest.
    pub apt1_digest: [u8; 32],
    /// Trust epoch.
    pub trust_epoch: u64,
    /// Revocation epoch.
    pub revocation_epoch: u64,
    /// Policy epoch.
    pub policy_epoch: u64,
    /// Expected readback-set digest.
    pub expected_readback_digest: [u8; 32],
    /// Observed readback digest.
    pub observed_readback_digest: [u8; 32],
    /// Absolute `CLOCK_MONOTONIC` deadline in nanoseconds; never zero.
    pub deadline_monotonic_ns: u64,
    /// Provider runtime-attestation key ID.
    pub runtime_attestation_key_id: String,
}

/// Signed `ReleaseV1` (`RLS1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRelease {
    /// Signed body.
    pub fields: ExecutionReleaseFields,
    /// `RLS1` self-digest.
    pub digest: [u8; 32],
    signature: [u8; 64],
}

impl ExecutionRelease {
    /// Compute the self-digest and sign it with a runtime-attestation signer.
    ///
    /// `sign` receives the exact domain-separated message
    /// (`PiglorOS.RLS1.Signature.v1\0 || digest`) and returns the Ed25519
    /// signature.
    ///
    /// # Errors
    /// Rejects zero identities, digests, deadline or an invalid key ID, and a
    /// zero signature.
    pub fn sign(
        fields: ExecutionReleaseFields,
        sign: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Result<Self, SandboxProviderProtocolError> {
        validate_release_fields(&fields)
            .and_then(|()| finish_self_digested("RLS1", &release_unsigned_value(&fields)))
            .and_then(|(digest, _)| {
                let signature = sign(&signature_message("RLS1", &digest));
                require_signature(&signature).map(|()| Self {
                    fields,
                    digest,
                    signature,
                })
            })
    }

    /// Exact canonical `RLS1` bytes.
    ///
    /// # Errors
    /// Returns an encoding error if the record cannot be serialized.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        encode(&Value::Array(vec![
            Value::Array(release_unsigned_value(&self.fields).to_vec()),
            bytes_value(&self.digest),
            bytes_value(&self.signature),
        ]))
    }

    /// Decode and validate exact canonical `RLS1` bytes.
    ///
    /// Decoding does not verify the signature; call [`Self::verify_signature`]
    /// with the authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let document = decode_document(bytes)?;
        let (fields, digest, signature) = signed::<15>(&document, "RLS1")?;
        let body = ExecutionReleaseFields {
            attempt_id: id16(&fields[2])?,
            nonce: fixed_bytes(&fields[3])?,
            ready1_digest: digest32(&fields[4])?,
            trs1_digest: digest32(&fields[5])?,
            rvs1_digest: digest32(&fields[6])?,
            apt1_digest: digest32(&fields[7])?,
            trust_epoch: uint(&fields[8])?,
            revocation_epoch: uint(&fields[9])?,
            policy_epoch: uint(&fields[10])?,
            expected_readback_digest: digest32(&fields[11])?,
            observed_readback_digest: digest32(&fields[12])?,
            deadline_monotonic_ns: uint(&fields[13])?,
            runtime_attestation_key_id: key_id(&fields[14])?,
        };
        validate_release_fields(&body)?;
        require_signature(&signature)?;
        verify_digest("RLS1", fields, digest)?;
        Ok(Self {
            fields: body,
            digest,
            signature,
        })
    }

    /// Verify the Ed25519 signature with the authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns `SignatureInvalid` when verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        verify_signature("RLS1", &self.digest, &self.signature, key)
    }
}

fn validate_release_fields(
    fields: &ExecutionReleaseFields,
) -> Result<(), SandboxProviderProtocolError> {
    if fields.attempt_id == [0; 16]
        || fields.deadline_monotonic_ns == 0
        || !valid_key_id(&fields.runtime_attestation_key_id)
        || !nonzero(&[
            fields.nonce,
            fields.ready1_digest,
            fields.trs1_digest,
            fields.rvs1_digest,
            fields.apt1_digest,
            fields.expected_readback_digest,
            fields.observed_readback_digest,
        ])
    {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn release_unsigned_value(fields: &ExecutionReleaseFields) -> [Value; 15] {
    [
        text_value("RLS1"),
        uint_value(1),
        bytes_value(&fields.attempt_id),
        bytes_value(&fields.nonce),
        bytes_value(&fields.ready1_digest),
        bytes_value(&fields.trs1_digest),
        bytes_value(&fields.rvs1_digest),
        bytes_value(&fields.apt1_digest),
        uint_value(fields.trust_epoch),
        uint_value(fields.revocation_epoch),
        uint_value(fields.policy_epoch),
        bytes_value(&fields.expected_readback_digest),
        bytes_value(&fields.observed_readback_digest),
        uint_value(fields.deadline_monotonic_ns),
        text_value(&fields.runtime_attestation_key_id),
    ]
}
