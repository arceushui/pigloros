//! Host-private Linux credential and peer-identity boundary for ADR-107.
//!
//! It produces FAE1 only from a kernel-authenticated Unix peer and resolves
//! the Owner only through the same protected FACR1 registry. It also signs the
//! typed FAI1/FAO1/FAC1/FRP1 inputs that the private coordinator builds; the
//! ADR-109 listener and journal orchestration live in `local_fork_listener`
//! and `local_fork_coordinator`.

use std::{
    fs::{File, OpenOptions},
    io::{Cursor, Read, Write},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
        unix::net::UnixStream,
    },
    path::Path,
};

use ciborium::value::Value;
use pos_core::{
    fork_authentication::{
        principal_digest_v1, AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
        ForkAuthenticationPolicyV1, LocalAccountBindingV1, LocalAccountRegistryV1,
        MAX_FORK_AUTH_CREDENTIAL_BYTES_V1, MAX_FORK_AUTH_POLICY_BYTES_V1,
    },
    CanonicalBytes, ForkAdmissionCommandCodecErrorV1, ForkAdmissionHostCommandV1,
    ForkAdmissionHostRecordV1, ForkAdmissionInitializeChallengeV1, ForkAdmissionOpenChallengeV1,
    ForkAdmissionRecoveryCommandV1, ForkAdmissionRecoveryProofV1, ForkCreateCommandV1, Hash,
    OwnerIdV1, PrincipalOwnerCommandV1, PrincipalRefV1, PublicKey,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, ForkAuthenticationAdapterSigningKeyV1,
    ForkAuthenticationSignatureErrorV1, ForkHostSigningKeyV1,
    VerifiedAuthenticatedPrincipalEvidenceV1,
};
use pos_store::{
    ForkAdmissionAuthorityBootstrapPortV1, ForkAdmissionAuthorityErrorV1,
    ForkAdmissionAuthoritySessionV1,
};
use rustix::fs::{openat, Dir, Mode, OFlags};
use rustix::net::sockopt::socket_peercred;
use rustix::rand::{getrandom, GetRandomFlags};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const AUTH_CREDENTIAL_NAME: &str = "pigloros.fork-admission-auth";
const HOST_CREDENTIAL_NAME: &str = "pigloros.fork-admission-host-signer";
const FAHK1_BYTES: usize = 42;
const PRIVATE_CREDENTIAL_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_CREDENTIAL_FILE_MODE: u32 = 0o400;
const AUTHENTICATION_LIFETIME_MICROS: u64 = 30_000_000;
/// ADR-107 FACR1 field bounds that pos-core does not export.
const MAX_FACR1_BINDINGS_V1: usize = 64;
const MAX_FACR1_TEXT_BYTES_V1: usize = 128;
const MAX_FACR1_PRINCIPAL_BYTES_V1: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum LocalForkAuthenticationErrorV1 {
    #[error("fork admission credential unavailable")]
    CredentialUnavailable,
    #[error("fork admission credential invalid")]
    CredentialInvalid,
    #[error("fork admission peer is not authenticated")]
    PeerUnauthenticated,
}

/// Closed result of the deployment-only FAI1/FAO1 host lifecycle.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum LocalForkAuthorityBootstrapErrorV1 {
    #[error("fork admission credentials are unavailable")]
    Credentials(#[from] LocalForkAuthenticationErrorV1),
    #[error("fork admission authority bootstrap failed")]
    Authority(#[from] ForkAdmissionAuthorityErrorV1),
}

/// Loaded, purpose-separated authority inputs retained only by the host.
pub(super) struct LocalForkAuthenticationCredentialsV1 {
    resolver: PrincipalOwnerResolverV1,
    adapter_signer: ForkAuthenticationAdapterSigningKeyV1,
    host_signer: LocalForkHostSignerV1,
}

impl LocalForkAuthenticationCredentialsV1 {
    /// Load exactly the two systemd credential names from one protected directory.
    ///
    /// The directory is opened once without following symlinks. Its names and
    /// children are read relative to that descriptor, and children are opened
    /// non-blocking so a FIFO fails the regular-file check instead of blocking.
    pub(super) fn load(
        directory: &Path,
        service_uid: u32,
    ) -> Result<Self, LocalForkAuthenticationErrorV1> {
        let directory = open_credential_directory(directory, service_uid)?;
        credential_names(&directory)?;
        let auth_bytes = Zeroizing::new(read_credential(
            &directory,
            AUTH_CREDENTIAL_NAME,
            service_uid,
        )?);
        let host_bytes = Zeroizing::new(read_credential(
            &directory,
            HOST_CREDENTIAL_NAME,
            service_uid,
        )?);
        parse_credentials(&auth_bytes, &host_bytes, service_uid)
    }

    #[must_use]
    pub(super) const fn policy(&self) -> &ForkAuthenticationPolicyV1 {
        self.resolver.policy()
    }

    #[cfg(test)]
    #[must_use]
    pub(super) const fn adapter_public_key(&self) -> [u8; 32] {
        self.adapter_signer.public_key()
    }

    /// Authenticate a connected pathname Unix peer by its kernel UID only.
    pub(super) fn authenticate_peer(
        &self,
        stream: &UnixStream,
    ) -> Result<AuthenticatedUnixPeerV1, LocalForkAuthenticationErrorV1> {
        socket_peercred(stream.as_fd())
            .map_err(|_| LocalForkAuthenticationErrorV1::PeerUnauthenticated)
            .and_then(|credentials| {
                self.resolver
                    .registry()
                    .lookup_uid(credentials.uid.as_raw())
                    .map(|binding| AuthenticatedUnixPeerV1 {
                        principal: binding.principal.clone(),
                    })
                    .ok_or(LocalForkAuthenticationErrorV1::PeerUnauthenticated)
            })
    }

    /// Produce one opaque FAE1 from an internally authenticated Unix peer.
    pub(super) fn produce(
        &self,
        peer: AuthenticatedUnixPeerV1,
    ) -> Result<ProducedLocalAuthenticationEvidenceV1, LocalForkAuthenticationErrorV1> {
        self.produce_with(peer, production_wall_time, operation_nonce)
    }

    fn produce_with(
        &self,
        peer: AuthenticatedUnixPeerV1,
        wall_time: impl FnOnce() -> Result<u64, LocalForkAuthenticationErrorV1>,
        nonce: impl FnOnce() -> Result<[u8; 32], LocalForkAuthenticationErrorV1>,
    ) -> Result<ProducedLocalAuthenticationEvidenceV1, LocalForkAuthenticationErrorV1> {
        let issued_at = wall_time()?;
        let expires_at = issued_at
            .checked_add(AUTHENTICATION_LIFETIME_MICROS)
            .ok_or(LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
        self.resolver
            .registry()
            .digest()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
            .and_then(|registry_binding| {
                nonce().map(|operation_nonce| AuthenticatedPrincipalRecordV1 {
                    principal: peer.principal,
                    adapter_id: self.resolver.registry().adapter_id().to_owned(),
                    assurance: self.resolver.registry().assurance(),
                    issued_at,
                    expires_at,
                    registry_binding,
                    operation_nonce,
                })
            })
            .and_then(|record| {
                self.adapter_signer
                    .sign_authenticated_principal(record)
                    .map(ProducedLocalAuthenticationEvidenceV1)
                    .map_err(signature_invalid)
            })
    }

    /// Verify locally produced FAE1 and resolve its Owner from FACR1 only.
    pub(super) fn resolve(
        &self,
        evidence: ProducedLocalAuthenticationEvidenceV1,
    ) -> Result<ResolvedLocalAuthenticationV1, LocalForkAuthenticationErrorV1> {
        self.resolver.resolve(evidence.0)
    }

    /// Sign one typed ADR-106 FAI1 challenge through protected host custody.
    pub(super) fn sign_initialize(
        &self,
        challenge: &ForkAdmissionInitializeChallengeV1,
    ) -> Result<pos_core::Signature, LocalForkAuthenticationErrorV1> {
        self.host_signer.sign_initialize(challenge)
    }

    /// Sign one typed ADR-106 FAO1 challenge through protected host custody.
    pub(super) fn sign_open(
        &self,
        challenge: &ForkAdmissionOpenChallengeV1,
    ) -> Result<pos_core::Signature, LocalForkAuthenticationErrorV1> {
        self.host_signer.sign_open(challenge)
    }

    #[must_use]
    pub(super) const fn host_public_key(&self) -> [u8; 32] {
        self.host_signer.public_key()
    }

    /// Sign one owner-bound typed ADR-106 POC1 command through protected custody.
    pub(super) fn sign_principal_owner_command(
        &self,
        command: &PrincipalOwnerCommandV1,
        authentication: &ResolvedLocalAuthenticationV1,
    ) -> Result<ForkAdmissionHostCommandV1, LocalForkAuthenticationErrorV1> {
        self.host_signer.sign_command(command, authentication)
    }

    /// Sign one typed ADR-106 FCC1 command through protected host custody.
    pub(super) fn sign_fork_command(
        &self,
        command: &ForkCreateCommandV1,
        authentication: &ResolvedLocalAuthenticationV1,
    ) -> Result<ForkAdmissionHostCommandV1, LocalForkAuthenticationErrorV1> {
        self.host_signer.sign_fork_command(command, authentication)
    }

    /// Sign one typed ADR-106 FRC1 recovery command through protected custody.
    pub(super) fn sign_recovery(
        &self,
        command: &ForkAdmissionRecoveryCommandV1,
    ) -> Result<ForkAdmissionRecoveryProofV1, LocalForkAuthenticationErrorV1> {
        self.host_signer.sign_recovery(command)
    }

    /// Consume one FAI1 challenge and durably establish this credential's FAH1.
    /// This deployment operation never accepts a public policy or host key.
    pub(super) fn provision_authority<S>(
        &self,
        store: &mut S,
    ) -> Result<ForkAdmissionHostRecordV1, LocalForkAuthorityBootstrapErrorV1>
    where
        S: ForkAdmissionAuthorityBootstrapPortV1,
    {
        self.policy()
            .digest()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
            .map_err(LocalForkAuthorityBootstrapErrorV1::from)
            .and_then(|policy_digest| {
                store
                    .begin_fork_admission_initialize(
                        PublicKey::from_bytes(self.host_public_key()),
                        policy_digest,
                    )
                    .map_err(LocalForkAuthorityBootstrapErrorV1::from)
                    .and_then(|challenge| {
                        self.sign_initialize(&challenge)
                            .map_err(LocalForkAuthorityBootstrapErrorV1::from)
                            .and_then(|signature| {
                                store
                                    .finalize_fork_admission_initialize(&challenge, &signature)
                                    .map_err(LocalForkAuthorityBootstrapErrorV1::from)
                            })
                    })
            })
    }

    /// Consume one FAO1 challenge after proving exact persisted FAH1 identity.
    pub(super) fn open_authority<S>(
        &self,
        store: &mut S,
    ) -> Result<ForkAdmissionAuthoritySessionV1, LocalForkAuthorityBootstrapErrorV1>
    where
        S: ForkAdmissionAuthorityBootstrapPortV1,
    {
        self.policy()
            .digest()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
            .map_err(LocalForkAuthorityBootstrapErrorV1::from)
            .and_then(|policy_digest| {
                store
                    .begin_fork_admission_open(
                        PublicKey::from_bytes(self.host_public_key()),
                        policy_digest,
                    )
                    .map_err(LocalForkAuthorityBootstrapErrorV1::from)
                    .and_then(|challenge| {
                        self.sign_open(&challenge)
                            .map_err(LocalForkAuthorityBootstrapErrorV1::from)
                            .and_then(|signature| {
                                store
                                    .finalize_fork_admission_open(&challenge, &signature)
                                    .map_err(LocalForkAuthorityBootstrapErrorV1::from)
                            })
                    })
            })
    }
}

/// Host-private Principal-to-Owner resolver over the protected FACR1 registry.
pub(super) struct PrincipalOwnerResolverV1 {
    policy: ForkAuthenticationPolicyV1,
    registry: LocalAccountRegistryV1,
}

impl PrincipalOwnerResolverV1 {
    const fn new(policy: ForkAuthenticationPolicyV1, registry: LocalAccountRegistryV1) -> Self {
        Self { policy, registry }
    }

    const fn policy(&self) -> &ForkAuthenticationPolicyV1 {
        &self.policy
    }

    const fn registry(&self) -> &LocalAccountRegistryV1 {
        &self.registry
    }

    fn resolve(
        &self,
        evidence: AuthenticatedPrincipalEvidenceV1,
    ) -> Result<ResolvedLocalAuthenticationV1, LocalForkAuthenticationErrorV1> {
        verify_authenticated_principal_evidence_v1(&self.policy, evidence)
            .map_err(signature_invalid)
            .and_then(|verified| {
                // Every commitment is computed once here, from the verified
                // FAE1 bytes, so later FAC1/FRP1 construction is infallible.
                let resolved = {
                    let evidence = verified.evidence();
                    let record = evidence.record();
                    self.registry
                        .digest()
                        .and_then(|registry_binding| {
                            principal_digest_v1(&record.principal).and_then(|principal_digest| {
                                evidence.digest().map(|evidence_digest| {
                                    (registry_binding, principal_digest, evidence_digest)
                                })
                            })
                        })
                        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
                        .and_then(|(registry_binding, principal_digest, evidence_digest)| {
                            if record.adapter_id != self.registry.adapter_id()
                                || record.assurance != self.registry.assurance()
                                || record.registry_binding != registry_binding
                            {
                                return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
                            }
                            self.registry
                                .lookup_principal(&record.principal)
                                .map(|owner| (owner, principal_digest, evidence_digest))
                                .ok_or(LocalForkAuthenticationErrorV1::PeerUnauthenticated)
                        })
                };
                resolved.map(|(owner, principal_digest, evidence_digest)| {
                    ResolvedLocalAuthenticationV1 {
                        verified,
                        owner,
                        principal_digest,
                        evidence_digest,
                    }
                })
            })
    }
}

/// Opaque host-signing custody.
///
/// Only typed ADR-106 challenges and commands enter this boundary, so the
/// command marker is fixed by the input type. The raw purpose-limited signer
/// never crosses it.
pub(super) struct LocalForkHostSignerV1 {
    signer: ForkHostSigningKeyV1,
}

impl LocalForkHostSignerV1 {
    const fn public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    fn sign_initialize(
        &self,
        challenge: &ForkAdmissionInitializeChallengeV1,
    ) -> Result<pos_core::Signature, LocalForkAuthenticationErrorV1> {
        self.signer
            .sign_initialize(&challenge.canonical_bytes())
            .map_err(signature_invalid)
    }

    fn sign_open(
        &self,
        challenge: &ForkAdmissionOpenChallengeV1,
    ) -> Result<pos_core::Signature, LocalForkAuthenticationErrorV1> {
        self.signer
            .sign_open(&challenge.canonical_bytes())
            .map_err(signature_invalid)
    }

    fn sign_command(
        &self,
        command: &PrincipalOwnerCommandV1,
        authentication: &ResolvedLocalAuthenticationV1,
    ) -> Result<ForkAdmissionHostCommandV1, LocalForkAuthenticationErrorV1> {
        if !principal_owner_matches(command, authentication.owner()) {
            return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
        }
        self.command(command.to_canonical_cbor(), authentication)
    }

    fn sign_fork_command(
        &self,
        command: &ForkCreateCommandV1,
        authentication: &ResolvedLocalAuthenticationV1,
    ) -> Result<ForkAdmissionHostCommandV1, LocalForkAuthenticationErrorV1> {
        self.command(command.to_canonical_cbor(), authentication)
    }

    fn sign_recovery(
        &self,
        command: &ForkAdmissionRecoveryCommandV1,
    ) -> Result<ForkAdmissionRecoveryProofV1, LocalForkAuthenticationErrorV1> {
        let command = command.to_canonical_cbor();
        self.signer
            .sign_recovery(&command)
            .map_err(signature_invalid)
            .and_then(|signature| {
                decode_record(
                    vec![
                        Value::Text("FRP1".to_owned()),
                        Value::Integer(1.into()),
                        Value::Bytes(command),
                        Value::Bytes(signature.as_bytes().to_vec()),
                    ],
                    ForkAdmissionRecoveryProofV1::from_canonical_cbor,
                )
            })
    }

    fn command(
        &self,
        command: Vec<u8>,
        authentication: &ResolvedLocalAuthenticationV1,
    ) -> Result<ForkAdmissionHostCommandV1, LocalForkAuthenticationErrorV1> {
        // Both FAC1 inputs fail closed with the same credential code, so one
        // mapped arm covers the signature and the FAE1 encoding.
        let verified = authentication.verified_evidence();
        self.signer
            .sign_command(&command, verified)
            .ok()
            .zip(verified.evidence().to_canonical_cbor().ok())
            .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)
            .and_then(|(signature, evidence)| {
                decode_record(
                    vec![
                        Value::Text("FAC1".to_owned()),
                        Value::Integer(1.into()),
                        Value::Bytes(command),
                        Value::Bytes(evidence),
                        Value::Bytes(signature.as_bytes().to_vec()),
                    ],
                    ForkAdmissionHostCommandV1::from_canonical_cbor,
                )
            })
    }
}

fn principal_owner_matches(command: &PrincipalOwnerCommandV1, owner: OwnerIdV1) -> bool {
    let bytes = command.to_canonical_cbor();
    let mut cursor = Cursor::new(bytes.as_slice());
    let value = ciborium::from_reader(&mut cursor);
    matches!(
        value,
        Ok(Value::Array(fields))
            if cursor.position() == u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                && matches!(fields.get(7), Some(Value::Text(candidate)) if candidate == owner.as_str())
    )
}

fn decode_record<T>(
    record: Vec<Value>,
    decode: impl FnOnce(&[u8]) -> Result<T, ForkAdmissionCommandCodecErrorV1>,
) -> Result<T, LocalForkAuthenticationErrorV1> {
    // Encoding into a Vec cannot fail; one arm covers both steps.
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Array(record), &mut bytes)
        .ok()
        .and_then(|()| decode(&bytes).ok())
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)
}

/// Non-cloneable result of one kernel-authenticated Unix connection.
pub(super) struct AuthenticatedUnixPeerV1 {
    principal: PrincipalRefV1,
}

/// Opaque evidence created only from a kernel-authenticated Unix peer.
pub(super) struct ProducedLocalAuthenticationEvidenceV1(AuthenticatedPrincipalEvidenceV1);

/// Verified local FAE1 together with the Owner resolved from the same FACR1 row
/// and the FAE1/Principal commitments computed once at resolution.
pub(super) struct ResolvedLocalAuthenticationV1 {
    verified: VerifiedAuthenticatedPrincipalEvidenceV1,
    owner: OwnerIdV1,
    principal_digest: Hash,
    evidence_digest: Hash,
}

impl ResolvedLocalAuthenticationV1 {
    #[must_use]
    pub(super) const fn owner(&self) -> OwnerIdV1 {
        self.owner
    }

    #[must_use]
    pub(super) const fn verified_evidence(&self) -> &VerifiedAuthenticatedPrincipalEvidenceV1 {
        &self.verified
    }

    #[must_use]
    pub(super) const fn principal_digest(&self) -> Hash {
        self.principal_digest
    }

    #[must_use]
    pub(super) const fn evidence_digest(&self) -> Hash {
        self.evidence_digest
    }
}

fn parse_credentials(
    auth_bytes: &[u8],
    host_bytes: &[u8],
    service_uid: u32,
) -> Result<LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1> {
    let (adapter_seed, policy, registry) = parse_facr1(auth_bytes, service_uid)?;
    let host_seed = parse_fahk1(host_bytes)?;
    // `from_seed` zeroizes its by-value seed copy. These guards retain the
    // extracted credential bytes across every fallible validation step.
    ForkAuthenticationAdapterSigningKeyV1::from_seed(*adapter_seed)
        .and_then(|adapter_signer| {
            ForkHostSigningKeyV1::from_seed(*host_seed)
                .map(|host_signer| (adapter_signer, host_signer))
        })
        .map_err(signature_invalid)
        .and_then(|signers| {
            registry
                .digest()
                .map(|registry_binding| (signers, registry_binding))
                .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
        })
        .and_then(|((adapter_signer, host_signer), registry_binding)| {
            let adapter_valid = policy
                .adapter(registry.adapter_id())
                .is_some_and(|adapter| {
                    adapter.verifying_key == adapter_signer.public_key()
                        && registry.assurance() >= adapter.minimum_assurance
                        && adapter.registry_bindings.contains(&registry_binding)
                });
            if !adapter_valid {
                return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
            }
            // Equal seeds derive equal keys, so this also rejects seed reuse.
            ensure_distinct_signing_keys(adapter_signer.public_key(), host_signer.public_key())?;
            Ok(LocalForkAuthenticationCredentialsV1 {
                resolver: PrincipalOwnerResolverV1::new(policy, registry),
                adapter_signer,
                host_signer: LocalForkHostSignerV1 {
                    signer: host_signer,
                },
            })
        })
}

fn ensure_distinct_signing_keys(
    adapter_public_key: [u8; 32],
    host_public_key: [u8; 32],
) -> Result<(), LocalForkAuthenticationErrorV1> {
    if adapter_public_key == host_public_key {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    Ok(())
}

fn parse_facr1(
    bytes: &[u8],
    service_uid: u32,
) -> Result<
    (
        Zeroizing<[u8; 32]>,
        ForkAuthenticationPolicyV1,
        LocalAccountRegistryV1,
    ),
    LocalForkAuthenticationErrorV1,
> {
    let mut values = canonical_array(bytes, "FACR1", 7)?;
    let seed = take_fixed_nonzero(&mut values.as_mut_slice()[2])?;
    let fields = values.as_slice();
    let policy_bytes = bounded_bytes(&fields[3], MAX_FORK_AUTH_POLICY_BYTES_V1)?;
    let policy = ForkAuthenticationPolicyV1::from_canonical_cbor(policy_bytes)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let adapter_id = bounded_text(&fields[4])?;
    let assurance = positive_u8(&fields[5])?;
    let entries = nonempty_array(&fields[6], MAX_FACR1_BINDINGS_V1)?;
    let bindings = entries
        .iter()
        .map(parse_binding)
        .collect::<Result<Vec<_>, _>>()?;
    let registry = LocalAccountRegistryV1::new(adapter_id, assurance, bindings, service_uid)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    Ok((seed, policy, registry))
}

fn parse_fahk1(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, LocalForkAuthenticationErrorV1> {
    if bytes.len() != FAHK1_BYTES {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let mut values = canonical_array(bytes, "FAHK1", 3)?;
    take_fixed_nonzero(&mut values.as_mut_slice()[2])
}

fn parse_binding(value: &Value) -> Result<LocalAccountBindingV1, LocalForkAuthenticationErrorV1> {
    let fields = array(value, 3)?;
    let uid = positive_u32(&fields[0])?;
    let principal_bytes = bounded_bytes(&fields[1], MAX_FACR1_PRINCIPAL_BYTES_V1)?;
    let principal = PrincipalRefV1::decode(&CanonicalBytes::from_vec(principal_bytes.to_vec()))
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let owner = bounded_text(&fields[2])?;
    OwnerIdV1::new(owner)
        .map(|owner| LocalAccountBindingV1 {
            uid,
            principal,
            owner,
        })
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
}

/// Open the credential directory itself (never a symlink) and validate it by descriptor.
fn open_credential_directory(
    directory: &Path,
    service_uid: u32,
) -> Result<File, LocalForkAuthenticationErrorV1> {
    if !directory.is_absolute() {
        return Err(LocalForkAuthenticationErrorV1::CredentialUnavailable);
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .and_then(|directory| directory.metadata().map(|metadata| (directory, metadata)))
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)
        .and_then(|(directory, metadata)| {
            if !metadata.is_dir()
                || metadata.uid() != service_uid
                || metadata.mode() & 0o777 != PRIVATE_CREDENTIAL_DIRECTORY_MODE
            {
                return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
            }
            Ok(directory)
        })
}

fn credential_names(directory: &File) -> Result<(), LocalForkAuthenticationErrorV1> {
    openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .and_then(Dir::new)
    .map_err(errno_unavailable)
    .and_then(|entries| {
        entries
            .map(|entry| {
                entry.map_err(errno_unavailable).and_then(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .map(str::to_owned)
                        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
                })
            })
            .filter(|name| !matches!(name.as_deref(), Ok("." | "..")))
            .collect::<Result<Vec<_>, _>>()
    })
    .and_then(|mut names| {
        names.sort_unstable();
        match names.as_slice() {
            [] => Err(LocalForkAuthenticationErrorV1::CredentialUnavailable),
            [name] if name == AUTH_CREDENTIAL_NAME || name == HOST_CREDENTIAL_NAME => {
                Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)
            }
            [auth, host] if auth == AUTH_CREDENTIAL_NAME && host == HOST_CREDENTIAL_NAME => Ok(()),
            _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
        }
    })
}

fn read_credential(
    directory: &File,
    name: &str,
    service_uid: u32,
) -> Result<Vec<u8>, LocalForkAuthenticationErrorV1> {
    openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(errno_unavailable)
    .and_then(|mut file| {
        file.metadata()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)
            .and_then(|metadata| {
                if !metadata.is_file()
                    || metadata.uid() != service_uid
                    || metadata.mode() & 0o777 != PRIVATE_CREDENTIAL_FILE_MODE
                {
                    return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
                }
                usize::try_from(metadata.len())
                    .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
                    .and_then(|size| {
                        if size > MAX_FORK_AUTH_CREDENTIAL_BYTES_V1 {
                            return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
                        }
                        finish_credential_read(&mut file, size)
                    })
            })
    })
}

const fn errno_unavailable(_: rustix::io::Errno) -> LocalForkAuthenticationErrorV1 {
    LocalForkAuthenticationErrorV1::CredentialUnavailable
}

fn finish_credential_read(
    reader: &mut impl Read,
    size: usize,
) -> Result<Vec<u8>, LocalForkAuthenticationErrorV1> {
    let mut bytes = Vec::with_capacity(size);
    if reader
        .take(u64::try_from(MAX_FORK_AUTH_CREDENTIAL_BYTES_V1 + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .is_err()
    {
        bytes.zeroize();
        return Err(LocalForkAuthenticationErrorV1::CredentialUnavailable);
    }
    if bytes.len() != size {
        bytes.zeroize();
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    Ok(bytes)
}

fn canonical_array(
    bytes: &[u8],
    marker: &str,
    expected_fields: usize,
) -> Result<SensitiveValues, LocalForkAuthenticationErrorV1> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let value = SensitiveValues::new(value)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let fields = value.as_slice();
    if fields.len() != expected_fields {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    if !matches!(fields.first(), Some(Value::Text(text)) if text == marker)
        || !matches!(fields.get(1), Some(Value::Integer(version)) if *version == 1.into())
    {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let mut encoded = Zeroizing::new(Vec::new());
    write_canonical_array(value.as_slice(), &mut *encoded).and_then(|()| {
        if encoded.as_slice() != bytes {
            return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
        }
        Ok(value)
    })
}

fn write_canonical_array(
    fields: &[Value],
    writer: &mut impl Write,
) -> Result<(), LocalForkAuthenticationErrorV1> {
    ciborium::into_writer(fields, writer)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
}

struct SensitiveValues(Vec<Value>);

impl SensitiveValues {
    fn new(value: Value) -> Result<Self, LocalForkAuthenticationErrorV1> {
        let Value::Array(values) = value else {
            let mut value = value;
            zeroize_value(&mut value);
            return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
        };
        Ok(Self(values))
    }

    fn as_slice(&self) -> &[Value] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [Value] {
        &mut self.0
    }
}

impl Drop for SensitiveValues {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(zeroize_value);
    }
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Tag(_, value) => zeroize_value(value),
        Value::Array(values) => values.iter_mut().for_each(zeroize_value),
        Value::Map(entries) => entries.iter_mut().for_each(|(key, value)| {
            zeroize_value(key);
            zeroize_value(value);
        }),
        _ => {}
    }
}

fn array(value: &Value, length: usize) -> Result<&[Value], LocalForkAuthenticationErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
    }
}

fn nonempty_array(
    value: &Value,
    maximum: usize,
) -> Result<&[Value], LocalForkAuthenticationErrorV1> {
    match value {
        Value::Array(values) if (1..=maximum).contains(&values.len()) => Ok(values),
        _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
    }
}

fn take_fixed_nonzero(
    value: &mut Value,
) -> Result<Zeroizing<[u8; 32]>, LocalForkAuthenticationErrorV1> {
    let Value::Bytes(bytes) = value else {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    };
    let is_valid = bytes.len() == 32 && bytes.iter().any(|byte| *byte != 0);
    if !is_valid {
        bytes.zeroize();
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(bytes);
    bytes.zeroize();
    Ok(seed)
}

fn bounded_bytes(value: &Value, maximum: usize) -> Result<&[u8], LocalForkAuthenticationErrorV1> {
    match value {
        Value::Bytes(bytes) if !bytes.is_empty() && bytes.len() <= maximum => Ok(bytes),
        _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
    }
}

fn bounded_text(value: &Value) -> Result<String, LocalForkAuthenticationErrorV1> {
    match value {
        Value::Text(text)
            if !text.is_empty()
                && text.len() <= MAX_FACR1_TEXT_BYTES_V1
                && !text.contains('\0') =>
        {
            Ok(text.clone())
        }
        _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
    }
}

fn positive_u8(value: &Value) -> Result<u8, LocalForkAuthenticationErrorV1> {
    match value {
        Value::Integer(value) => u8::try_from(*value)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid),
        _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
    }
}

fn positive_u32(value: &Value) -> Result<u32, LocalForkAuthenticationErrorV1> {
    match value {
        Value::Integer(value) => u32::try_from(*value)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid),
        _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
    }
}

const fn signature_invalid(
    _: ForkAuthenticationSignatureErrorV1,
) -> LocalForkAuthenticationErrorV1 {
    LocalForkAuthenticationErrorV1::CredentialInvalid
}

fn production_wall_time() -> Result<u64, LocalForkAuthenticationErrorV1> {
    wall_time_from_duration(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ()),
    )
}

fn wall_time_from_duration(
    duration: Result<std::time::Duration, ()>,
) -> Result<u64, LocalForkAuthenticationErrorV1> {
    let duration = duration.map_err(|()| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
    u64::try_from(duration.as_micros())
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)
}

fn operation_nonce() -> Result<[u8; 32], LocalForkAuthenticationErrorV1> {
    operation_nonce_with(random_fill)
}

fn random_fill(remaining: &mut [u8]) -> Result<usize, LocalForkAuthenticationErrorV1> {
    getrandom(remaining, GetRandomFlags::empty())
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)
}

fn operation_nonce_with(
    mut fill: impl FnMut(&mut [u8]) -> Result<usize, LocalForkAuthenticationErrorV1>,
) -> Result<[u8; 32], LocalForkAuthenticationErrorV1> {
    loop {
        let mut nonce = [0; 32];
        let mut remaining = nonce.as_mut_slice();
        while !remaining.is_empty() {
            let read = fill(&mut *remaining)?;
            if read == 0 {
                return Err(LocalForkAuthenticationErrorV1::CredentialUnavailable);
            }
            remaining = &mut remaining[read..];
        }
        if nonce != [0; 32] {
            return Ok(nonce);
        }
    }
}

/// Build valid private credentials for a real current-UID Unix-socket test.
///
/// Production loading deliberately requires the credential files and directory
/// to be owned by the service UID, while FACR1 forbids that UID as a client.
/// A non-root test process cannot model both facts through filesystem ownership,
/// so this fixture directly exercises the private parser with a synthetic,
/// distinct service UID. It is unavailable outside tests and exposes neither a
/// seed nor a production constructor.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn test_credentials_for_current_peer(
) -> Result<LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1> {
    test_credentials_for_current_peer_with_seeds([7; 32], [8; 32])
}

/// Build valid credentials whose registry deliberately excludes the current
/// Unix peer, for listener fail-closed boundary tests.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn test_credentials_rejecting_current_peer(
) -> Result<LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1> {
    let peer_uid = rustix::process::geteuid().as_raw();
    let service_uid = [1, 2]
        .into_iter()
        .find(|uid| *uid != peer_uid)
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let registered_uid = [3, 4, 5]
        .into_iter()
        .find(|uid| *uid != peer_uid && *uid != service_uid)
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let (facr1, fahk1) =
        test_credential_bytes_for_client(registered_uid, service_uid, [7; 32], [8; 32])?;
    parse_credentials(&facr1, &fahk1, service_uid)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn test_unregistered_peer(
) -> Result<AuthenticatedUnixPeerV1, LocalForkAuthenticationErrorV1> {
    let principal = PrincipalRefV1::try_new([0xff; 16], "unix.unregistered")
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    Ok(AuthenticatedUnixPeerV1 { principal })
}

/// Build current-peer credentials with explicit purpose-separated test seeds.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn test_credentials_for_current_peer_with_seeds(
    adapter_seed: [u8; 32],
    host_seed: [u8; 32],
) -> Result<LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1> {
    let peer_uid = rustix::process::geteuid().as_raw();
    let service_uid = [1, 2]
        .into_iter()
        .find(|uid| *uid != peer_uid)
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let (facr1, fahk1) =
        test_credential_bytes_for_client(peer_uid, service_uid, adapter_seed, host_seed)?;
    parse_credentials(&facr1, &fahk1, service_uid)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn test_credential_bytes_for_client(
    client_uid: u32,
    service_uid: u32,
    adapter_seed: [u8; 32],
    host_seed: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), LocalForkAuthenticationErrorV1> {
    use ciborium::value::Value;
    use pos_core::fork_authentication::ForkAuthenticationAdapterPolicyV1;

    let principal = PrincipalRefV1::try_new([9; 16], "unix.test")
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let registry = LocalAccountRegistryV1::new(
        "local-unix".to_owned(),
        2,
        vec![LocalAccountBindingV1 {
            uid: client_uid,
            principal: principal.clone(),
            owner: OwnerIdV1::from_static("owner"),
        }],
        service_uid,
    )
    .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(adapter_seed)
        .map_err(signature_invalid)?;
    let policy = ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
        adapter_id: "local-unix".to_owned(),
        verifying_key: adapter.public_key(),
        minimum_assurance: 2,
        registry_bindings: vec![registry
            .digest()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?],
    }])
    .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let principal = principal
        .encode()
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let facr1 = test_credential_cbor(&Value::Array(vec![
        Value::Text("FACR1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(adapter_seed.to_vec()),
        Value::Bytes(
            policy
                .to_canonical_cbor()
                .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?,
        ),
        Value::Text("local-unix".to_owned()),
        Value::Integer(2.into()),
        Value::Array(vec![Value::Array(vec![
            Value::Integer(client_uid.into()),
            Value::Bytes(principal.as_slice().to_vec()),
            Value::Text("owner".to_owned()),
        ])]),
    ]))?;
    let fahk1 = test_credential_cbor(&Value::Array(vec![
        Value::Text("FAHK1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(host_seed.to_vec()),
    ]))?;
    Ok((facr1, fahk1))
}

/// Produce two valid, purpose-separated credential payloads for service tests.
///
/// This fixture is test-only. Production authority inputs can only enter
/// through the protected filesystem loader.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) fn test_credential_bytes_for_service(
    service_uid: u32,
    adapter_seed: [u8; 32],
    host_seed: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), LocalForkAuthenticationErrorV1> {
    let client_uid = [1, 2]
        .into_iter()
        .find(|uid| *uid != service_uid)
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    test_credential_bytes_for_client(client_uid, service_uid, adapter_seed, host_seed)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn test_credential_cbor(
    value: &ciborium::value::Value,
) -> Result<Vec<u8>, LocalForkAuthenticationErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    Ok(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        ffi::OsString,
        fs,
        os::unix::{
            ffi::OsStringExt as _,
            fs::PermissionsExt as _,
            net::{UnixListener, UnixStream},
        },
    };

    use super::*;
    use ciborium::value::Value;
    use pos_core::fork_authentication::{principal_digest_v1, ForkAuthenticationAdapterPolicyV1};

    fn test_ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
    }

    fn encode(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        test_ok(ciborium::into_writer(value, &mut bytes));
        bytes
    }

    fn current_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn mapped_uid() -> u32 {
        if current_uid() == 1 {
            2
        } else {
            1
        }
    }

    fn binding(uid: u32) -> LocalAccountBindingV1 {
        LocalAccountBindingV1 {
            uid,
            principal: test_ok(PrincipalRefV1::try_new([9; 16], "unix.test")),
            owner: OwnerIdV1::from_static("owner"),
        }
    }

    fn registry(uid: u32, service_uid: u32) -> LocalAccountRegistryV1 {
        test_ok(LocalAccountRegistryV1::new(
            "local-unix".to_owned(),
            2,
            vec![binding(uid)],
            service_uid,
        ))
    }

    fn credential_bytes_for_service(
        uid: u32,
        service_uid: u32,
        host_seed: [u8; 32],
    ) -> (Vec<u8>, Vec<u8>) {
        test_ok(test_credential_bytes_for_client(
            uid,
            service_uid,
            [7; 32],
            host_seed,
        ))
    }

    fn credential_bytes(uid: u32, host_seed: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        credential_bytes_for_service(uid, current_uid(), host_seed)
    }

    fn credentials_directory(auth: &[u8], host: &[u8]) -> tempfile::TempDir {
        let directory = test_ok(tempfile::tempdir());
        test_ok(fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o700),
        ));
        for (name, bytes) in [(AUTH_CREDENTIAL_NAME, auth), (HOST_CREDENTIAL_NAME, host)] {
            let path = directory.path().join(name);
            test_ok(fs::write(&path, bytes));
            test_ok(fs::set_permissions(path, fs::Permissions::from_mode(0o400)));
        }
        directory
    }

    fn expect_invalid<T>(result: Result<T, LocalForkAuthenticationErrorV1>) {
        assert_eq!(
            result.err(),
            Some(LocalForkAuthenticationErrorV1::CredentialInvalid)
        );
    }

    fn expect_unavailable<T>(result: Result<T, LocalForkAuthenticationErrorV1>) {
        assert_eq!(
            result.err(),
            Some(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
    }

    fn open_directory(path: &Path) -> File {
        test_ok(fs::set_permissions(path, fs::Permissions::from_mode(0o700)));
        test_ok(open_credential_directory(path, current_uid()))
    }

    fn load_error(
        auth: &[u8],
        host: &[u8],
        service_uid: u32,
    ) -> Option<LocalForkAuthenticationErrorV1> {
        let directory = credentials_directory(auth, host);
        LocalForkAuthenticationCredentialsV1::load(directory.path(), service_uid).err()
    }

    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    /// Replace one FACR1 field per labelled case and require a fail-closed load.
    fn expect_field_cases_invalid(
        auth: &[u8],
        host: &[u8],
        service_uid: u32,
        cases: impl IntoIterator<Item = (&'static str, usize, Value)>,
    ) {
        for (label, index, value) in cases {
            let mut fields = test_ok(facr1_fields(auth));
            fields[index] = value;
            assert_eq!(
                load_error(&encode(&Value::Array(fields)), host, service_uid),
                Some(LocalForkAuthenticationErrorV1::CredentialInvalid),
                "{label}"
            );
        }
    }

    fn expect_load_invalid(auth: &[u8], host: &[u8], service_uid: u32) {
        let directory = credentials_directory(auth, host);
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            service_uid,
        ));
    }

    fn facr1_fields(bytes: &[u8]) -> Result<Vec<Value>, &'static str> {
        let value: Value = test_ok(ciborium::from_reader(bytes));
        let Value::Array(fields) = value else {
            return Err("credential fixture must be an array");
        };
        Ok(fields)
    }

    #[test]
    fn pathname_unix_listener_rejects_service_peer_and_resolves_trusted_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let uid = mapped_uid();
        let (auth, host) = credential_bytes_for_service(uid, current_uid(), [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials =
            LocalForkAuthenticationCredentialsV1::load(directory.path(), current_uid())?;
        assert_eq!(
            credentials
                .policy()
                .adapter("local-unix")
                .map(|entry| entry.minimum_assurance),
            Some(2)
        );
        assert_ne!(credentials.adapter_public_key(), [0; 32]);
        let socket_path = directory.path().join("fork-admission.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let connector = std::thread::spawn(move || UnixStream::connect(socket_path));
        let (server, _) = listener.accept()?;
        let client = connector
            .join()
            .map_err(|_| std::io::Error::other("Unix client thread panicked"))??;
        assert!(matches!(
            credentials.authenticate_peer(&server),
            Err(LocalForkAuthenticationErrorV1::PeerUnauthenticated)
        ));
        let peer = AuthenticatedUnixPeerV1 {
            principal: binding(uid).principal,
        };
        assert_eq!(peer.principal.trust_domain(), "unix.test");
        let evidence = credentials.produce(peer)?;
        let resolved = credentials.resolve(evidence)?;
        assert_eq!(resolved.owner(), OwnerIdV1::from_static("owner"));
        let record = resolved.verified_evidence().evidence().record();
        assert_eq!(record.adapter_id, "local-unix");
        assert_eq!(record.assurance, 2);
        assert!(record.issued_at < record.expires_at);
        assert_ne!(record.operation_nonce, [0; 32]);
        drop(client);
        Ok(())
    }

    #[test]
    fn loader_rejects_swapped_extra_equal_and_noncanonical_credentials() {
        let uid = mapped_uid();
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&host, &auth);
        assert!(matches!(
            LocalForkAuthenticationCredentialsV1::load(directory.path(), current_uid()),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        ));

        let directory = credentials_directory(&auth, &host);
        test_ok(fs::write(directory.path().join("unexpected"), [1]));
        assert!(matches!(
            LocalForkAuthenticationCredentialsV1::load(directory.path(), current_uid()),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        ));

        let (auth, host) = credential_bytes(uid, [7; 32]);
        let directory = credentials_directory(&auth, &host);
        assert!(matches!(
            LocalForkAuthenticationCredentialsV1::load(directory.path(), current_uid()),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        ));

        // Exactly 42 bytes, so it passes the length gate: the version uses a
        // non-shortest `0x18 0x01` uint, compensated by a 31-byte seed.
        let mut noncanonical = vec![
            0x83, 0x65, b'F', b'A', b'H', b'K', b'1', 0x18, 0x01, 0x58, 0x1f,
        ];
        noncanonical.extend_from_slice(&[8; 31]);
        assert_eq!(noncanonical.len(), FAHK1_BYTES);
        expect_load_invalid(&auth, &noncanonical, current_uid());
    }

    #[test]
    fn loader_accepts_literal_fahk1_vector_and_rejects_adjacent_lengths() {
        // ADR-107: array(3) header, text(5) "FAHK1", uint 1, bstr(32) seed.
        let mut literal = vec![0x83, 0x65, b'F', b'A', b'H', b'K', b'1', 0x01, 0x58, 0x20];
        literal.extend_from_slice(&[8; 32]);
        assert_eq!(literal.len(), 42);
        let (auth, encoded) = credential_bytes(mapped_uid(), [8; 32]);
        assert_eq!(literal, encoded);
        let directory = credentials_directory(&auth, &literal);
        let credentials = test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            current_uid(),
        ));
        let initialize = initialize_challenge(host_signer().public_key());
        assert_eq!(
            test_ok(credentials.sign_initialize(&initialize)),
            test_ok(host_signer().sign_initialize(&test_ok(initialize.to_canonical_cbor())))
        );

        expect_load_invalid(&auth, &literal[..41], current_uid());
        let mut extended = literal;
        extended.push(0);
        expect_load_invalid(&auth, &extended, current_uid());
    }

    #[test]
    fn loader_accepts_separate_valid_credentials() {
        let uid = mapped_uid();
        let (auth, host) = credential_bytes_for_service(uid, current_uid(), [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials = test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            current_uid(),
        ));

        assert_eq!(
            credentials
                .policy()
                .adapter("local-unix")
                .map(|adapter| adapter.minimum_assurance),
            Some(2)
        );
        assert_ne!(credentials.adapter_public_key(), [0; 32]);
    }

    #[test]
    fn resolver_rejects_policy_and_exact_registry_mismatches() {
        let uid = mapped_uid();
        let (auth, host) = credential_bytes_for_service(uid, current_uid(), [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials = test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            current_uid(),
        ));
        let registry_binding = test_ok(credentials.resolver.registry().digest());

        let policy_mismatch = AuthenticatedPrincipalRecordV1 {
            principal: binding(uid).principal,
            adapter_id: "other-adapter".to_owned(),
            assurance: 2,
            issued_at: 1,
            expires_at: 2,
            registry_binding,
            operation_nonce: [1; 32],
        };
        let evidence = test_ok(
            credentials
                .adapter_signer
                .sign_authenticated_principal(policy_mismatch),
        );
        expect_invalid(credentials.resolve(ProducedLocalAuthenticationEvidenceV1(evidence)));

        let unknown_principal = AuthenticatedPrincipalRecordV1 {
            principal: test_ok(PrincipalRefV1::try_new([8; 16], "unix.test")),
            adapter_id: "local-unix".to_owned(),
            assurance: 2,
            issued_at: 1,
            expires_at: 2,
            registry_binding,
            operation_nonce: [1; 32],
        };
        let evidence = test_ok(
            credentials
                .adapter_signer
                .sign_authenticated_principal(unknown_principal),
        );
        assert!(matches!(
            credentials.resolve(ProducedLocalAuthenticationEvidenceV1(evidence)),
            Err(LocalForkAuthenticationErrorV1::PeerUnauthenticated)
        ));

        let registry_mismatch = AuthenticatedPrincipalRecordV1 {
            principal: binding(uid).principal,
            adapter_id: "local-unix".to_owned(),
            assurance: 3,
            issued_at: 1,
            expires_at: 2,
            registry_binding,
            operation_nonce: [1; 32],
        };
        let evidence = test_ok(
            credentials
                .adapter_signer
                .sign_authenticated_principal(registry_mismatch),
        );
        expect_invalid(credentials.resolve(ProducedLocalAuthenticationEvidenceV1(evidence)));
    }

    fn loaded_credentials() -> LocalForkAuthenticationCredentialsV1 {
        let (auth, host) = credential_bytes(mapped_uid(), [8; 32]);
        let directory = credentials_directory(&auth, &host);
        test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            current_uid(),
        ))
    }

    fn resolved_authentication(
        credentials: &LocalForkAuthenticationCredentialsV1,
    ) -> ResolvedLocalAuthenticationV1 {
        let peer = AuthenticatedUnixPeerV1 {
            principal: binding(mapped_uid()).principal,
        };
        let evidence = test_ok(credentials.produce_with(peer, || Ok(1), || Ok([1; 32])));
        test_ok(credentials.resolve(evidence))
    }

    fn host_signer() -> ForkHostSigningKeyV1 {
        test_ok(ForkHostSigningKeyV1::from_seed([8; 32]))
    }

    fn initialize_challenge(host_key: [u8; 32]) -> ForkAdmissionInitializeChallengeV1 {
        test_ok(ForkAdmissionInitializeChallengeV1::new(
            pos_core::Hash::from_bytes([1; 32]),
            pos_core::Hash::from_bytes([2; 32]),
            pos_core::PublicKey::from_bytes(host_key),
            pos_core::Hash::from_bytes([4; 32]),
        ))
    }

    #[test]
    fn protected_host_signer_accepts_only_typed_adr106_proofs() {
        let credentials = loaded_credentials();
        let signer = host_signer();
        let initialize = initialize_challenge(signer.public_key());
        assert_eq!(
            test_ok(credentials.sign_initialize(&initialize)),
            test_ok(signer.sign_initialize(&test_ok(initialize.to_canonical_cbor())))
        );
        // FAI1 is bound to the custody key; a challenge for another key is refused.
        let foreign = test_ok(ForkHostSigningKeyV1::from_seed([9; 32]));
        expect_invalid(credentials.sign_initialize(&initialize_challenge(foreign.public_key())));

        let open = test_ok(ForkAdmissionOpenChallengeV1::new(
            pos_core::Hash::from_bytes([1; 32]),
            pos_core::Hash::from_bytes([2; 32]),
            pos_core::Hash::from_bytes([3; 32]),
        ));
        assert_eq!(
            test_ok(credentials.sign_open(&open)),
            test_ok(signer.sign_open(&test_ok(open.to_canonical_cbor())))
        );

        let recovery_bytes = encode(&Value::Array(vec![
            Value::Text("FRC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(vec![1; 32]),
            Value::Bytes(vec![2; 32]),
            Value::Integer(1.into()),
            Value::Bytes(vec![3; 32]),
        ]));
        let recovery = test_ok(ForkAdmissionRecoveryCommandV1::from_canonical_cbor(
            &recovery_bytes,
        ));
        let proof = test_ok(credentials.sign_recovery(&recovery));
        assert_eq!(proof.command_bytes(), recovery_bytes);
        assert_eq!(
            proof.signature(),
            test_ok(signer.sign_recovery(&recovery_bytes))
        );
    }

    #[test]
    fn protected_host_signer_binds_commands_to_resolved_authentication() {
        let credentials = loaded_credentials();
        let signer = host_signer();
        let authentication = resolved_authentication(&credentials);
        let evidence = authentication.verified_evidence();
        let evidence_digest = test_ok(evidence.evidence().digest());
        let principal_digest =
            test_ok(principal_digest_v1(&evidence.evidence().record().principal));
        let poc1 = |owner: &str| {
            encode(&Value::Array(vec![
                Value::Text("POC1".to_owned()),
                Value::Integer(1.into()),
                Value::Bytes(vec![1; 32]),
                Value::Bytes(vec![2; 32]),
                Value::Bytes(vec![3; 32]),
                Value::Bytes(evidence_digest.as_bytes().to_vec()),
                Value::Bytes(principal_digest.as_bytes().to_vec()),
                Value::Text(owner.to_owned()),
            ]))
        };
        let principal_owner_bytes = poc1(authentication.owner().as_str());
        let principal_owner = test_ok(PrincipalOwnerCommandV1::from_canonical_cbor(
            &principal_owner_bytes,
        ));
        let host_command =
            test_ok(credentials.sign_principal_owner_command(&principal_owner, &authentication));
        assert_eq!(host_command.command_bytes(), principal_owner_bytes);
        assert_eq!(
            host_command.signature(),
            test_ok(signer.sign_command(&principal_owner_bytes, evidence))
        );

        let fork_bytes = encode(&Value::Array(vec![
            Value::Text("FCC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(vec![1; 32]),
            Value::Bytes(vec![2; 32]),
            Value::Bytes(vec![3; 32]),
            Value::Bytes(evidence_digest.as_bytes().to_vec()),
            Value::Bytes(principal_digest.as_bytes().to_vec()),
            Value::Bytes(vec![4; 16]),
            Value::Integer(5.into()),
            Value::Integer(5.into()),
            Value::Bytes(vec![6; 32]),
            Value::Bytes(vec![7; 32]),
            Value::Integer(1.into()),
            Value::Text("child".to_owned()),
        ]));
        let fork = test_ok(ForkCreateCommandV1::from_canonical_cbor(&fork_bytes));
        let host_command = test_ok(credentials.sign_fork_command(&fork, &authentication));
        assert_eq!(host_command.command_bytes(), fork_bytes);
        assert_eq!(
            host_command.signature(),
            test_ok(signer.sign_command(&fork_bytes, evidence))
        );

        let wrong_owner = test_ok(PrincipalOwnerCommandV1::from_canonical_cbor(&poc1(
            "other-owner",
        )));
        expect_invalid(credentials.sign_principal_owner_command(&wrong_owner, &authentication));
    }

    #[test]
    fn resolver_rejects_foreign_adapter_key_and_altered_signature() {
        let uid = mapped_uid();
        let credentials = loaded_credentials();
        let record = AuthenticatedPrincipalRecordV1 {
            principal: binding(uid).principal,
            adapter_id: "local-unix".to_owned(),
            assurance: 2,
            issued_at: 1,
            expires_at: 2,
            registry_binding: test_ok(credentials.resolver.registry().digest()),
            operation_nonce: [1; 32],
        };

        let foreign_adapter = test_ok(ForkAuthenticationAdapterSigningKeyV1::from_seed([9; 32]));
        let foreign = test_ok(foreign_adapter.sign_authenticated_principal(record.clone()));
        expect_invalid(credentials.resolve(ProducedLocalAuthenticationEvidenceV1(foreign)));

        let genuine = test_ok(
            credentials
                .adapter_signer
                .sign_authenticated_principal(record.clone()),
        );
        let mut signature = *genuine.signature();
        signature[0] ^= 0x01;
        let altered = test_ok(AuthenticatedPrincipalEvidenceV1::new(record, signature));
        assert_eq!(
            test_ok(credentials.resolve(ProducedLocalAuthenticationEvidenceV1(genuine))).owner(),
            OwnerIdV1::from_static("owner")
        );
        expect_invalid(credentials.resolve(ProducedLocalAuthenticationEvidenceV1(altered)));
    }

    #[test]
    fn equal_derived_signing_keys_fail_closed() {
        expect_invalid(ensure_distinct_signing_keys([1; 32], [1; 32]));
    }

    #[test]
    fn producer_fails_closed_for_clock_overflow_and_entropy_faults() {
        let uid = mapped_uid();
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials = test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            current_uid(),
        ));

        expect_unavailable(credentials.produce_with(
            AuthenticatedUnixPeerV1 {
                principal: binding(uid).principal,
            },
            || Err(LocalForkAuthenticationErrorV1::CredentialUnavailable),
            operation_nonce,
        ));
        expect_unavailable(credentials.produce_with(
            AuthenticatedUnixPeerV1 {
                principal: binding(uid).principal,
            },
            || Ok(u64::MAX),
            operation_nonce,
        ));
        expect_unavailable(credentials.produce_with(
            AuthenticatedUnixPeerV1 {
                principal: binding(uid).principal,
            },
            || Ok(1),
            || Err(LocalForkAuthenticationErrorV1::CredentialUnavailable),
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn principal_owner_command_is_bound_to_the_resolved_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let credentials = test_credentials_for_current_peer()?;
        let (_client, server) = UnixStream::pair()?;
        let authentication =
            credentials.resolve(credentials.produce(credentials.authenticate_peer(&server)?)?)?;
        let command = |owner: &str| {
            PrincipalOwnerCommandV1::from_canonical_cbor(&encode(&Value::Array(vec![
                Value::Text("POC1".to_owned()),
                Value::Integer(1.into()),
                Value::Bytes(vec![1; 32]),
                Value::Bytes(vec![2; 32]),
                Value::Bytes(vec![3; 32]),
                Value::Bytes(vec![4; 32]),
                Value::Bytes(vec![5; 32]),
                Value::Text(owner.to_owned()),
            ])))
        };

        let substituted = command("other-owner")?;
        assert_eq!(
            credentials.sign_principal_owner_command(&substituted, &authentication),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        );
        Ok(())
    }

    #[test]
    fn peer_without_a_registry_mapping_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (auth, host) = credential_bytes(mapped_uid(), [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials =
            LocalForkAuthenticationCredentialsV1::load(directory.path(), current_uid())?;
        let (peer, _other) = UnixStream::pair()?;
        assert!(matches!(
            credentials.authenticate_peer(&peer),
            Err(LocalForkAuthenticationErrorV1::PeerUnauthenticated)
        ));
        Ok(())
    }

    #[test]
    fn credential_filesystem_and_read_faults_fail_closed() {
        let uid = mapped_uid();
        let owner_uid = current_uid();
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);

        expect_invalid(open_credential_directory(directory.path(), owner_uid ^ 1));
        expect_invalid(read_credential(
            &open_directory(directory.path()),
            AUTH_CREDENTIAL_NAME,
            owner_uid ^ 1,
        ));

        expect_unavailable(LocalForkAuthenticationCredentialsV1::load(
            Path::new("relative"),
            owner_uid,
        ));
        expect_unavailable(LocalForkAuthenticationCredentialsV1::load(
            directory.path().join("missing").as_path(),
            owner_uid,
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path().join(AUTH_CREDENTIAL_NAME).as_path(),
            owner_uid,
        ));
        test_ok(fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o722),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            owner_uid,
        ));
        test_ok(fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o755),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            owner_uid,
        ));
        test_ok(fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o700),
        ));
        test_ok(fs::set_permissions(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o444),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            owner_uid,
        ));
        test_ok(fs::set_permissions(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o400),
        ));
        test_ok(fs::set_permissions(
            directory.path().join(HOST_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o644),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            owner_uid,
        ));
        test_ok(fs::set_permissions(
            directory.path().join(HOST_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o600),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            owner_uid,
        ));
        test_ok(fs::set_permissions(
            directory.path().join(HOST_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o620),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            owner_uid,
        ));

        test_ok(fs::set_permissions(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o620),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            owner_uid,
        ));
    }

    #[test]
    fn oversized_credential_file_fails_closed() {
        let (auth, host) = credential_bytes(mapped_uid(), [8; 32]);
        let directory = credentials_directory(&auth, &host);
        test_ok(fs::set_permissions(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o600),
        ));
        test_ok(fs::set_permissions(
            directory.path().join(HOST_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o400),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            current_uid(),
        ));
        test_ok(fs::write(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            vec![1; MAX_FORK_AUTH_CREDENTIAL_BYTES_V1 + 1],
        ));
        test_ok(fs::set_permissions(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o400),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            current_uid(),
        ));
    }

    #[test]
    fn credential_directory_and_file_name_faults_fail_closed() {
        let directory = test_ok(tempfile::tempdir());
        let opened = open_directory(directory.path());
        expect_unavailable(credential_names(&opened));
        expect_unavailable(read_credential(
            &opened,
            AUTH_CREDENTIAL_NAME,
            current_uid(),
        ));

        let auth_path = directory.path().join(AUTH_CREDENTIAL_NAME);
        test_ok(fs::write(&auth_path, []));
        expect_unavailable(credential_names(&opened));
        test_ok(fs::remove_file(auth_path));

        let host_path = directory.path().join(HOST_CREDENTIAL_NAME);
        test_ok(fs::write(&host_path, []));
        expect_unavailable(credential_names(&opened));
        test_ok(fs::remove_file(host_path));

        test_ok(fs::write(
            directory.path().join(OsString::from_vec(vec![0xff])),
            [],
        ));
        expect_invalid(credential_names(&opened));
    }

    #[test]
    fn fifo_credential_fails_closed_without_blocking() {
        let (auth, host) = credential_bytes(mapped_uid(), [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let auth_path = directory.path().join(AUTH_CREDENTIAL_NAME);
        test_ok(fs::remove_file(&auth_path));
        test_ok(rustix::fs::mknodat(
            rustix::fs::CWD,
            auth_path.as_path(),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o400),
            0,
        ));
        let path = directory.path().to_path_buf();
        let service_uid = current_uid();
        let (sender, receiver) = std::sync::mpsc::channel();
        let _loader = std::thread::spawn(move || {
            sender.send(LocalForkAuthenticationCredentialsV1::load(&path, service_uid).err())
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(Some(LocalForkAuthenticationErrorV1::CredentialInvalid))
        );
    }

    #[test]
    fn deterministic_credential_io_and_randomness_faults_fail_closed() {
        struct FailingReader;

        struct FailingWriter;

        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("read fault"))
            }
        }

        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("write fault"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut short = &b"short"[..];
        expect_invalid(finish_credential_read(&mut short, 6));
        let grown = vec![0; MAX_FORK_AUTH_CREDENTIAL_BYTES_V1 + 100];
        let mut grown = grown.as_slice();
        expect_invalid(finish_credential_read(&mut grown, 1));
        assert_eq!(grown.len(), 99);
        let mut failing = FailingReader;
        assert_eq!(
            finish_credential_read(&mut failing, 1),
            Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        expect_invalid(write_canonical_array(
            &[Value::Integer(1.into())],
            &mut FailingWriter,
        ));
        assert_eq!(
            wall_time_from_duration(Err(())),
            Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        assert_eq!(
            wall_time_from_duration(Ok(std::time::Duration::new(u64::MAX, 0))),
            Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        assert_eq!(
            operation_nonce_with(|_| Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)),
            Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        assert_eq!(
            operation_nonce_with(|_| Ok(0)),
            Err(LocalForkAuthenticationErrorV1::CredentialUnavailable)
        );
        assert_ne!(test_ok(operation_nonce()), [0; 32]);
        let mut fills = 0_u8;
        assert_eq!(
            operation_nonce_with(|bytes| {
                fills = fills.saturating_add(1);
                bytes.fill(u8::from(fills != 1));
                Ok(bytes.len())
            }),
            Ok([1; 32])
        );
    }

    #[test]
    fn malformed_credential_fields_fail_closed() {
        let uid = mapped_uid();
        let service_uid = current_uid();
        let (auth, host) = credential_bytes(uid, [8; 32]);
        expect_load_invalid(&[0; 2], &host, service_uid);
        expect_load_invalid(&auth, &[0; FAHK1_BYTES], service_uid);
        let mut noncanonical = auth.clone();
        noncanonical[0] = 0x98;
        noncanonical.insert(1, 7);
        expect_load_invalid(&noncanonical, &host, service_uid);
        let mut fields = test_ok(facr1_fields(&auth));
        fields[0] = Value::Text("wrong-marker".to_owned());
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);
        let mut fields = test_ok(facr1_fields(&auth));
        fields[6] = Value::Array(vec![Value::Array(vec![
            Value::Integer(0.into()),
            Value::Bytes(vec![1]),
            Value::Text("owner".to_owned()),
        ])]);
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);
    }

    #[test]
    fn credential_policy_and_registry_mismatches_fail_closed() {
        let uid = mapped_uid();
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let service_uid = current_uid();
        expect_invalid(parse_credentials(&auth, &host, uid));

        let registry = registry(uid, service_uid);
        let wrong_signer = test_ok(ForkAuthenticationAdapterSigningKeyV1::from_seed([9; 32]));
        let wrong_policy = test_ok(ForkAuthenticationPolicyV1::new(vec![
            ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "local-unix".to_owned(),
                verifying_key: wrong_signer.public_key(),
                minimum_assurance: 2,
                registry_bindings: vec![test_ok(registry.digest())],
            },
        ]));
        let adapter = test_ok(ForkAuthenticationAdapterSigningKeyV1::from_seed([7; 32]));
        let strict_policy = test_ok(ForkAuthenticationPolicyV1::new(vec![
            ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "local-unix".to_owned(),
                verifying_key: adapter.public_key(),
                minimum_assurance: 3,
                registry_bindings: vec![test_ok(registry.digest())],
            },
        ]));
        expect_field_cases_invalid(
            &auth,
            &host,
            service_uid,
            [
                ("zero seed", 2, Value::Bytes(vec![0; 32])),
                ("text seed", 2, text("not-a-seed")),
                (
                    "foreign adapter key",
                    3,
                    Value::Bytes(test_ok(wrong_policy.to_canonical_cbor())),
                ),
                (
                    "assurance below policy",
                    3,
                    Value::Bytes(test_ok(strict_policy.to_canonical_cbor())),
                ),
                ("undecodable policy", 3, Value::Bytes(vec![1])),
                ("text policy", 3, text("not-policy-bytes")),
                ("adapter absent from policy", 4, text("missing-adapter")),
                ("integer adapter id", 4, Value::Integer(1.into())),
                ("text assurance", 5, text("not-an-assurance")),
                ("integer registry", 6, Value::Integer(1.into())),
            ],
        );
    }

    #[test]
    fn malformed_registry_rows_fail_closed() {
        let uid = mapped_uid();
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let principal = Value::Bytes(test_ok(binding(uid).principal.encode()).as_slice().to_vec());
        let row = |uid_field: Value, principal_field: Value, owner_field: Value| {
            Value::Array(vec![Value::Array(vec![
                uid_field,
                principal_field,
                owner_field,
            ])])
        };
        let mapped = || Value::Integer(uid.into());
        expect_field_cases_invalid(
            &auth,
            &host,
            current_uid(),
            [
                (
                    "non-array binding",
                    6,
                    Value::Array(vec![Value::Integer(1.into())]),
                ),
                (
                    "unbound owner",
                    6,
                    row(mapped(), principal.clone(), text("another-owner")),
                ),
                (
                    "text uid",
                    6,
                    row(text("not-a-uid"), principal.clone(), text("owner")),
                ),
                (
                    "text principal",
                    6,
                    row(mapped(), text("not-a-principal"), text("owner")),
                ),
                (
                    "undecodable principal",
                    6,
                    row(mapped(), Value::Bytes(vec![1]), text("owner")),
                ),
                (
                    "integer owner",
                    6,
                    row(mapped(), principal, Value::Integer(1.into())),
                ),
            ],
        );
    }

    #[test]
    fn malformed_credential_encodings_fail_closed() {
        let (auth, host) = credential_bytes(mapped_uid(), [8; 32]);
        let encoding_cases = [
            ("trailing byte", [auth.as_slice(), &[0]].concat()),
            ("truncated CBOR", vec![0xff]),
            (
                "tagged top-level value",
                encode(&Value::Tag(0, Box::new(Value::Bytes(vec![1])))),
            ),
            (
                "map with tagged key",
                encode(&Value::Map(vec![(
                    Value::Tag(0, Box::new(Value::Bytes(vec![2]))),
                    Value::Bytes(vec![3]),
                )])),
            ),
        ];
        for (label, bytes) in encoding_cases {
            assert_eq!(
                load_error(&bytes, &host, current_uid()),
                Some(LocalForkAuthenticationErrorV1::CredentialInvalid),
                "{label}"
            );
        }
    }
}
