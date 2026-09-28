//! Host-private Linux credential and peer-identity boundary for ADR-107.
//!
//! It produces FAE1 only from a kernel-authenticated Unix peer and resolves
//! the Owner only through the same protected FACR1 registry. #450 owns all
//! listener, FAH1, session, command, and durable-authority orchestration.

#![expect(
    clippy::redundant_pub_crate,
    reason = "these types must be reachable by the crate-private #450 host, while the credential module remains private to this crate"
)]

use std::{
    fs::{self, OpenOptions},
    io::{Cursor, Read},
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
        AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
        ForkAuthenticationPolicyV1, LocalAccountBindingV1, LocalAccountRegistryV1,
        MAX_FORK_AUTH_CREDENTIAL_BYTES_V1,
    },
    CanonicalBytes, OwnerIdV1, PrincipalRefV1,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, ForkAuthenticationAdapterSigningKeyV1,
    ForkAuthenticationSignatureErrorV1, ForkHostSigningKeyV1,
    VerifiedAuthenticatedPrincipalEvidenceV1,
};
use rustix::net::sockopt::socket_peercred;
use rustix::rand::{getrandom, GetRandomFlags};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const AUTH_CREDENTIAL_NAME: &str = "pigloros.fork-admission-auth";
const HOST_CREDENTIAL_NAME: &str = "pigloros.fork-admission-host-signer";
const FAHK1_BYTES: usize = 42;
const CREDENTIAL_DIRECTORY_MODE: u32 = 0o022;
const AUTHENTICATION_LIFETIME_MICROS: u64 = 30_000_000;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum LocalForkAuthenticationErrorV1 {
    #[error("fork admission credential unavailable")]
    CredentialUnavailable,
    #[error("fork admission credential invalid")]
    CredentialInvalid,
    #[error("fork admission peer is not authenticated")]
    PeerUnauthenticated,
}

/// Loaded, purpose-separated authority inputs retained only by the host.
pub(crate) struct LocalForkAuthenticationCredentialsV1 {
    resolver: PrincipalOwnerResolverV1,
    adapter_signer: ForkAuthenticationAdapterSigningKeyV1,
    _host_signer: LocalForkHostSignerV1,
}

impl LocalForkAuthenticationCredentialsV1 {
    /// Load exactly the two systemd credential names from one protected directory.
    pub(crate) fn load(
        directory: &Path,
        service_uid: u32,
    ) -> Result<Self, LocalForkAuthenticationErrorV1> {
        validate_credential_directory(directory)?;
        credential_names(directory)?;
        let auth_bytes = Zeroizing::new(read_credential(directory, AUTH_CREDENTIAL_NAME)?);
        let host_bytes = Zeroizing::new(read_credential(directory, HOST_CREDENTIAL_NAME)?);
        parse_credentials(&auth_bytes, &host_bytes, service_uid)
    }

    #[must_use]
    pub(crate) const fn policy(&self) -> &ForkAuthenticationPolicyV1 {
        self.resolver.policy()
    }

    #[must_use]
    pub(crate) const fn adapter_public_key(&self) -> [u8; 32] {
        self.adapter_signer.public_key()
    }

    /// Authenticate a connected pathname Unix peer by its kernel UID only.
    pub(crate) fn authenticate_peer(
        &self,
        stream: &UnixStream,
    ) -> Result<AuthenticatedUnixPeerV1, LocalForkAuthenticationErrorV1> {
        let uid = socket_peercred(stream.as_fd())
            .map_err(|_| LocalForkAuthenticationErrorV1::PeerUnauthenticated)?
            .uid
            .as_raw();
        let binding = self
            .resolver
            .registry()
            .lookup_uid(uid)
            .ok_or(LocalForkAuthenticationErrorV1::PeerUnauthenticated)?;
        Ok(AuthenticatedUnixPeerV1 {
            principal: binding.principal.clone(),
        })
    }

    /// Produce one opaque FAE1 from an internally authenticated Unix peer.
    pub(crate) fn produce(
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
            .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)?;
        let registry_binding = self
            .resolver
            .registry()
            .digest()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
        let record = AuthenticatedPrincipalRecordV1 {
            principal: peer.principal,
            adapter_id: self.resolver.registry().adapter_id().to_owned(),
            assurance: self.resolver.registry().assurance(),
            issued_at,
            expires_at,
            registry_binding,
            operation_nonce: nonce()?,
        };
        self.adapter_signer
            .sign_authenticated_principal(record)
            .map(ProducedLocalAuthenticationEvidenceV1)
            .map_err(signature_invalid)
    }

    /// Verify locally produced FAE1 and resolve its Owner from FACR1 only.
    pub(crate) fn resolve(
        &self,
        evidence: ProducedLocalAuthenticationEvidenceV1,
    ) -> Result<ResolvedLocalAuthenticationV1, LocalForkAuthenticationErrorV1> {
        self.resolver.resolve(evidence.0)
    }
}

/// Host-private Principal-to-Owner resolver over the protected FACR1 registry.
pub(crate) struct PrincipalOwnerResolverV1 {
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
        let verified = verify_authenticated_principal_evidence_v1(&self.policy, evidence)
            .map_err(signature_invalid)?;
        let record = verified.evidence().record();
        let registry_binding = self
            .registry
            .digest()
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
        if record.adapter_id != self.registry.adapter_id()
            || record.assurance != self.registry.assurance()
            || record.registry_binding != registry_binding
        {
            return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
        }
        let owner = self
            .registry
            .lookup_principal(&record.principal)
            .ok_or(LocalForkAuthenticationErrorV1::PeerUnauthenticated)?;
        Ok(ResolvedLocalAuthenticationV1 { verified, owner })
    }
}

/// Opaque host-signing custody.
///
/// #450 adds the crate-private methods that accept its typed host-derived
/// commands. The raw purpose-limited signer never crosses this boundary.
pub(crate) struct LocalForkHostSignerV1 {
    _signer: ForkHostSigningKeyV1,
}

/// Non-cloneable result of one kernel-authenticated Unix connection.
pub(crate) struct AuthenticatedUnixPeerV1 {
    principal: PrincipalRefV1,
}

impl AuthenticatedUnixPeerV1 {
    #[must_use]
    pub(crate) const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }
}

/// Opaque evidence created only from a kernel-authenticated Unix peer.
pub(crate) struct ProducedLocalAuthenticationEvidenceV1(AuthenticatedPrincipalEvidenceV1);

/// Verified local FAE1 together with the Owner resolved from the same FACR1 row.
pub(crate) struct ResolvedLocalAuthenticationV1 {
    verified: VerifiedAuthenticatedPrincipalEvidenceV1,
    owner: OwnerIdV1,
}

impl ResolvedLocalAuthenticationV1 {
    #[must_use]
    pub(crate) const fn owner(&self) -> OwnerIdV1 {
        self.owner
    }

    pub(crate) const fn verified_evidence(&self) -> &VerifiedAuthenticatedPrincipalEvidenceV1 {
        &self.verified
    }
}

fn parse_credentials(
    auth_bytes: &[u8],
    host_bytes: &[u8],
    service_uid: u32,
) -> Result<LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1> {
    let (adapter_seed, policy, registry) = parse_facr1(auth_bytes, service_uid)?;
    let host_seed = parse_fahk1(host_bytes)?;
    if adapter_seed[..] == host_seed[..] {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    // `from_seed` zeroizes its by-value seed copy. These guards retain the
    // extracted credential bytes across every fallible validation step.
    let adapter_signer = ForkAuthenticationAdapterSigningKeyV1::from_seed(*adapter_seed)
        .map_err(signature_invalid)?;
    let adapter = policy
        .adapter(registry.adapter_id())
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let registry_binding = registry
        .digest()
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    if adapter.verifying_key != adapter_signer.public_key()
        || registry.assurance() < adapter.minimum_assurance
        || !adapter.registry_bindings.contains(&registry_binding)
    {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let host_signer = ForkHostSigningKeyV1::from_seed(*host_seed).map_err(signature_invalid)?;
    ensure_distinct_signing_keys(adapter_signer.public_key(), host_signer.public_key())?;
    Ok(LocalForkAuthenticationCredentialsV1 {
        resolver: PrincipalOwnerResolverV1::new(policy, registry),
        adapter_signer,
        _host_signer: LocalForkHostSignerV1 {
            _signer: host_signer,
        },
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
    let policy_bytes = bounded_bytes(&fields[3], 37_528)?;
    let policy = ForkAuthenticationPolicyV1::from_canonical_cbor(policy_bytes)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let adapter_id = bounded_text(&fields[4])?;
    let assurance = positive_u8(&fields[5])?;
    let entries = nonempty_array(&fields[6], 64)?;
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
    let principal_bytes = bounded_bytes(&fields[1], 256)?;
    let principal = PrincipalRefV1::decode(&CanonicalBytes::from_vec(principal_bytes.to_vec()))
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let owner = OwnerIdV1::new(bounded_text(&fields[2])?)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    Ok(LocalAccountBindingV1 {
        uid,
        principal,
        owner,
    })
}

fn validate_credential_directory(directory: &Path) -> Result<(), LocalForkAuthenticationErrorV1> {
    if !directory.is_absolute() {
        return Err(LocalForkAuthenticationErrorV1::CredentialUnavailable);
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
    if !metadata.is_dir() || metadata.mode() & CREDENTIAL_DIRECTORY_MODE != 0 {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    Ok(())
}

fn credential_names(directory: &Path) -> Result<(), LocalForkAuthenticationErrorV1> {
    let mut names = fs::read_dir(directory)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?
        .map(|entry| entry.map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable))
        .map(|entry| {
            entry.and_then(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_unstable();
    match names.as_slice() {
        [auth, host] if auth == AUTH_CREDENTIAL_NAME && host == HOST_CREDENTIAL_NAME => Ok(()),
        _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
    }
}

fn read_credential(
    directory: &Path,
    name: &str,
) -> Result<Vec<u8>, LocalForkAuthenticationErrorV1> {
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
    if !metadata.is_file() || metadata.mode() & CREDENTIAL_DIRECTORY_MODE != 0 {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let size = usize::try_from(metadata.len())
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    if size > MAX_FORK_AUTH_CREDENTIAL_BYTES_V1 {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    finish_credential_read(&mut file, size)
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
    let result = ciborium::into_writer(value.as_slice(), &mut *encoded);
    assert!(
        result.is_ok(),
        "writing canonical CBOR to a Vec cannot fail"
    );
    if encoded.as_slice() != bytes {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    Ok(value)
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
        Value::Text(text) if !text.is_empty() && text.len() <= 128 && !text.contains('\0') => {
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        ffi::OsString,
        fs,
        os::unix::{ffi::OsStringExt as _, fs::PermissionsExt as _, net::UnixStream},
    };

    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixListener;

    use super::*;
    use ciborium::value::Value;
    use pos_core::fork_authentication::ForkAuthenticationAdapterPolicyV1;

    fn test_ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
    }

    fn encode(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        test_ok(ciborium::into_writer(value, &mut bytes));
        bytes
    }

    fn current_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn binding(uid: u32) -> LocalAccountBindingV1 {
        LocalAccountBindingV1 {
            uid,
            principal: test_ok(PrincipalRefV1::try_new([9; 16], "unix.test")),
            owner: OwnerIdV1::from_static("owner"),
        }
    }

    fn registry(uid: u32) -> LocalAccountRegistryV1 {
        test_ok(LocalAccountRegistryV1::new(
            "local-unix".to_owned(),
            2,
            vec![binding(uid)],
            uid.saturating_add(1),
        ))
    }

    fn credential_bytes(uid: u32, host_seed: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let adapter_seed = [7; 32];
        let registry = registry(uid);
        let adapter = test_ok(ForkAuthenticationAdapterSigningKeyV1::from_seed(
            adapter_seed,
        ));
        let policy = test_ok(ForkAuthenticationPolicyV1::new(vec![
            ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "local-unix".to_owned(),
                verifying_key: adapter.public_key(),
                minimum_assurance: 2,
                registry_bindings: vec![test_ok(registry.digest())],
            },
        ]));
        let principal = test_ok(binding(uid).principal.encode());
        let facr1 = encode(&Value::Array(vec![
            Value::Text("FACR1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(adapter_seed.to_vec()),
            Value::Bytes(test_ok(policy.to_canonical_cbor())),
            Value::Text("local-unix".to_owned()),
            Value::Integer(2.into()),
            Value::Array(vec![Value::Array(vec![
                Value::Integer(uid.into()),
                Value::Bytes(principal.as_slice().to_vec()),
                Value::Text("owner".to_owned()),
            ])]),
        ]));
        let fahk1 = encode(&Value::Array(vec![
            Value::Text("FAHK1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(host_seed.to_vec()),
        ]));
        (facr1, fahk1)
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
    #[cfg(target_os = "linux")]
    fn pathname_unix_listener_authenticates_kernel_peer_and_resolves_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let uid = current_uid();
        if uid == 0 || uid == 65_534 {
            return Ok(());
        }
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials =
            LocalForkAuthenticationCredentialsV1::load(directory.path(), uid.saturating_add(1))?;
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
        let peer = credentials.authenticate_peer(&server)?;
        assert_eq!(peer.principal().trust_domain(), "unix.test");
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
        let uid = current_uid().max(1);
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&host, &auth);
        assert!(matches!(
            LocalForkAuthenticationCredentialsV1::load(directory.path(), uid.saturating_add(1)),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        ));

        let directory = credentials_directory(&auth, &host);
        test_ok(fs::write(directory.path().join("unexpected"), [1]));
        assert!(matches!(
            LocalForkAuthenticationCredentialsV1::load(directory.path(), uid.saturating_add(1)),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        ));

        let (auth, host) = credential_bytes(uid, [7; 32]);
        let directory = credentials_directory(&auth, &host);
        assert!(matches!(
            LocalForkAuthenticationCredentialsV1::load(directory.path(), uid.saturating_add(1)),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        ));

        let directory = credentials_directory(&auth, &[0x98, 0x03, b'F', b'A', b'H', b'K', b'1']);
        assert!(matches!(
            LocalForkAuthenticationCredentialsV1::load(directory.path(), uid.saturating_add(1)),
            Err(LocalForkAuthenticationErrorV1::CredentialInvalid)
        ));
    }

    #[test]
    fn loader_accepts_separate_valid_credentials() {
        let uid = current_uid().max(1);
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials = test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            uid.saturating_add(1),
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
        let uid = current_uid().max(1);
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials = test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            uid.saturating_add(1),
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

    #[test]
    fn equal_derived_signing_keys_fail_closed() {
        expect_invalid(ensure_distinct_signing_keys([1; 32], [1; 32]));
    }

    #[test]
    fn producer_fails_closed_for_clock_overflow_and_entropy_faults() {
        let uid = current_uid().max(1);
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials = test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            uid.saturating_add(1),
        ));

        expect_unavailable(credentials.produce_with(
            AuthenticatedUnixPeerV1 {
                principal: binding(uid).principal,
            },
            || Err(LocalForkAuthenticationErrorV1::CredentialUnavailable),
            operation_nonce,
        ));
        expect_invalid(credentials.produce_with(
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
    fn peer_without_a_registry_mapping_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let uid = current_uid();
        let mapped_uid = uid.saturating_add(1).max(1);
        if mapped_uid == 65_534 || mapped_uid == u32::MAX {
            return Ok(());
        }
        let (auth, host) = credential_bytes(mapped_uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials = LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            mapped_uid.saturating_add(1),
        )?;
        let (peer, _other) = UnixStream::pair()?;
        assert!(matches!(
            credentials.authenticate_peer(&peer),
            Err(LocalForkAuthenticationErrorV1::PeerUnauthenticated)
        ));
        Ok(())
    }

    #[test]
    fn credential_filesystem_and_read_faults_fail_closed() {
        let uid = current_uid().max(1);
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);

        expect_unavailable(LocalForkAuthenticationCredentialsV1::load(
            Path::new("relative"),
            uid,
        ));
        expect_unavailable(LocalForkAuthenticationCredentialsV1::load(
            Path::new("/tmp/pigloros-missing-credential-directory"),
            uid,
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path().join(AUTH_CREDENTIAL_NAME).as_path(),
            uid,
        ));
        test_ok(fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o722),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            uid,
        ));
        test_ok(fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o700),
        ));
        test_ok(fs::set_permissions(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o400),
        ));
        test_ok(fs::set_permissions(
            directory.path().join(HOST_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o620),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            uid,
        ));

        test_ok(fs::set_permissions(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o620),
        ));
        expect_invalid(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            uid,
        ));
        test_ok(fs::set_permissions(
            directory.path().join(AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o600),
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
            uid,
        ));
    }

    #[test]
    fn credential_directory_and_file_name_faults_fail_closed() {
        let directory = test_ok(tempfile::tempdir());
        expect_unavailable(credential_names(directory.path()));
        expect_unavailable(read_credential(directory.path(), AUTH_CREDENTIAL_NAME));

        test_ok(fs::write(
            directory.path().join(OsString::from_vec(vec![0xff])),
            [],
        ));
        expect_invalid(credential_names(directory.path()));
    }

    #[test]
    fn deterministic_credential_io_and_randomness_faults_fail_closed() {
        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("read fault"))
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
        let uid = current_uid().max(1);
        let service_uid = uid.saturating_add(1);
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
        let uid = current_uid().max(1);
        let (auth, host) = credential_bytes(uid, [8; 32]);
        let service_uid = uid.saturating_add(1);
        expect_load_invalid(&auth, &host, uid);

        let registry = registry(uid);
        let wrong_signer = test_ok(ForkAuthenticationAdapterSigningKeyV1::from_seed([9; 32]));
        let wrong_policy = test_ok(ForkAuthenticationPolicyV1::new(vec![
            ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "local-unix".to_owned(),
                verifying_key: wrong_signer.public_key(),
                minimum_assurance: 2,
                registry_bindings: vec![test_ok(registry.digest())],
            },
        ]));
        let mut fields = test_ok(facr1_fields(&auth));
        fields[3] = Value::Bytes(test_ok(wrong_policy.to_canonical_cbor()));
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let adapter = test_ok(ForkAuthenticationAdapterSigningKeyV1::from_seed([7; 32]));
        let strict_policy = test_ok(ForkAuthenticationPolicyV1::new(vec![
            ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "local-unix".to_owned(),
                verifying_key: adapter.public_key(),
                minimum_assurance: 3,
                registry_bindings: vec![test_ok(registry.digest())],
            },
        ]));
        let mut fields = test_ok(facr1_fields(&auth));
        fields[3] = Value::Bytes(test_ok(strict_policy.to_canonical_cbor()));
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[6] = Value::Array(vec![Value::Array(vec![
            Value::Integer(uid.into()),
            Value::Bytes(test_ok(binding(uid).principal.encode()).as_slice().to_vec()),
            Value::Text("another-owner".to_owned()),
        ])]);
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[3] = Value::Bytes(vec![1]);
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[4] = Value::Text("missing-adapter".to_owned());
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[6] = Value::Array(vec![Value::Integer(1.into())]);
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[2] = Value::Bytes(vec![0; 32]);
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut trailing = auth.clone();
        trailing.push(0);
        expect_load_invalid(&trailing, &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[2] = Value::Text("not-a-seed".to_owned());
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[3] = Value::Text("not-policy-bytes".to_owned());
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[4] = Value::Integer(1.into());
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[5] = Value::Text("not-an-assurance".to_owned());
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[6] = Value::Integer(1.into());
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[6] = Value::Array(vec![Value::Array(vec![
            Value::Text("not-a-uid".to_owned()),
            Value::Bytes(test_ok(binding(uid).principal.encode()).as_slice().to_vec()),
            Value::Text("owner".to_owned()),
        ])]);
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[6] = Value::Array(vec![Value::Array(vec![
            Value::Text("not-principal-bytes".to_owned()),
            Value::Text("not-a-principal".to_owned()),
            Value::Text("owner".to_owned()),
        ])]);
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        let mut fields = test_ok(facr1_fields(&auth));
        fields[6] = Value::Array(vec![Value::Array(vec![
            Value::Integer(uid.into()),
            Value::Bytes(vec![1]),
            Value::Text("owner".to_owned()),
        ])]);
        expect_load_invalid(&encode(&Value::Array(fields)), &host, service_uid);

        expect_load_invalid(&[0xff], &host, service_uid);

        let tagged_auth = encode(&Value::Tag(0, Box::new(Value::Bytes(vec![1]))));
        expect_load_invalid(&tagged_auth, &host, service_uid);
        let mapped_auth = encode(&Value::Map(vec![(
            Value::Tag(0, Box::new(Value::Bytes(vec![2]))),
            Value::Bytes(vec![3]),
        )]));
        expect_load_invalid(&mapped_auth, &host, service_uid);
    }
}
