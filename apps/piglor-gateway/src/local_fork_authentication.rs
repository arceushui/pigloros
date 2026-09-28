//! Host-private Linux credential and peer-identity boundary for ADR-107.
//!
//! This module deliberately stops before producing authentication evidence.
//! The evidence marker amendment remains pending; #450 owns all listener,
//! FAH1, session, command, and durable-authority orchestration.

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
        ForkAuthenticationPolicyV1, LocalAccountBindingV1, LocalAccountRegistryV1,
        MAX_FORK_AUTH_CREDENTIAL_BYTES_V1,
    },
    CanonicalBytes, OwnerIdV1, PrincipalRefV1,
};
use pos_crypto::fork_authentication::{
    ForkAuthenticationAdapterSigningKeyV1, ForkAuthenticationSignatureErrorV1, ForkHostSigningKeyV1,
};
use rustix::net::sockopt::socket_peercred;
use thiserror::Error;
use zeroize::Zeroize;

const AUTH_CREDENTIAL_NAME: &str = "pigloros.fork-admission-auth";
const HOST_CREDENTIAL_NAME: &str = "pigloros.fork-admission-host-signer";
const FAHK1_BYTES: usize = 42;
const CREDENTIAL_DIRECTORY_MODE: u32 = 0o022;

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
    policy: ForkAuthenticationPolicyV1,
    registry: LocalAccountRegistryV1,
    adapter_signer: ForkAuthenticationAdapterSigningKeyV1,
    host_signer: LocalForkHostSignerV1,
}

impl LocalForkAuthenticationCredentialsV1 {
    /// Load exactly the two systemd credential names from one protected directory.
    pub(crate) fn load(
        directory: &Path,
        service_uid: u32,
    ) -> Result<Self, LocalForkAuthenticationErrorV1> {
        validate_credential_directory(directory)?;
        credential_names(directory)?;
        let mut auth_bytes = read_credential(directory, AUTH_CREDENTIAL_NAME)?;
        let mut host_bytes = read_credential(directory, HOST_CREDENTIAL_NAME)?;
        let parsed = parse_credentials(&auth_bytes, &host_bytes, service_uid);
        auth_bytes.zeroize();
        host_bytes.zeroize();
        parsed
    }

    #[must_use]
    pub(crate) const fn policy(&self) -> &ForkAuthenticationPolicyV1 {
        &self.policy
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
            .registry
            .lookup_uid(uid)
            .ok_or(LocalForkAuthenticationErrorV1::PeerUnauthenticated)?;
        Ok(AuthenticatedUnixPeerV1 {
            principal: binding.principal.clone(),
            owner: binding.owner,
        })
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
    owner: OwnerIdV1,
}

impl AuthenticatedUnixPeerV1 {
    #[must_use]
    pub(crate) const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> OwnerIdV1 {
        self.owner
    }
}

fn parse_credentials(
    auth_bytes: &[u8],
    host_bytes: &[u8],
    service_uid: u32,
) -> Result<LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1> {
    let (mut adapter_seed, policy, registry) = parse_facr1(auth_bytes, service_uid)?;
    let mut host_seed = parse_fahk1(host_bytes)?;
    if adapter_seed == host_seed {
        adapter_seed.zeroize();
        host_seed.zeroize();
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let adapter_signer = ForkAuthenticationAdapterSigningKeyV1::from_seed(adapter_seed)
        .map_err(signature_invalid)?;
    adapter_seed.zeroize();
    let adapter = policy
        .adapter(registry.adapter_id())
        .ok_or(LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    if adapter.verifying_key != adapter_signer.public_key()
        || registry.assurance() < adapter.minimum_assurance
        || !adapter.registry_bindings.contains(&registry.digest())
    {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let host_signer = ForkHostSigningKeyV1::from_seed(host_seed).map_err(signature_invalid)?;
    host_seed.zeroize();
    if adapter_signer.public_key() == host_signer.public_key() {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    Ok(LocalForkAuthenticationCredentialsV1 {
        policy,
        registry,
        adapter_signer,
        host_signer: LocalForkHostSignerV1 {
            _signer: host_signer,
        },
    })
}

fn parse_facr1(
    bytes: &[u8],
    service_uid: u32,
) -> Result<
    ([u8; 32], ForkAuthenticationPolicyV1, LocalAccountRegistryV1),
    LocalForkAuthenticationErrorV1,
> {
    let fields = canonical_array(bytes, MAX_FORK_AUTH_CREDENTIAL_BYTES_V1, "FACR1", 7)?;
    let seed = fixed_nonzero(&fields[2], 32)?;
    let policy_bytes = bounded_bytes(&fields[3], 37_528)?;
    let policy = ForkAuthenticationPolicyV1::from_canonical_cbor(policy_bytes)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    let adapter_id = bounded_text(&fields[4])?;
    let assurance = positive_u8(&fields[5])?;
    let entries = array(&fields[6], 64)?;
    let bindings = entries
        .iter()
        .map(|entry| parse_binding(entry))
        .collect::<Result<Vec<_>, _>>()?;
    let registry =
        LocalAccountRegistryV1::new(adapter_id.clone(), assurance, bindings, service_uid)
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    Ok((seed, policy, registry))
}

fn parse_fahk1(bytes: &[u8]) -> Result<[u8; 32], LocalForkAuthenticationErrorV1> {
    if bytes.len() != FAHK1_BYTES {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let fields = canonical_array(bytes, FAHK1_BYTES, "FAHK1", 3)?;
    fixed_nonzero(&fields[2], 32)
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
    let mut bytes = Vec::with_capacity(size);
    file.read_to_end(&mut bytes)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialUnavailable)?;
    if bytes.len() != size {
        bytes.zeroize();
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    Ok(bytes)
}

fn canonical_array(
    bytes: &[u8],
    maximum: usize,
    marker: &str,
    expected_fields: usize,
) -> Result<Vec<Value>, LocalForkAuthenticationErrorV1> {
    if bytes.len() > maximum {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    if cursor.position()
        != u64::try_from(bytes.len())
            .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?
    {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let fields = array(&value, expected_fields)?;
    if !matches!(fields.first(), Some(Value::Text(text)) if text == marker)
        || !matches!(fields.get(1), Some(Value::Integer(version)) if *version == 1.into())
    {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    let mut encoded = Vec::new();
    ciborium::into_writer(&value, &mut encoded)
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)?;
    if encoded != bytes {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    Ok(fields)
}

fn array(value: &Value, length: usize) -> Result<Vec<Value>, LocalForkAuthenticationErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values.clone()),
        _ => Err(LocalForkAuthenticationErrorV1::CredentialInvalid),
    }
}

fn fixed_nonzero(value: &Value, length: usize) -> Result<[u8; 32], LocalForkAuthenticationErrorV1> {
    let Value::Bytes(bytes) = value else {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    };
    if bytes.len() != length || !bytes.iter().any(|byte| *byte != 0) {
        return Err(LocalForkAuthenticationErrorV1::CredentialInvalid);
    }
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| LocalForkAuthenticationErrorV1::CredentialInvalid)
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

fn signature_invalid(_: ForkAuthenticationSignatureErrorV1) -> LocalForkAuthenticationErrorV1 {
    LocalForkAuthenticationErrorV1::CredentialInvalid
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt as _, net::UnixStream},
    };

    use super::*;
    use ciborium::value::Value;
    use pos_core::fork_authentication::ForkAuthenticationAdapterPolicyV1;

    fn test_ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
    }

    fn encode(value: Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        test_ok(ciborium::into_writer(&value, &mut bytes));
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

    fn credential_bytes(uid: u32, host_seed: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let adapter_seed = [7; 32];
        let registry = test_ok(LocalAccountRegistryV1::new(
            "local-unix".to_owned(),
            2,
            vec![binding(uid)],
            uid.saturating_add(1),
        ));
        let adapter = test_ok(ForkAuthenticationAdapterSigningKeyV1::from_seed(
            adapter_seed,
        ));
        let policy = test_ok(ForkAuthenticationPolicyV1::new(vec![
            ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "local-unix".to_owned(),
                verifying_key: adapter.public_key(),
                minimum_assurance: 2,
                registry_bindings: vec![registry.digest()],
            },
        ]));
        let principal = test_ok(binding(uid).principal.encode());
        let facr1 = encode(Value::Array(vec![
            Value::Text("FACR1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(adapter_seed.to_vec()),
            Value::Bytes(policy.to_canonical_cbor()),
            Value::Text("local-unix".to_owned()),
            Value::Integer(2.into()),
            Value::Array(vec![Value::Array(vec![
                Value::Integer(uid.into()),
                Value::Bytes(principal.as_slice().to_vec()),
                Value::Text("owner".to_owned()),
            ])]),
        ]));
        let fahk1 = encode(Value::Array(vec![
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

    #[test]
    fn protected_credentials_bind_policy_registry_and_kernel_peer() {
        let uid = current_uid();
        if uid == 0 || uid == 65_534 {
            return;
        }
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
                .map(|entry| entry.minimum_assurance),
            Some(2)
        );
        assert_ne!(credentials.adapter_public_key(), [0; 32]);
        let (peer, _other) = test_ok(UnixStream::pair());
        let peer = test_ok(credentials.authenticate_peer(&peer));
        assert_eq!(peer.principal().trust_domain(), "unix.test");
        assert_eq!(peer.owner(), OwnerIdV1::from_static("owner"));
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
    fn peer_without_a_registry_mapping_fails_closed() {
        let uid = current_uid();
        let mapped_uid = uid.saturating_add(1).max(1);
        if mapped_uid == 65_534 || mapped_uid == u32::MAX {
            return;
        }
        let (auth, host) = credential_bytes(mapped_uid, [8; 32]);
        let directory = credentials_directory(&auth, &host);
        let credentials = test_ok(LocalForkAuthenticationCredentialsV1::load(
            directory.path(),
            mapped_uid.saturating_add(1),
        ));
        let (peer, _other) = test_ok(UnixStream::pair());
        assert!(matches!(
            credentials.authenticate_peer(&peer),
            Err(LocalForkAuthenticationErrorV1::PeerUnauthenticated)
        ));
    }
}
