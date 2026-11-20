//! `piglor-gateway provision-local-erasure`: the offline first step of the
//! Local erasure bundle (ADR-136 §4 *Bundle*; #1429, owner decisions Q1,
//! Q6, Q14 and Q15 of 2026-11-17 on #1412).
//!
//! The command runs under its systemd unit as an ADR-134 §8 offline writer:
//! it holds the store's shared mode lock and attaches to the store's
//! binding, never binding it. The unit's credential directory holds exactly
//! two credentials: [`LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME`], the role-2
//! signer's 32-byte Ed25519 seed, and the deployment release anchor
//! [`pos_local_erasure_loader::deployment_trust::RELEASE_TRUST_CREDENTIAL_NAME`], which
//! authenticates the installed TPS1 of the trust state store.
//!
//! ```text
//! piglor-gateway provision-local-erasure <sqlite-path>
//!     --issued-by <erasure-bundle/...> --signer-owner <owner-id> --out <absolute-path>
//!     [--expiry <unix-seconds, default 0>] [--signer-epoch <epoch, default 1>]
//!     [--rotation <routine|compromise, default routine>]
//! ```
//!
//! The command first claims `--out`, an absolute path, as a new file with
//! mode `0600`; an existing file is refused before anything else happens,
//! and a claimed file is removed again when a later step fails or panics (a
//! run killed outright can leave an empty file, which is safe to delete).
//! The checks that need no store write run next, in order: the installed
//! TPS1 must not be past its `offline_valid_through`, the `--issued-by` key
//! id must be a current, unrevoked TPS1 root, the installed TPS1 must not
//! revoke the signer key, and `<sqlite-path>` must name an existing file;
//! then the command takes the shared mode lock, which creates the store's
//! lock file, attaches as an offline writer, and checks that the store
//! records a Local Principal and that the complete ELB1 encodes. Only then
//! does it register the signer key under `(signer_owner, role 2,
//! signer_epoch)`, write the store identity once, open the Erasure Host
//! Timeline if it is absent, and write the unsigned ELB1 to the claimed
//! file, syncing it and its directory. The holder of the `erasure-bundle/`
//! root signs it into ELB1S offline.
//!
//! **Shared lock.** Like every offline writer, the command holds the mode
//! lock shared, so the lock alone does not exclude a serving Gateway. The
//! key-registry read-modify-write relies on the unit's
//! `Conflicts=piglor-gateway.service`, which stops `serve` while the command
//! runs.
//!
//! **Store identity.** 32 random bytes, written once through the write-once
//! erasure store identity; a re-run reuses the recorded value.
//!
//! **Erasure Host Timeline (ELHT1).** A host-owned root Timeline named
//! [`LOCAL_ERASURE_HOST_TIMELINE_NAME`] at the identity
//! [`pos_core::local_erasure_host_timeline_v1`]: the 128-bit prefix of
//! `CA("ELHT1", [store_identity])`, read as a ULID whose time bits carry no
//! time. It is the fence of key destruction for erasure, so the bundle lists
//! it in `host_timelines` with the Principal's Consent Timeline and its
//! authority Timeline, sorted, and composition refuses a bundle without it.
//! The first run opens it through a closed erasure host. A re-run on a
//! store that already has it, such as a routine signer rotation on a store
//! that holds erasure requests, opens no host and writes only through the
//! raw store under the mode lock. A store that holds erasure requests but no
//! Erasure Host Timeline cannot be provisioned: the closed host refuses it.
//!
//! **Executor binding (ELEXV1).** ELB1 binds
//! [`pos_runtime::local_erasure_execution_binding_v1`]: the executor id
//! `pigloros.local-erasure-executor` and `CA("ELEXV1", [executor_id, 1])`.
//!
//! **Rotation.** A routine rotation re-runs the command with a new signer
//! credential and a higher `--signer-epoch`; the key registry refuses another
//! key for a registered identity, a lower epoch and a reused key. A new
//! epoch becomes the registry's only active signing key, so the old signer
//! can sign nothing more, even for a request pinned to its bundle. A new
//! key is therefore registered only when no erasure request pins a bundle
//! (the ADR-136 §5 pin rule composition applies); otherwise the command
//! refuses before any write. A compromise passes `--rotation compromise`
//! and is registered only once the installed TPS1 revokes the old signer
//! key and the root or signer of every pinned bundle. A re-run with the
//! registered key is unchanged (owner decision of 2026-11-18 on #1431).
//! The pin check and the registration that follows are two steps over the
//! store, so the command must run with the Gateway stopped: a serving
//! Gateway could pin a bundle between them. The unit's
//! `Conflicts=piglor-gateway.service` stops `serve` while it runs; never run
//! the command beside a serving Gateway by other means.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use pos_core::{
    local_erasure_host_timeline_v1, local_erasure_owner_ref_v1, local_erasure_signer_key_id_v1,
    ErasureAuthoritySnapshotV1, ErasureErrorV1, ErasureInventoryPersistencePortV1,
    ErasureRecoveryLimitsV1, ErasureReferenceV1, EventStore, Hash, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, LocalErasureBundleV1, LocalErasureOwnerRowV1,
    LocalErasureSignerIdentityV1, OwnerIdV1, TimelineId,
};
use pos_crypto::key_roles::SigningKeyMaterial;
use pos_runtime::{
    local_erasure_execution_binding_v1, local_erasure_signer_rotation_v1,
    ErasureCoordinatorCompositionV1, LocalErasureRotationRefusalV1, LocalErasureSignerRotationV1,
    LOCAL_ERASURE_CLASSIFICATION_V1, LOCAL_ERASURE_POLICY_REFERENCE_V1,
};
use pos_store::{sqlite::SqliteStore, trust_policy_registry::CurrentTrustPolicyV1, StoreConfig};
use rand::RngExt as _;
use thiserror::Error;
use zeroize::Zeroizing;

use pos_local_erasure_loader::deployment_trust::{
    load_deployment_trust_v1, release_trust_from_credential, MAX_RELEASE_TRUST_CREDENTIAL_BYTES,
    RELEASE_TRUST_CREDENTIAL_NAME,
};
use pos_local_erasure_loader::local_principal::{
    local_principal_authority_timeline, recorded_registry_digest,
};
use pos_local_erasure_loader::unix_now;

use crate::local_principal::local_principal_consent_timeline;

/// The systemd credential holding the role-2 erasure signer's Ed25519 seed.
pub const LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME: &str = "pigloros.local-erasure-signer";

/// The name of the Erasure Host Timeline.
pub const LOCAL_ERASURE_HOST_TIMELINE_NAME: &str = "pigloros.local-erasure.host";

/// The largest credential the unit reads.
const MAX_CREDENTIAL_BYTES: usize = MAX_RELEASE_TRUST_CREDENTIAL_BYTES;

/// The command's flags, each given at most once.
const FLAGS: [&str; 6] = [
    "--expiry",
    "--issued-by",
    "--out",
    "--rotation",
    "--signer-epoch",
    "--signer-owner",
];

/// Closed `provision-local-erasure` refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum LocalErasureProvisionErrorV1 {
    /// The command line is not the documented one.
    #[error(
        "Usage: piglor-gateway provision-local-erasure <sqlite-path> --issued-by <key-id> \
         --signer-owner <owner-id> --out <absolute-path> [--expiry <unix-seconds>] \
         [--signer-epoch <epoch>] [--rotation routine|compromise]"
    )]
    Usage,
    /// `--out` exists, or its directory or the new file cannot be opened.
    #[error("--out must name a new file: it exists or cannot be created")]
    OutExists,
    /// The signer credential is not a 32-byte Ed25519 seed.
    #[error("the local erasure signer credential is not a 32-byte Ed25519 seed")]
    SignerCredentialInvalid,
    /// The installed TPS1 is past its `offline_valid_through`.
    #[error("the installed TPS1 has expired; install a current TPS1 first")]
    TrustExpired,
    /// `--issued-by` names no current TPS1 root, or a revoked one.
    #[error("--issued-by names no current, unrevoked root of the installed TPS1")]
    IssuerUntrusted,
    /// The installed TPS1 revokes the signer key.
    #[error("the installed TPS1 revokes this local erasure signer key")]
    SignerRevoked,
    /// The store records no Local Principal.
    #[error("the store records no Local Principal; run provision-local-principal first")]
    PrincipalMissing,
    /// The values form no valid ELB1, such as an `--issued-by` key id
    /// without the `erasure-bundle/` prefix, a signer epoch of zero or a
    /// signer owner that is no key-registry owner id.
    #[error(
        "these values form no valid local erasure bundle: --issued-by needs the \
         erasure-bundle/ prefix, --signer-owner 1 to 128 bytes and --signer-epoch at least 1"
    )]
    BundleInvalid,
    /// The key registry refuses the signer key: another key holds the
    /// identity, the epoch is below the owner's highest, or the key is
    /// registered elsewhere.
    #[error(
        "the key registry refuses this signer key: another key holds this --signer-owner and \
         --signer-epoch, the epoch is below the owner's highest, or the key is registered \
         under another epoch"
    )]
    SignerRefused,
    /// The signer key differs from the one the key registry holds for
    /// `--signer-owner` and its registration is refused: a routine rotation
    /// while an erasure request pins a bundle, a `--rotation compromise`
    /// the installed TPS1 does not reflect, or a key registry whose current
    /// signer cannot be read (owner decision of 2026-11-18 on #1431).
    #[error("refused to register a new local erasure signer key: {0}")]
    Rotation(LocalErasureRotationRefusalV1),
}

/// One parsed `provision-local-erasure` command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureProvisionRequestV1 {
    /// The Gateway's `SQLite` store.
    pub sqlite_path: String,
    /// The new file the unsigned ELB1 is written to, an absolute path.
    pub out: PathBuf,
    /// The TPS1 root key id that signs the bundle.
    pub issued_by: String,
    /// The ELB1 expiry; 0 keeps the bundle valid until TPS1 revokes it.
    pub expiry: u64,
    /// The key-registry owner id of the role-2 signer.
    pub signer_owner: String,
    /// The signer key epoch.
    pub signer_epoch: u64,
    /// How a signer key other than the registered one is registered.
    pub rotation: LocalErasureSignerRotationV1,
}

impl LocalErasureProvisionRequestV1 {
    /// Parse the arguments after the command name.
    ///
    /// # Errors
    /// Returns [`LocalErasureProvisionErrorV1::Usage`] without an `SQLite`
    /// path or with a flag in its place, with an unknown, repeated or
    /// value-less flag, without a required flag, with a relative `--out`,
    /// or with a number that is not a `u64`.
    pub fn parse(args: &[String]) -> Result<Self, LocalErasureProvisionErrorV1> {
        args.split_first()
            .filter(|(sqlite_path, _)| !sqlite_path.starts_with("--"))
            .ok_or(LocalErasureProvisionErrorV1::Usage)
            .and_then(|(sqlite_path, flags)| {
                flag_values(flags).and_then(|values| {
                    Ok(Self {
                        sqlite_path: sqlite_path.clone(),
                        out: absolute(required(&values, "--out")?)?,
                        issued_by: required(&values, "--issued-by")?.to_owned(),
                        expiry: number(&values, "--expiry", 0)?,
                        signer_owner: required(&values, "--signer-owner")?.to_owned(),
                        signer_epoch: number(&values, "--signer-epoch", 1)?,
                        rotation: rotation(&values)?,
                    })
                })
            })
    }
}

fn flag_values(flags: &[String]) -> Result<BTreeMap<&str, &str>, LocalErasureProvisionErrorV1> {
    flags
        .chunks(2)
        .try_fold(BTreeMap::new(), |mut values, pair| match pair {
            [flag, value]
                if FLAGS.contains(&flag.as_str()) && !values.contains_key(flag.as_str()) =>
            {
                values.insert(flag.as_str(), value.as_str());
                Ok(values)
            }
            _ => Err(LocalErasureProvisionErrorV1::Usage),
        })
}

fn required<'a>(
    values: &BTreeMap<&str, &'a str>,
    flag: &str,
) -> Result<&'a str, LocalErasureProvisionErrorV1> {
    values
        .get(flag)
        .copied()
        .ok_or(LocalErasureProvisionErrorV1::Usage)
}

fn absolute(path: &str) -> Result<PathBuf, LocalErasureProvisionErrorV1> {
    Some(PathBuf::from(path))
        .filter(|path| path.is_absolute())
        .ok_or(LocalErasureProvisionErrorV1::Usage)
}

/// `--rotation`: `routine`, the default, or `compromise`.
fn rotation(
    values: &BTreeMap<&str, &str>,
) -> Result<LocalErasureSignerRotationV1, LocalErasureProvisionErrorV1> {
    match values.get("--rotation").copied() {
        None | Some("routine") => Ok(LocalErasureSignerRotationV1::Routine),
        Some("compromise") => Ok(LocalErasureSignerRotationV1::Compromise),
        Some(_) => Err(LocalErasureProvisionErrorV1::Usage),
    }
}

fn number(
    values: &BTreeMap<&str, &str>,
    flag: &str,
    default: u64,
) -> Result<u64, LocalErasureProvisionErrorV1> {
    values.get(flag).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| LocalErasureProvisionErrorV1::Usage)
    })
}

/// Run `provision-local-erasure` from its systemd credentials.
///
/// It claims `request.out`, authenticates the installed TPS1 of the trust
/// state store at `trust_state` against the release anchor in
/// `credential_directory`, provisions the store of `request` and writes the
/// unsigned ELB1 to the claimed file. The directory must hold exactly
/// [`LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME`] and
/// [`RELEASE_TRUST_CREDENTIAL_NAME`], with the custody checks of the
/// Fork-authority credentials.
///
/// # Errors
/// Returns an error when `request.out` exists or cannot be created, when a
/// credential or the deployment trust is unavailable or invalid, when
/// [`provision_local_erasure`] refuses, or when the file cannot be written.
/// After a claim, every error or panic removes the claimed file again.
pub fn provision_local_erasure_from_credentials(
    request: &LocalErasureProvisionRequestV1,
    credential_directory: &Path,
    trust_state: &Path,
) -> io::Result<()> {
    claim_bundle_file(&request.out).and_then(|claimed| {
        credentialed_bundle(request, credential_directory, trust_state)
            .and_then(|bundle| claimed.write(&bundle))
    })
}

/// Read the unit's two credentials and the deployment trust, then
/// provision the store and return the unsigned ELB1.
fn credentialed_bundle(
    request: &LocalErasureProvisionRequestV1,
    credential_directory: &Path,
    trust_state: &Path,
) -> io::Result<Vec<u8>> {
    pos_local_erasure_loader::credentials::open_exact_credentials(
        credential_directory,
        &[
            LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME,
            RELEASE_TRUST_CREDENTIAL_NAME,
        ],
        rustix::process::geteuid().as_raw(),
    )
    .and_then(|credentials| {
        credentials
            .read(LOCAL_ERASURE_SIGNER_CREDENTIAL_NAME, MAX_CREDENTIAL_BYTES)
            .and_then(|signer| {
                credentials
                    .read(RELEASE_TRUST_CREDENTIAL_NAME, MAX_CREDENTIAL_BYTES)
                    .map(|release| (signer, release))
            })
    })
    .map_err(io::Error::other)
    .and_then(|(signer, release)| {
        release_trust_from_credential(&release)
            .and_then(|release| load_deployment_trust_v1(trust_state, release))
            .map_err(io::Error::other)
            .and_then(|trust| {
                signer_material(&signer)
                    .map_err(io::Error::other)
                    .and_then(|signer| {
                        provision_local_erasure(request, &signer, &trust, unix_now())
                    })
            })
    })
}

/// The signing key of a 32-byte Ed25519 seed credential.
///
/// The seed is copied straight into a zeroizing buffer, so no other copy of
/// it outlives this call.
pub(crate) fn signer_material(
    seed: &[u8],
) -> Result<SigningKeyMaterial, LocalErasureProvisionErrorV1> {
    (seed.len() == 32)
        .then(|| {
            let mut secret = Zeroizing::new([0_u8; 32]);
            secret.copy_from_slice(seed);
            SigningKeyMaterial::new(SigningKey::from_bytes(&secret))
        })
        .ok_or(LocalErasureProvisionErrorV1::SignerCredentialInvalid)
}

/// Provision the store of `request` for `signer` under the installed TPS1
/// `trust` at Unix second `now` and return the unsigned ELB1.
///
/// `trust` must not have expired: `now` must not be past its
/// `offline_valid_through`, the bound composition admits new work under.
/// A `sqlite_path` that names no existing file is refused as an unbound
/// store before the mode lock is taken, so provisioning creates neither a
/// database nor a lock file for it.
///
/// # Errors
/// Returns a [`LocalErasureProvisionErrorV1`] refusal, or the mode-lock,
/// offline-writer, store or host error. Every [`LocalErasureProvisionErrorV1`]
/// refusal but [`LocalErasureProvisionErrorV1::SignerRefused`] comes before
/// the first write. A host error opening the Erasure Host Timeline comes
/// after the signer registration and the store identity are written; both
/// writes are idempotent, so a re-run repeats them unchanged.
pub fn provision_local_erasure(
    request: &LocalErasureProvisionRequestV1,
    signer: &SigningKeyMaterial,
    trust: &CurrentTrustPolicyV1,
    now: u64,
) -> io::Result<Vec<u8>> {
    trusted_issuer(
        request,
        trust,
        now,
        signer.public_verification_key().as_bytes(),
    )
    .map_err(io::Error::other)
    .and_then(|()| {
        Some(request.sqlite_path.as_str())
            .filter(|path| Path::new(path).is_file())
            .ok_or(crate::mode_profile::GatewayModeErrorV1::Store(
                pos_core::GatewayModeBindingErrorV1::Unbound,
            ))
            .and_then(crate::mode_profile::GatewayModeStoreLockV1::shared)
            .map_err(io::Error::other)
            .and_then(|lock| {
                let provisioned = provision_locked(request, signer, trust);
                drop(lock);
                provisioned
            })
    })
}

/// The steps under the mode lock: the raw-store steps, then the Erasure
/// Host Timeline when the store does not hold it yet.
fn provision_locked(
    request: &LocalErasureProvisionRequestV1,
    signer: &SigningKeyMaterial,
    trust: &CurrentTrustPolicyV1,
) -> io::Result<Vec<u8>> {
    provision_store(request, signer, trust).and_then(|(bundle, missing)| {
        missing
            .map_or(Ok(()), |timeline| {
                open_host_timeline(&request.sqlite_path, timeline)
            })
            .map(|()| bundle)
    })
}

/// The installed TPS1 must not have expired at `now`, the `--issued-by`
/// root must be current and unrevoked in it, and the signer key unrevoked.
fn trusted_issuer(
    request: &LocalErasureProvisionRequestV1,
    trust: &CurrentTrustPolicyV1,
    now: u64,
    signer_public_key: &[u8; 32],
) -> Result<(), LocalErasureProvisionErrorV1> {
    let snapshot = trust.snapshot();
    let revoked = |key_id: &str| snapshot.revoked_key_ids.iter().any(|id| id == key_id);
    if now > trust.expiry() {
        Err(LocalErasureProvisionErrorV1::TrustExpired)
    } else if revoked(&request.issued_by)
        || !snapshot
            .trust_roots
            .iter()
            .any(|root| root.key_id == request.issued_by)
    {
        Err(LocalErasureProvisionErrorV1::IssuerUntrusted)
    } else if revoked(&local_erasure_signer_key_id_v1(signer_public_key)) {
        Err(LocalErasureProvisionErrorV1::SignerRevoked)
    } else {
        Ok(())
    }
}

/// The raw-store steps under the mode lock, over the existing file
/// [`provision_local_erasure`] checked before taking the lock.
///
/// The steps build ELB1 from the recorded Local Principal and store
/// identity, then register the signer and write the identity, and return
/// ELB1 and the Erasure Host Timeline when the store does not hold it yet.
fn provision_store(
    request: &LocalErasureProvisionRequestV1,
    signer: &SigningKeyMaterial,
    trust: &CurrentTrustPolicyV1,
) -> io::Result<(Vec<u8>, Option<TimelineId>)> {
    SqliteStore::open(&request.sqlite_path)
        .map_err(io::Error::other)
        .and_then(|mut store| {
            crate::mode_profile::attach_offline_writer_v1(&mut store)
                .map_err(io::Error::other)
                .and_then(|_| recorded_registry_digest(&store).map_err(io::Error::other))
                .and_then(|registry| {
                    registry
                        .ok_or(LocalErasureProvisionErrorV1::PrincipalMissing)
                        .map_err(io::Error::other)
                })
                .and_then(|registry| {
                    store
                        .erasure_authority_snapshot_with_limits(
                            ErasureRecoveryLimitsV1::compiled_maximum(),
                        )
                        .map_err(io::Error::other)
                        .and_then(|snapshot| {
                            write_store(&mut store, request, signer, trust, registry, &snapshot)
                        })
                })
        })
}

/// Build ELB1 for the recorded (or a new random) store identity, then
/// register the signer and write the identity once.
fn write_store(
    store: &mut SqliteStore,
    request: &LocalErasureProvisionRequestV1,
    signer: &SigningKeyMaterial,
    trust: &CurrentTrustPolicyV1,
    registry: Hash,
    snapshot: &ErasureAuthoritySnapshotV1,
) -> io::Result<(Vec<u8>, Option<TimelineId>)> {
    let identity = snapshot.store_identity().unwrap_or_else(random_identity);
    validated_bundle(request, signer, trust, registry, identity).and_then(
        |(owner, (bundle, host_timeline))| {
            local_erasure_signer_rotation_v1(
                store,
                owner,
                *signer.public_verification_key().as_bytes(),
                request.rotation,
                &trust.snapshot().revoked_key_ids,
            )
            .map_err(LocalErasureProvisionErrorV1::Rotation)
            .map_err(io::Error::other)
            .and_then(|()| register_signer(store, owner, request.signer_epoch, signer))
            .and_then(|()| {
                store
                    .init_erasure_store_identity(identity)
                    .map_err(io::Error::other)
            })
            .map(|_| {
                let missing = snapshot.timeline(host_timeline).is_none();
                (bundle, missing.then_some(host_timeline))
            })
        },
    )
}

/// The signer owner id and the ELB1 of these values, or
/// [`LocalErasureProvisionErrorV1::BundleInvalid`].
fn validated_bundle(
    request: &LocalErasureProvisionRequestV1,
    signer: &SigningKeyMaterial,
    trust: &CurrentTrustPolicyV1,
    registry: Hash,
    identity: Hash,
) -> io::Result<(OwnerIdV1, (Vec<u8>, TimelineId))> {
    OwnerIdV1::new(request.signer_owner.as_str())
        .ok()
        .zip(bundle(request, signer, trust, registry, identity).ok())
        .ok_or(LocalErasureProvisionErrorV1::BundleInvalid)
        .map_err(io::Error::other)
}

/// A new random store identity.
fn random_identity() -> Hash {
    let mut identity = [0; 32];
    rand::rng().fill(&mut identity);
    Hash::from_bytes(identity)
}

/// The canonical unsigned ELB1 of this store and its Erasure Host Timeline.
fn bundle(
    request: &LocalErasureProvisionRequestV1,
    signer: &SigningKeyMaterial,
    trust: &CurrentTrustPolicyV1,
    registry: Hash,
    identity: Hash,
) -> Result<(Vec<u8>, TimelineId), ErasureErrorV1> {
    let store_identity = ErasureReferenceV1::from_digest(*identity.as_bytes());
    let signer_public_key = *signer.public_verification_key().as_bytes();
    local_erasure_host_timeline_v1(store_identity).and_then(|host_timeline| {
        owner_rows(store_identity).and_then(|owners| {
            LocalErasureBundleV1 {
                tps1: ErasureReferenceV1::from_digest(trust.digest()),
                store_identity,
                authority_registry_digest: ErasureReferenceV1::from_digest(*registry.as_bytes()),
                host_timelines: [
                    local_principal_consent_timeline(),
                    host_timeline,
                    local_principal_authority_timeline(),
                ]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
                policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
                owners,
                execution_binding: local_erasure_execution_binding_v1(),
                signer_identity: LocalErasureSignerIdentityV1 {
                    owner_id: request.signer_owner.as_bytes().to_vec(),
                    epoch: request.signer_epoch,
                },
                signer_public_key,
                signer_key_id: local_erasure_signer_key_id_v1(&signer_public_key),
                issued_by: request.issued_by.clone(),
                expiry: request.expiry,
            }
            .to_canonical_cbor()
            .map(|bundle| (bundle, host_timeline))
        })
    })
}

/// One owner row per `(category, ack_class)` of the compiled ELP1, each
/// owned by this store.
fn owner_rows(
    store_identity: ErasureReferenceV1,
) -> Result<Vec<LocalErasureOwnerRowV1>, ErasureErrorV1> {
    LOCAL_ERASURE_CLASSIFICATION_V1
        .iter()
        .map(|&(_, _, category, ack_class)| (u64::from(category), ack_class))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(category, ack_class)| {
            local_erasure_owner_ref_v1(store_identity, category, ack_class).map(|owner_ref| {
                LocalErasureOwnerRowV1 {
                    category,
                    ack_class: ack_class.to_owned(),
                    owner_ref,
                }
            })
        })
        .collect()
}

/// Register the signer key under `(owner, role 2, epoch)`; an exact
/// re-registration is unchanged.
fn register_signer(
    store: &mut SqliteStore,
    owner: OwnerIdV1,
    epoch: u64,
    signer: &SigningKeyMaterial,
) -> io::Result<()> {
    store
        .load_key_registry()
        .map_err(io::Error::other)
        .and_then(|registry| {
            let mut registry = registry.unwrap_or_else(KeyRegistryStateV1::new);
            registry
                .register_key(KeyRegistrationV1::new(
                    KeyIdentityV1::new(owner, KeyRoleV1::TimelineIntegritySigning, epoch),
                    signer.material_digest(),
                    Some(signer.public_verification_key()),
                ))
                .map_err(|_| io::Error::other(LocalErasureProvisionErrorV1::SignerRefused))
                .and_then(|_| store.save_key_registry(&registry).map_err(io::Error::other))
        })
}

/// Open the Erasure Host Timeline through a closed erasure host.
fn open_host_timeline(sqlite_path: &str, timeline: TimelineId) -> io::Result<()> {
    crate::startup::open_recovered_erasure_host(
        StoreConfig::Sqlite {
            path: sqlite_path.to_owned(),
        },
        crate::startup::GatewayHostStoreV1::Standard,
        &ErasureCoordinatorCompositionV1::closed(),
    )
    .and_then(|mut host| {
        crate::mode_profile::attach_offline_writer_v1(host.gateway_mode_binding())
            .map_err(io::Error::other)
            .and_then(|_| {
                host.command_sender()
                    .and_then(|mut sender| {
                        sender
                            .open_root_timeline(timeline, LOCAL_ERASURE_HOST_TIMELINE_NAME)
                            .map(drop)
                    })
                    .map_err(crate::startup::erasure_host_failure)
            })
    })
}

/// The claimed `--out` file and its directory.
///
/// Dropping it before a completed write, on an error or a panic, removes
/// the claimed path again.
struct ClaimedBundleFileV1 {
    file: File,
    directory: File,
    path: PathBuf,
    written: bool,
}

impl ClaimedBundleFileV1 {
    /// Write `bundle`, then sync the file and its directory.
    fn write(mut self, bundle: &[u8]) -> io::Result<()> {
        let written = self
            .file
            .write_all(bundle)
            .and_then(|()| self.file.sync_all())
            .and_then(|()| self.directory.sync_all());
        self.written = written.is_ok();
        written
    }
}

impl Drop for ClaimedBundleFileV1 {
    fn drop(&mut self) {
        if !self.written {
            drop(std::fs::remove_file(&self.path));
        }
    }
}

/// Claim the absolute path `out` as a new owner-only file.
fn claim_bundle_file(out: &Path) -> io::Result<ClaimedBundleFileV1> {
    out.parent()
        .ok_or(LocalErasureProvisionErrorV1::Usage)
        .map_err(io::Error::other)
        .and_then(|parent| File::open(parent).map_err(|error| out_unavailable(error.kind())))
        .and_then(|directory| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(out)
                .map_err(|error| out_unavailable(error.kind()))
                .map(|file| ClaimedBundleFileV1 {
                    file,
                    directory,
                    path: out.to_owned(),
                    written: false,
                })
        })
}

/// The payload-free [`LocalErasureProvisionErrorV1::OutExists`] refusal of
/// a `--out` that cannot be claimed, with the io error `kind`.
fn out_unavailable(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, LocalErasureProvisionErrorV1::OutExists)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests;
