//! Gateway execution-mode profiles (ADR-134).
//!
//! A Gateway execution-mode profile (GMP1) is the release-compiled, reviewed
//! declaration of the serving mode of one Gateway process and its store:
//! `gateway-mode-local-v1` or `gateway-mode-air-gapped-v1`. A binding is
//! *composition-verified*: `serve --profile` selects it, the startup
//! predicates check the composed listeners, network grants and ledger source
//! against it, and the store records it with a `binding_epoch`. It is never an
//! ADR-104 EPF1, a qualification, a reproducibility claim or a registration
//! authority.
//!
//! The only public items are the closed [`GatewayModeProfileIdV1`], the
//! operator inputs ([`GatewayNetworkGrantV1`], [`GatewayServeCompositionV1`]),
//! the store lock, the typed error, and the opaque [`GatewayModeBindingV1`]
//! handle, which only [`bind_gateway_mode_v1`] returns. A downstream crate can
//! neither construct a handle nor read bytes from it:
//!
//! ```compile_fail
//! let _handle = piglor_gateway::mode_profile::GatewayModeBindingV1 {};
//! ```
//!
//! ```compile_fail
//! fn digest(handle: &piglor_gateway::mode_profile::GatewayModeBindingV1) {
//!     let _bytes = handle.revision_input();
//! }
//! ```

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod declaration;
mod gmp1;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt,
    net::SocketAddr,
    num::NonZeroU64,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use ciborium::Value;
use pos_core::{
    GatewayModeBindingHostV1, GatewayModeBindingPortV1, GatewayModeBindingRecordV1,
    GatewayModeProfileRefV1,
};
use pos_runtime::ErasureExecutionHostV1;

use gmp1::{
    Gmp1RecordV1, AIR_GAPPED_MODE_PROFILE_ID, GMP1_MAGIC, GMP1_PLATFORM_LINUX, GMP1_VERSION,
    LOCAL_MODE_PROFILE_ID,
};

#[cfg(target_os = "linux")]
mod compiled {
    include!(concat!(env!("OUT_DIR"), "/gateway_mode_profiles.rs"));
}

/// Digest domain of one canonical GMP1 record, distinct from EPF1's.
const GMP1_DIGEST_DOMAIN: &[u8] = b"PiglorOS.GatewayModeProfile.v1\0";
/// Maximum canonical bytes of one GMP1 record.
const GMP1_MAX_BYTES: usize = 4_096;
/// Ingress tag of a loopback TCP HTTP listener.
const INGRESS_LOOPBACK_HTTP: u8 = 1;
/// Ingress tag of a non-loopback, public read-only (spectator) listener.
const INGRESS_PUBLIC_READ_ONLY: u8 = 2;
/// Ingress tag of the Unix-domain Fork-admission socket.
const INGRESS_FORK_ADMISSION_SOCKET: u8 = 3;
/// Revocation freshness of a mode whose single bound store makes revocation
/// state current by construction (D10).
const REVOCATION_CURRENT_BY_CONSTRUCTION: u8 = 1;
/// The `epf1_field` of the security revision until #461 installs an EPF1.
const EPF1_EXPLICIT_ABSENT: u8 = 0x00;

/// Closed failures of composing, binding and migrating a Gateway execution
/// mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GatewayModeBindingErrorV1 {
    /// The `--profile` value names no compiled execution-mode profile.
    #[error("unknown gateway execution-mode profile")]
    UnknownProfile,
    /// The `--network-grant` value names no network grant.
    #[error("unknown network grant")]
    UnknownNetworkGrant,
    /// Execution-mode profiles and their store lock require Linux.
    #[error("gateway execution-mode profiles require Linux")]
    UnsupportedPlatform,
    /// The compiled profile bytes failed their own GMP1 rules.
    #[error("compiled gateway execution-mode profile is invalid")]
    InvalidProfileRecord,
    /// A composed listener is outside the profile's ingress.
    #[error("a composed listener is outside the execution mode's ingress")]
    ListenerOutsideIngress,
    /// A network-bearing feature lacks its `--network-grant`.
    #[error("a network-bearing feature requires its --network-grant")]
    NetworkGrantRequired,
    /// The execution mode accepts no network grant.
    #[error("the execution mode accepts no --network-grant")]
    NetworkGrantRefused,
    /// `OwnTracks` ingress needs a loopback bind.
    #[error("OwnTracks ingress requires a loopback bind")]
    OwnTracksRequiresLoopback,
    /// `LEDGER_SOURCE` names a network source.
    #[error("LEDGER_SOURCE must be a local filesystem path")]
    NetworkLedgerSource,
    /// The store refused or failed the binding operation.
    #[error("store execution-mode binding failed: {0}")]
    Store(#[from] pos_core::GatewayModeBindingErrorV1),
    /// The store is bound to another execution mode.
    #[error("store is bound to another execution mode; run migrate-mode")]
    ModeMismatch,
    /// The store's mode lock is held by another process or cannot be taken.
    #[error("store execution-mode lock is unavailable")]
    StoreLockUnavailable,
    /// The bound execution mode refuses this operation.
    #[error("the store's execution mode refuses this operation")]
    RefusedInMode,
    /// A write found this process's binding epoch stale (ADR-134 §8).
    #[error("gateway mode binding is stale")]
    Stale,
}

/// The closed set of compiled Gateway execution-mode profile identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayModeProfileIdV1 {
    /// `gateway-mode-local-v1`.
    Local,
    /// `gateway-mode-air-gapped-v1`.
    AirGapped,
}

impl GatewayModeProfileIdV1 {
    const ALL: [Self; 2] = [Self::Local, Self::AirGapped];

    /// The profile identifier text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => LOCAL_MODE_PROFILE_ID,
            Self::AirGapped => AIR_GAPPED_MODE_PROFILE_ID,
        }
    }
}

impl FromStr for GatewayModeProfileIdV1 {
    type Err = GatewayModeBindingErrorV1;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|id| id.as_str() == value)
            .ok_or(GatewayModeBindingErrorV1::UnknownProfile)
    }
}

/// One explicit operator network grant (`--network-grant`, ADR-134 §4).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GatewayNetworkGrantV1 {
    /// `owntracks`: authenticated `OwnTracks` ingress on the loopback bind.
    OwnTracks,
    /// `public-read-only`: the non-loopback read-only spectator listener.
    PublicReadOnly,
}

impl GatewayNetworkGrantV1 {
    /// The one-byte security-revision tag (ADR-134 §6).
    const fn tag(self) -> u8 {
        match self {
            Self::OwnTracks => 0x01,
            Self::PublicReadOnly => 0x02,
        }
    }
}

impl FromStr for GatewayNetworkGrantV1 {
    type Err = GatewayModeBindingErrorV1;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "owntracks" => Ok(Self::OwnTracks),
            "public-read-only" => Ok(Self::PublicReadOnly),
            _ => Err(GatewayModeBindingErrorV1::UnknownNetworkGrant),
        }
    }
}

/// The host-owned facts of one `serve` composition that the startup
/// predicates check (ADR-134 §4).
#[derive(Clone, Debug)]
pub struct GatewayServeCompositionV1 {
    /// The TCP HTTP bind.
    pub tcp_addr: SocketAddr,
    /// Whether `--owntracks-owner-key` composes `OwnTracks` ingress.
    pub owntracks_ingress: bool,
    /// Whether `--require-local-fork-authority` composes the Unix socket.
    pub fork_admission_socket: bool,
    /// The configured `LEDGER_SOURCE`, if any.
    pub ledger_source: Option<OsString>,
    /// The sorted, duplicate-free `--network-grant` set.
    pub network_grants: BTreeSet<GatewayNetworkGrantV1>,
}

/// A GMP1 digest. It has no conversion to `pos_core::Hash`, `[u8; 32]` or any
/// EPF1 type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GatewayModeProfileDigestV1([u8; 32]);

impl GatewayModeProfileDigestV1 {
    fn of(bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(GMP1_DIGEST_DOMAIN);
        hasher.update(bytes);
        Self(*hasher.finalize().as_bytes())
    }

    /// The 32 bytes the §6 security revision binds.
    const fn revision_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The 32 bytes the store port records.
    const fn store_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Lower-case hexadecimal for operator disclosure.
    fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// One compiled execution-mode profile.
#[derive(Clone, Debug)]
pub(crate) struct GatewayModeProfileV1 {
    id: GatewayModeProfileIdV1,
    record: Gmp1RecordV1,
    digest: GatewayModeProfileDigestV1,
}

impl GatewayModeProfileV1 {
    /// Decode compiled `bytes` as the profile of `id`.
    fn decode(id: GatewayModeProfileIdV1, bytes: &[u8]) -> Result<Self, GatewayModeBindingErrorV1> {
        decode_gmp1(bytes)
            .filter(|record| record.mode_profile_id == id.as_str())
            .map(|record| Self {
                id,
                record,
                digest: GatewayModeProfileDigestV1::of(bytes),
            })
            .ok_or(GatewayModeBindingErrorV1::InvalidProfileRecord)
    }

    /// The neutral store reference of this profile.
    fn reference(&self) -> Result<GatewayModeProfileRefV1, GatewayModeBindingErrorV1> {
        GatewayModeProfileRefV1::try_new(self.id.as_str(), self.digest.store_bytes())
            .map_err(GatewayModeBindingErrorV1::Store)
    }

    fn allows_ingress(&self, tag: u8) -> bool {
        self.record.ingress.contains(&tag)
    }
}

/// Decode one canonical GMP1 record; `None` for anything else, EPF1 bytes
/// included.
fn decode_gmp1(bytes: &[u8]) -> Option<Gmp1RecordV1> {
    if bytes.len() > GMP1_MAX_BYTES {
        return None;
    }
    let items = ciborium::de::from_reader::<Value, _>(bytes)
        .ok()?
        .into_array()
        .ok()?;
    let [magic, version, id, semantic_version, mode, network_allowed, ingress, predicates, freshness, registration, platform, previous] =
        <[Value; 12]>::try_from(items).ok()?;
    let header = text(magic)? == GMP1_MAGIC
        && small(&version)? == GMP1_VERSION
        && small(&platform)? == GMP1_PLATFORM_LINUX;
    let record = Gmp1RecordV1 {
        mode_profile_id: text(id)?,
        semantic_version: text(semantic_version)?,
        mode: small(&mode)?,
        network_allowed: network_allowed.as_bool()?,
        ingress: small_list(ingress)?,
        startup_predicates: small_list(predicates)?,
        revocation_freshness: small(&freshness)?,
        registration_profile_id: optional_text(registration)?,
        previous_mode_profile_digest: optional_digest(previous)?,
    };
    (header && record.validate().is_ok() && record.encode() == bytes).then_some(record)
}

fn text(value: Value) -> Option<String> {
    value.into_text().ok()
}

fn small(value: &Value) -> Option<u8> {
    value
        .as_integer()
        .and_then(|integer| u8::try_from(integer).ok())
}

fn small_list(value: Value) -> Option<Vec<u8>> {
    value
        .into_array()
        .ok()
        .and_then(|items| items.iter().map(small).collect())
}

fn optional_text(value: Value) -> Option<Option<String>> {
    if value.is_null() {
        Some(None)
    } else {
        text(value).map(Some)
    }
}

fn optional_digest(value: Value) -> Option<Option<[u8; 32]>> {
    if value.is_null() {
        Some(None)
    } else {
        value
            .into_bytes()
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(Some)
    }
}

/// The compiled profile of `id` (Linux only).
#[cfg(target_os = "linux")]
pub(crate) fn installed_gateway_mode_profile_v1(
    id: GatewayModeProfileIdV1,
) -> Result<GatewayModeProfileV1, GatewayModeBindingErrorV1> {
    let bytes = match id {
        GatewayModeProfileIdV1::Local => compiled::GATEWAY_MODE_LOCAL_V1,
        GatewayModeProfileIdV1::AirGapped => compiled::GATEWAY_MODE_AIR_GAPPED_V1,
    };
    GatewayModeProfileV1::decode(id, bytes)
}

/// Execution-mode profiles are compiled only for Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) const fn installed_gateway_mode_profile_v1(
    _id: GatewayModeProfileIdV1,
) -> Result<GatewayModeProfileV1, GatewayModeBindingErrorV1> {
    Err(GatewayModeBindingErrorV1::UnsupportedPlatform)
}

/// Run startup predicates 1 to 4, the pure configuration checks, for `id`
/// before any lock, store, ledger or listener (ADR-134 §4).
///
/// # Errors
/// Returns the first refused predicate.
pub fn verify_gateway_serve_composition_v1(
    id: GatewayModeProfileIdV1,
    composition: &GatewayServeCompositionV1,
) -> Result<(), GatewayModeBindingErrorV1> {
    installed_gateway_mode_profile_v1(id)
        .and_then(|profile| verify_predicates(&profile, composition))
}

fn verify_predicates(
    profile: &GatewayModeProfileV1,
    composition: &GatewayServeCompositionV1,
) -> Result<(), GatewayModeBindingErrorV1> {
    listeners_within_ingress(profile, composition)
        .and_then(|()| network_features_granted(profile, composition))
        .and_then(|()| no_network_ledger_source(composition))
}

const fn refuse(
    refused: bool,
    error: GatewayModeBindingErrorV1,
) -> Result<(), GatewayModeBindingErrorV1> {
    if refused {
        Err(error)
    } else {
        Ok(())
    }
}

/// Predicate 2: every composed listener is in the profile's ingress, and the
/// spectator listener has its operator grant.
fn listeners_within_ingress(
    profile: &GatewayModeProfileV1,
    composition: &GatewayServeCompositionV1,
) -> Result<(), GatewayModeBindingErrorV1> {
    let loopback = composition.tcp_addr.ip().is_loopback();
    let tcp = if loopback {
        INGRESS_LOOPBACK_HTTP
    } else {
        INGRESS_PUBLIC_READ_ONLY
    };
    let outside = !profile.allows_ingress(tcp)
        || (composition.fork_admission_socket
            && !profile.allows_ingress(INGRESS_FORK_ADMISSION_SOCKET));
    let ungranted = !loopback
        && !composition
            .network_grants
            .contains(&GatewayNetworkGrantV1::PublicReadOnly);
    refuse(outside, GatewayModeBindingErrorV1::ListenerOutsideIngress)
        .and_then(|()| refuse(ungranted, GatewayModeBindingErrorV1::NetworkGrantRequired))
}

/// Predicate 3: a mode without network accepts no grant, and `OwnTracks`
/// needs its grant and a loopback bind; it is never silently dropped.
fn network_features_granted(
    profile: &GatewayModeProfileV1,
    composition: &GatewayServeCompositionV1,
) -> Result<(), GatewayModeBindingErrorV1> {
    let owntracks = composition.owntracks_ingress;
    refuse(
        !profile.record.network_allowed && !composition.network_grants.is_empty(),
        GatewayModeBindingErrorV1::NetworkGrantRefused,
    )
    .and_then(|()| {
        refuse(
            owntracks
                && !composition
                    .network_grants
                    .contains(&GatewayNetworkGrantV1::OwnTracks),
            GatewayModeBindingErrorV1::NetworkGrantRequired,
        )
    })
    .and_then(|()| {
        refuse(
            owntracks && !composition.tcp_addr.ip().is_loopback(),
            GatewayModeBindingErrorV1::OwnTracksRequiresLoopback,
        )
    })
}

/// Predicate 4: the ledger source is absent or a local filesystem path.
fn no_network_ledger_source(
    composition: &GatewayServeCompositionV1,
) -> Result<(), GatewayModeBindingErrorV1> {
    refuse(
        composition
            .ledger_source
            .as_ref()
            .is_some_and(|source| source.to_string_lossy().contains("://")),
        GatewayModeBindingErrorV1::NetworkLedgerSource,
    )
}

/// The process-wide signal that a write found this binding stale.
#[derive(Debug, Default)]
pub(crate) struct GatewayModeStaleSignalV1 {
    fired: AtomicBool,
    notify: tokio::sync::Notify,
}

impl GatewayModeStaleSignalV1 {
    /// Record a stale write and wake the serve loop.
    pub(crate) fn fire(&self) {
        self.fired.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    /// Whether a write found the binding stale.
    pub(crate) fn fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }

    /// Resolve once a write found the binding stale.
    pub(crate) async fn wait(&self) {
        self.notify.notified().await;
    }
}

/// The §6 security-revision inputs of one bound execution mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GatewayExecutionModeRevisionV1 {
    mode_profile: [u8; 32],
    grants: Vec<u8>,
    revocation_current_by_construction: bool,
}

impl GatewayExecutionModeRevisionV1 {
    /// The ordered §6 fields that precede the registry digest and the
    /// revocation byte: GMP1 digest, `epf1_field`, sorted grant tags.
    pub(crate) fn fields(&self) -> [&[u8]; 3] {
        [
            &self.mode_profile,
            std::slice::from_ref(&EPF1_EXPLICIT_ABSENT),
            &self.grants,
        ]
    }

    /// Whether revocation state is current by construction (Air-Gapped, D10).
    pub(crate) const fn revocation_current_by_construction(&self) -> bool {
        self.revocation_current_by_construction
    }
}

/// Opaque handle of one composition-verified, store-bound execution mode.
///
/// Only [`bind_gateway_mode_v1`] returns one. It has no public constructor,
/// field, or byte or digest accessor; its `Debug` output is redacted.
#[derive(Clone)]
pub struct GatewayModeBindingV1 {
    profile: GatewayModeProfileV1,
    network_grants: BTreeSet<GatewayNetworkGrantV1>,
    binding_epoch: NonZeroU64,
    stale: Arc<GatewayModeStaleSignalV1>,
}

impl fmt::Debug for GatewayModeBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayModeBindingV1 { .. }")
    }
}

impl GatewayModeBindingV1 {
    fn new(
        profile: GatewayModeProfileV1,
        network_grants: BTreeSet<GatewayNetworkGrantV1>,
        record: &GatewayModeBindingRecordV1,
    ) -> Self {
        Self {
            profile,
            network_grants,
            binding_epoch: record.binding_epoch(),
            stale: Arc::default(),
        }
    }

    /// The §6 revision inputs of this binding.
    pub(crate) fn revision_input(&self) -> GatewayExecutionModeRevisionV1 {
        GatewayExecutionModeRevisionV1 {
            mode_profile: self.profile.digest.revision_bytes(),
            grants: self
                .network_grants
                .iter()
                .map(|grant| grant.tag())
                .collect(),
            revocation_current_by_construction: self.profile.record.revocation_freshness
                == REVOCATION_CURRENT_BY_CONSTRUCTION,
        }
    }

    /// The ADR-058 profile this mode's own Plugin registration selects
    /// (field 9); it never authorizes.
    pub(crate) fn registration_profile_id(&self) -> Option<&str> {
        self.profile.record.registration_profile_id.as_deref()
    }

    /// The signal a stale write fires.
    pub(crate) fn stale_signal(&self) -> Arc<GatewayModeStaleSignalV1> {
        Arc::clone(&self.stale)
    }

    /// The operator disclosure of this binding.
    pub(crate) fn disclosure(&self) -> String {
        format!(
            "{} ({}) at binding epoch {}",
            self.profile.id.as_str(),
            self.profile.digest.to_hex(),
            self.binding_epoch
        )
    }
}

/// Bind the opened store of `host` to the compiled profile `id` (ADR-134
/// §4 predicates 1 to 5 and §8), attaching the binding's epoch to the host's
/// one adapter instance before its first write. This is the only way to
/// obtain a [`GatewayModeBindingV1`].
///
/// An empty store is bound at epoch 1; a store bound to the same profile is
/// attached; a store bound to the revision this profile names as its previous
/// digest rotates one hop. A populated unbound store and any other binding
/// are refused: only `migrate-mode` changes the mode.
///
/// # Errors
/// Returns the first refused predicate or store binding failure.
pub fn bind_gateway_mode_v1(
    id: GatewayModeProfileIdV1,
    composition: &GatewayServeCompositionV1,
    host: &mut ErasureExecutionHostV1,
) -> Result<GatewayModeBindingV1, GatewayModeBindingErrorV1> {
    installed_gateway_mode_profile_v1(id)
        .and_then(|profile| verify_predicates(&profile, composition).map(|()| profile))
        .and_then(|profile| {
            bind_store(host.gateway_mode_binding(), &profile).map(|record| {
                GatewayModeBindingV1::new(profile, composition.network_grants.clone(), &record)
            })
        })
}

/// What predicate 5 does with the store's current binding.
#[derive(Debug, Eq, PartialEq)]
enum BindingDecisionV1 {
    Bind,
    Attach,
    Rotate(GatewayModeProfileRefV1),
}

fn decide(
    stored: Option<GatewayModeBindingRecordV1>,
    current: &GatewayModeProfileRefV1,
    previous: Option<[u8; 32]>,
) -> Result<BindingDecisionV1, GatewayModeBindingErrorV1> {
    match stored {
        None => Ok(BindingDecisionV1::Bind),
        Some(record) if record.profile() == current => Ok(BindingDecisionV1::Attach),
        Some(record)
            if record.profile().profile_id() == current.profile_id()
                && previous == Some(record.profile().profile_digest()) =>
        {
            Ok(BindingDecisionV1::Rotate(record.profile().clone()))
        }
        Some(_) => Err(GatewayModeBindingErrorV1::ModeMismatch),
    }
}

fn bind_store(
    port: &mut dyn GatewayModeBindingPortV1,
    profile: &GatewayModeProfileV1,
) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
    profile.reference().and_then(|current| {
        port.load_mode_binding()
            .map_err(GatewayModeBindingErrorV1::Store)
            .and_then(|stored| {
                decide(
                    stored,
                    &current,
                    profile.record.previous_mode_profile_digest,
                )
            })
            .and_then(|decision| apply_decision(port, current, decision))
    })
}

fn apply_decision(
    port: &mut dyn GatewayModeBindingPortV1,
    current: GatewayModeProfileRefV1,
    decision: BindingDecisionV1,
) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
    let host = GatewayModeBindingHostV1::new();
    match decision {
        BindingDecisionV1::Bind => port.bind_empty_store_mode(host.authorize_bind(current)),
        BindingDecisionV1::Attach => port.attach_mode_binding(),
        BindingDecisionV1::Rotate(from) => host
            .authorize_rotation(from, current)
            .and_then(|permit| port.rotate_mode(permit)),
    }
    .map_err(GatewayModeBindingErrorV1::Store)
}

/// Attach an offline writer's adapter to its store's binding and return the
/// bound mode (ADR-134 §8). Offline writers never bind: an unbound,
/// populated-unbound or unreadable store is refused, and so is a binding no
/// compiled profile matches.
///
/// # Errors
/// Returns the store's refusal or [`GatewayModeBindingErrorV1::ModeMismatch`].
pub(crate) fn attach_offline_writer_v1(
    store: &mut dyn GatewayModeBindingPortV1,
) -> Result<GatewayModeProfileIdV1, GatewayModeBindingErrorV1> {
    store
        .attach_mode_binding()
        .map_err(GatewayModeBindingErrorV1::Store)
        .and_then(|record| compiled_id_of(record.profile()))
}

fn compiled_id_of(
    profile: &GatewayModeProfileRefV1,
) -> Result<GatewayModeProfileIdV1, GatewayModeBindingErrorV1> {
    GatewayModeProfileIdV1::ALL
        .into_iter()
        .find(|id| {
            installed_gateway_mode_profile_v1(*id)
                .and_then(|installed| installed.reference())
                .is_ok_and(|installed| &installed == profile)
        })
        .ok_or(GatewayModeBindingErrorV1::ModeMismatch)
}

/// Refuse an operation the Air-Gapped mode never composes.
pub(crate) const fn refuse_air_gapped(
    mode: GatewayModeProfileIdV1,
) -> Result<(), GatewayModeBindingErrorV1> {
    refuse(
        matches!(mode, GatewayModeProfileIdV1::AirGapped),
        GatewayModeBindingErrorV1::RefusedInMode,
    )
}

/// The non-blocking advisory lock on `<sqlite-path>.gateway-mode.lock`
/// (ADR-134 §8): `serve` and every offline writer hold it shared for their
/// lifetime; `migrate-mode` holds it exclusive. Neither waits.
#[derive(Debug)]
pub struct GatewayModeStoreLockV1 {
    _file: std::fs::File,
}

impl GatewayModeStoreLockV1 {
    /// Take the shared lock of the store at `sqlite_path`.
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::StoreLockUnavailable`] while
    /// `migrate-mode` holds it or when the lock file cannot be opened, and
    /// [`GatewayModeBindingErrorV1::UnsupportedPlatform`] off Linux.
    pub fn shared(sqlite_path: &str) -> Result<Self, GatewayModeBindingErrorV1> {
        Self::acquire(sqlite_path, false)
    }

    /// Take the exclusive lock of the store at `sqlite_path`.
    ///
    /// # Errors
    /// Returns [`GatewayModeBindingErrorV1::StoreLockUnavailable`] while any
    /// other holder exists or when the lock file cannot be opened, and
    /// [`GatewayModeBindingErrorV1::UnsupportedPlatform`] off Linux.
    pub fn exclusive(sqlite_path: &str) -> Result<Self, GatewayModeBindingErrorV1> {
        Self::acquire(sqlite_path, true)
    }

    #[cfg(target_os = "linux")]
    fn acquire(sqlite_path: &str, exclusive: bool) -> Result<Self, GatewayModeBindingErrorV1> {
        let operation = if exclusive {
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        } else {
            rustix::fs::FlockOperation::NonBlockingLockShared
        };
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(format!("{sqlite_path}.gateway-mode.lock"))
            .ok()
            .and_then(|file| {
                rustix::fs::flock(&file, operation)
                    .ok()
                    .map(|()| Self { _file: file })
            })
            .ok_or(GatewayModeBindingErrorV1::StoreLockUnavailable)
    }

    #[cfg(not(target_os = "linux"))]
    const fn acquire(
        _sqlite_path: &str,
        _exclusive: bool,
    ) -> Result<Self, GatewayModeBindingErrorV1> {
        Err(GatewayModeBindingErrorV1::UnsupportedPlatform)
    }
}

/// `migrate-mode <sqlite-path> --from <id> --to <id>`: under the exclusive
/// lock, advance the store's binding from `from` to `to` (epoch + 1 and a
/// history entry of kind migrate). Returns the operator audit line.
///
/// # Errors
/// Returns a lock, profile or store refusal; nothing changes on failure.
pub fn migrate_gateway_mode_v1(
    sqlite_path: &str,
    from: GatewayModeProfileIdV1,
    to: GatewayModeProfileIdV1,
) -> Result<String, GatewayModeBindingErrorV1> {
    let lock = GatewayModeStoreLockV1::exclusive(sqlite_path)?;
    let audit = installed_gateway_mode_profile_v1(from)
        .and_then(|from| installed_gateway_mode_profile_v1(to).map(|to| (from, to)))
        .and_then(|(from, to)| {
            from.reference()
                .and_then(|from_ref| to.reference().map(|to_ref| (from_ref, to_ref)))
                .and_then(|(from_ref, to_ref)| {
                    GatewayModeBindingHostV1::new()
                        .authorize_migration(from_ref, to_ref)
                        .map_err(GatewayModeBindingErrorV1::Store)
                })
                .and_then(|permit| {
                    pos_store::sqlite::SqliteStore::open(sqlite_path)
                        .map_err(|_| {
                            GatewayModeBindingErrorV1::Store(
                                pos_core::GatewayModeBindingErrorV1::Unavailable,
                            )
                        })
                        .and_then(|mut store| {
                            store
                                .migrate_mode(permit)
                                .map_err(GatewayModeBindingErrorV1::Store)
                        })
                })
                .map(|record| {
                    format!(
                        "migrated gateway execution mode from {} ({}) to {} ({}) at binding epoch {}",
                        from.id.as_str(),
                        from.digest.to_hex(),
                        to.id.as_str(),
                        to.digest.to_hex(),
                        record.binding_epoch()
                    )
                })
        });
    drop(lock);
    audit
}

/// A unit-test binding of the compiled `id` at epoch 1 with `grants`, for
/// in-crate fixtures that never open a bound store.
#[cfg(test)]
pub(crate) fn test_binding(
    id: GatewayModeProfileIdV1,
    grants: impl IntoIterator<Item = GatewayNetworkGrantV1>,
) -> GatewayModeBindingV1 {
    let profile = installed_gateway_mode_profile_v1(id)
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
    let reference = profile
        .reference()
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
    GatewayModeBindingV1::new(
        profile,
        grants.into_iter().collect(),
        &GatewayModeBindingRecordV1::new(reference, NonZeroU64::MIN),
    )
}

/// Bind an empty unit-test store to the compiled `id`, as the first `serve`
/// does, so offline-writer tests can run against it.
#[cfg(test)]
pub(crate) fn bind_test_store(
    store: &mut dyn GatewayModeBindingPortV1,
    id: GatewayModeProfileIdV1,
) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
    installed_gateway_mode_profile_v1(id)
        .and_then(|profile| profile.reference())
        .and_then(|reference| {
            store
                .bind_empty_store_mode(GatewayModeBindingHostV1::new().authorize_bind(reference))
                .map_err(GatewayModeBindingErrorV1::Store)
        })
}
