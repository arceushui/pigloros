//! The production Local Principal: explicit provisioning and the authorized
//! serve composition (#1361; owner decisions D1 and D4 on #302).
//!
//! Loopback reachability is the Local trust boundary, and one host-pinned
//! Principal acts behind it (D1). An operator provisions that Principal once,
//! offline, with `piglor-gateway provision-local-principal <sqlite-path>`
//! under its systemd unit (D4). The unit's one credential,
//! [`LOCAL_PRINCIPAL_CREDENTIAL_NAME`], is a TOML document naming the
//! Principal, the entities it may act as and its explicit operation grants:
//!
//! ```toml
//! principal_id = "01JC0GATEWAYQ0CA1PR1NC1PA1"
//! trust_domain = "local"
//! actor_entity_ids = ["01JC0GATEWAYQ0CA1ACT0R0000"]
//! operations = ["timeline.create", "timeline.events.read"]
//! ```
//!
//! Provisioning persists one root capability grant through
//! [`AuthorityPersistenceHostV1`] into the store's authority records: the
//! Principal is its grantor and grantee, its scope lists exactly the granted
//! operations ([`GatewayOperationV1::named`]) and the listed actors, and its
//! `authority_registry_digest` commits to the whole document. The authority
//! registry snapshot and the Principal's authentication evidence are a pure
//! function of that recorded grant, so the store holds one source of truth and
//! `serve` recomposes exactly what was provisioned. Nothing is provisioned
//! implicitly: a host without the record serves every protected operation
//! `401 unauthenticated`. A store holds at most one Local Principal; a
//! different document is refused rather than merged.
//!
//! `serve` reads the record through its one erasure host and never writes
//! authority at startup, so starting with or without it never rewrites a
//! recorded authority record.

#[cfg(target_os = "linux")]
use std::path::Path;
use std::{io, sync::Arc};

use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityCommitOutcomeV1, AuthorityErrorV1, AuthorityGranteeV1, AuthorityPersistenceErrorV1,
    AuthorityPersistenceHostV1, AuthorityPersistencePortV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityViewV1, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1, EntityId, Hash,
    PersistedAuthorityV1, PrincipalRefV1, Seq, TimelineId, WallTime,
};
use pos_runtime::ErasureExecutionHostV1;
use serde::Deserialize;
use thiserror::Error;
use ulid::Ulid;

use crate::{
    startup::erasure_host_failure, Gateway, GatewayAuthoritySourceV1, GatewayAuthorization,
    GatewayOperationV1, LocalAuthenticationAdapter, OwnTracksOwnerKey,
};

/// The one systemd credential `provision-local-principal` reads.
pub const LOCAL_PRINCIPAL_CREDENTIAL_NAME: &str = "pigloros.local-principal";
/// The largest Local Principal credential accepted.
pub const MAX_LOCAL_PRINCIPAL_CREDENTIAL_BYTES: usize = 16 * 1_024;
/// The authentication adapter the Local Principal's evidence names.
const LOCAL_ADAPTER_ID: &str = "local-loopback";
/// The one audience every Gateway operation is evaluated for.
const GATEWAY_AUDIENCE: &str = "gateway";

/// Closed Local Principal provisioning and composition failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum LocalPrincipalErrorV1 {
    /// The provisioning document is malformed or names no valid grant.
    #[error("Local Principal provisioning document is invalid")]
    Invalid,
    /// The store already holds a different Local Principal.
    #[error(
        "this store already holds a different Local Principal; a store holds exactly one \
         Principal and rotation is not supported, so provision the original document again \
         (an exact retry succeeds) or create a new store and provision it"
    )]
    Conflict,
    /// The store's authority records cannot be read or written.
    #[error("Local Principal authority is unavailable")]
    Unavailable,
    /// The store records a Local Principal this host cannot recompose
    /// exactly: the authority record is corrupt or conflicts with its
    /// Timeline. Startup fails; the host is never treated as unprovisioned.
    #[error(
        "the store's Local Principal authority record is unreadable or conflicts with its \
         authority Timeline; restore the store from a backup"
    )]
    Corrupt,
}

/// The operator's TOML provisioning document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalPrincipalDocumentV1 {
    principal_id: String,
    trust_domain: String,
    actor_entity_ids: Vec<String>,
    operations: Vec<String>,
}

/// One validated Local Principal provisioning: its root capability grant
/// and the authority registry snapshot that attests it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPrincipalProvisionV1 {
    grant: CapabilityGrantV1,
    registry: AuthorityRegistrySnapshotV1,
}

impl LocalPrincipalProvisionV1 {
    /// Grant `principal` exactly `operations`, acting as `actor_entity_ids`.
    ///
    /// # Errors
    /// Returns [`LocalPrincipalErrorV1::Invalid`] for an empty or oversized
    /// actor or operation set, or an invalid Principal or entity.
    pub fn try_new(
        principal: &PrincipalRefV1,
        actor_entity_ids: impl IntoIterator<Item = EntityId>,
        operations: impl IntoIterator<Item = GatewayOperationV1>,
    ) -> Result<Self, LocalPrincipalErrorV1> {
        let mut actors = actor_entity_ids.into_iter().collect::<Vec<_>>();
        actors.sort_unstable();
        actors.dedup();
        let mut operations = operations.into_iter().collect::<Vec<_>>();
        operations.sort_unstable_by_key(operation_name);
        operations.dedup();
        let registry_digest = registry_digest(principal, &actors, &operations);
        CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: sorted_set(operations.iter().copied().map(GatewayOperationV1::resource)),
            actions: sorted_set(operations.iter().copied().map(GatewayOperationV1::action)),
            purposes: sorted_set(operations.iter().copied().map(GatewayOperationV1::purpose)),
            audiences: vec![GATEWAY_AUDIENCE.to_owned()],
            actor_entity_ids: actors,
            subject_ids: Vec::new(),
            participant_ids: Vec::new(),
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 1,
            budget: 1,
            environment_constraints: Vec::new(),
        })
        .and_then(|scope| {
            CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
                grant_id: local_principal_grant_id(),
                grantor: principal.clone(),
                grantee: AuthorityGranteeV1::Principal(principal.clone()),
                trust_domain: principal.trust_domain().to_owned(),
                scope,
                valid_from_position: Seq::from_u64(1),
                valid_until_position: Seq::from_u64(u64::MAX),
                parent_grant_id: None,
                delegation_depth: 0,
                max_delegation_depth: 0,
                permitted_delegate_classes: Vec::new(),
                consent_references: Vec::new(),
                policy_revision: derived_hash("pigloros gateway local principal policy v1"),
                issuance_timeline: local_principal_authority_timeline(),
                issuance_seq: Seq::from_u64(1),
                revocation_epoch: 0,
                revocation_fence: None,
                authority_registry_digest: registry_digest,
            })
        })
        .and_then(|grant| {
            authority_for(&grant, &grant).map(|(_, registry)| Self { grant, registry })
        })
        .map_err(|_| LocalPrincipalErrorV1::Invalid)
    }

    /// Parse and validate the operator's TOML provisioning document.
    ///
    /// # Errors
    /// Returns [`LocalPrincipalErrorV1::Invalid`] for malformed TOML, an
    /// unknown member, a malformed ULID, an unknown operation name, or a
    /// document [`Self::try_new`] refuses.
    pub fn from_toml(text: &str) -> Result<Self, LocalPrincipalErrorV1> {
        toml::from_str::<LocalPrincipalDocumentV1>(text)
            .ok()
            .and_then(|document| {
                let principal = Ulid::from_string(&document.principal_id)
                    .ok()
                    .and_then(|id| {
                        PrincipalRefV1::try_new(id.to_bytes(), document.trust_domain).ok()
                    });
                let actors = document
                    .actor_entity_ids
                    .iter()
                    .map(|text| Ulid::from_string(text).ok().map(EntityId::from_ulid))
                    .collect::<Option<Vec<_>>>();
                let operations = document
                    .operations
                    .iter()
                    .map(|name| GatewayOperationV1::named(name))
                    .collect::<Option<Vec<_>>>();
                principal.zip(actors).zip(operations)
            })
            .ok_or(LocalPrincipalErrorV1::Invalid)
            .and_then(|((principal, actors), operations)| {
                Self::try_new(&principal, actors, operations)
            })
    }
}

/// Persist `provision` as the store's one Local Principal.
///
/// Its root capability grant commits under a permit of the
/// [`AuthorityPersistenceHostV1`] its registry snapshot attests. An exact
/// retry is [`AuthorityCommitOutcomeV1::Unchanged`].
///
/// # Errors
/// Returns [`LocalPrincipalErrorV1::Conflict`] when the store already holds
/// a different Local Principal, and [`LocalPrincipalErrorV1::Unavailable`]
/// when the store is bound to another host or cannot commit.
pub fn provision_local_principal<S>(
    store: &mut S,
    provision: &LocalPrincipalProvisionV1,
) -> Result<AuthorityCommitOutcomeV1, LocalPrincipalErrorV1>
where
    S: AuthorityPersistencePortV1 + ?Sized,
{
    let host = AuthorityPersistenceHostV1::new(&provision.registry);
    store
        .bind_authority_persistence(host.persistence_binding())
        .and_then(|()| host.authorize_grant(&provision.grant))
        .and_then(|permit| store.issue_capability_grant(permit, &provision.grant))
        .map_err(persistence_failure)
}

/// Provision the Local Principal of the systemd credential in
/// `credential_directory` into the `SQLite` store at `sqlite_path`; an exact
/// retry succeeds unchanged.
///
/// The directory must hold exactly [`LOCAL_PRINCIPAL_CREDENTIAL_NAME`], with
/// the custody checks of the Fork-authority credentials.
///
/// # Errors
/// Returns an error when the credential is unavailable or invalid, or when
/// the store cannot be opened or provisioned.
#[cfg(target_os = "linux")]
pub fn provision_local_principal_from_credentials(
    sqlite_path: &str,
    credential_directory: &Path,
) -> io::Result<()> {
    crate::local_fork_authentication::read_single_credential(
        credential_directory,
        LOCAL_PRINCIPAL_CREDENTIAL_NAME,
        rustix::process::geteuid().as_raw(),
        MAX_LOCAL_PRINCIPAL_CREDENTIAL_BYTES,
    )
    .map_err(io::Error::other)
    .and_then(|bytes| {
        std::str::from_utf8(&bytes)
            .map_err(io::Error::other)
            .and_then(|text| LocalPrincipalProvisionV1::from_toml(text).map_err(io::Error::other))
    })
    .and_then(|provision| {
        // An offline writer (ADR-134 §8): under the shared mode lock, attach
        // the store's binding before writing; it never binds.
        crate::mode_profile::GatewayModeStoreLockV1::shared(sqlite_path)
            .map_err(io::Error::other)
            .and_then(|lock| {
                let provisioned = pos_store::sqlite::SqliteStore::open(sqlite_path)
                    .map_err(io::Error::other)
                    .and_then(|mut store| {
                        crate::mode_profile::attach_offline_writer_v1(&mut store)
                            .map_err(io::Error::other)
                            .and_then(|_| {
                                provision_local_principal(&mut store, &provision)
                                    .map(|_| ())
                                    .map_err(io::Error::other)
                            })
                    });
                drop(lock);
                provisioned
            })
    })
}

/// Compose the Local Principal recorded in `store` as the Gateway
/// authorizer, or `None` when the store has none (an unprovisioned host).
///
/// Reading never writes the store.
///
/// # Errors
/// Returns [`LocalPrincipalErrorV1::Unavailable`] when the store cannot be
/// read, and [`LocalPrincipalErrorV1::Corrupt`] when its authority records
/// are invalid or hold a Local Principal record this host cannot
/// recompose exactly. Only a store that records no Local Principal grant (a
/// store resolves no chain for an absent leaf, and it validates every
/// recorded grant's chain on write) is unprovisioned.
pub fn load_local_principal<S>(
    store: &S,
) -> Result<Option<GatewayAuthorization>, LocalPrincipalErrorV1>
where
    S: AuthorityPersistencePortV1 + ?Sized,
{
    match store.load_authority(local_principal_grant_id()) {
        // The store resolves no chain for an absent leaf grant.
        Err(AuthorityPersistenceErrorV1::Conflict) => Ok(None),
        Err(AuthorityPersistenceErrorV1::Unavailable) => Err(LocalPrincipalErrorV1::Unavailable),
        Err(_) => Err(LocalPrincipalErrorV1::Corrupt),
        Ok(persisted) => compose(&persisted)
            .map(Some)
            .ok_or(LocalPrincipalErrorV1::Corrupt),
    }
}

/// Compose the Local Principal recorded in the store of `host`.
///
/// # Errors
/// Returns an error when the host is not ready or its authority records are
/// unavailable.
pub fn load_host_local_principal(
    host: &mut ErasureExecutionHostV1,
    mode: &crate::mode_profile::GatewayModeBindingV1,
) -> io::Result<Option<GatewayAuthorization>> {
    mode.verify_host(host)
        .map_err(io::Error::other)
        .and_then(|()| {
            host.command_sender()
                .and_then(|mut sender| {
                    sender.with_scheduled_admission(|ports| load_local_principal(&*ports))
                })
                .map_err(erasure_host_failure)
        })
        .and_then(|loaded| loaded.map_err(io::Error::other))
        .and_then(|authorization| {
            authorization
                .map(|authorization| authorization.with_mode_binding(mode))
                .transpose()
                .map_err(io::Error::other)
        })
}

/// The production serve composition (D1) of the Gateway over `host`, bound
/// to the execution mode `mode` the host's store records.
///
/// It accepts authenticated local `OwnTracks` ingress when
/// `owntracks_owner_key` is given, and every protected operation requires
/// the Local Principal recorded in the host's store.
///
/// # Errors
/// Returns an error when the host's store is not bound to `mode`, the
/// authority records are unavailable, or the Gateway cannot bind the host.
pub fn local_gateway(
    mut host: ErasureExecutionHostV1,
    owntracks_owner_key: Option<&OwnTracksOwnerKey>,
    mode: &crate::mode_profile::GatewayModeBindingV1,
) -> io::Result<Gateway> {
    load_host_local_principal(&mut host, mode).and_then(|authorization| {
        match (owntracks_owner_key, host) {
            (Some(owner_key), host) => {
                Gateway::new_with_owntracks_erasure_host(host, owner_key, authorization)
            }
            (None, host) => Gateway::new_with_erasure_host(host, authorization),
        }
        .map_err(io::Error::other)
    })
}

/// The source a Local Principal authorizer recomposes itself from: the
/// store's record under the one Local Principal grant identity.
struct LocalPrincipalSourceV1;

impl GatewayAuthoritySourceV1 for LocalPrincipalSourceV1 {
    fn leaf_grant_id(&self) -> Hash {
        local_principal_grant_id()
    }

    fn recompose(
        &self,
        persisted: &PersistedAuthorityV1,
    ) -> Option<(AuthorityViewV1, AuthorityRegistrySnapshotV1)> {
        recompose(persisted).map(|(view, registry, _)| (view, registry))
    }
}

/// The authorizer of one recorded Local Principal chain, which brings
/// itself current with the store's record before each decision.
fn compose(persisted: &PersistedAuthorityV1) -> Option<GatewayAuthorization> {
    recompose(persisted).map(|(view, registry, evidence)| {
        GatewayAuthorization::new(
            Arc::new(LocalAuthenticationAdapter::new(evidence)),
            view,
            registry,
        )
        .with_source(Arc::new(LocalPrincipalSourceV1))
    })
}

/// Recompose the view, attesting registry and pinned evidence of one
/// recorded Local Principal chain.
///
/// The record is the as-issued root grant plus the revocations the store
/// holds on its authority Timeline; a chain this host cannot reproduce
/// exactly is refused, never merged.
fn recompose(
    persisted: &PersistedAuthorityV1,
) -> Option<(
    AuthorityViewV1,
    AuthorityRegistrySnapshotV1,
    AuthenticatedPrincipalResultV1,
)> {
    persisted
        .chain()
        .grants()
        .first()
        .and_then(|root| {
            as_issued(root)
                .and_then(|grant| {
                    authority_for(&grant, root)
                        .map(|(evidence, registry)| (grant, evidence, registry))
                })
                .ok()
        })
        .and_then(|(grant, evidence, registry)| {
            let host = AuthorityPersistenceHostV1::new(&registry);
            let mut state = AuthorityPersistenceStateV1::new();
            host.authorize_grant(&grant)
                .and_then(|permit| state.issue_grant(permit, grant.clone()))
                .and_then(|_| {
                    persisted.revocations().iter().try_for_each(|revocation| {
                        host.authorize_revocation(&grant, revocation)
                            .and_then(|permit| state.revoke_grant(permit, revocation.clone()))
                            .map(|_| ())
                    })
                })
                .and_then(|()| state.view(grant.grant_id()))
                .ok()
                .filter(|view| view.authority() == persisted)
                .map(|view| (view, registry, evidence))
        })
}

/// The grant as provisioned: a resolved chain carries the store's current
/// revocation epoch and fence, which the as-issued record never holds.
fn as_issued(grant: &CapabilityGrantV1) -> Result<CapabilityGrantV1, AuthorityErrorV1> {
    CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: grant.grant_id(),
        grantor: grant.grantor().clone(),
        grantee: grant.grantee().clone(),
        trust_domain: grant.trust_domain().to_owned(),
        scope: grant.scope().clone(),
        valid_from_position: grant.valid_from_position(),
        valid_until_position: grant.valid_until_position(),
        parent_grant_id: grant.parent_grant_id(),
        delegation_depth: grant.delegation_depth(),
        max_delegation_depth: grant.max_delegation_depth(),
        permitted_delegate_classes: grant.permitted_delegate_classes().to_vec(),
        consent_references: grant.consent_references().to_vec(),
        policy_revision: grant.policy_revision(),
        issuance_timeline: grant.issuance_timeline(),
        issuance_seq: grant.issuance_seq(),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: grant.authority_registry_digest(),
    })
}

/// The Local Principal's pinned authentication evidence and the registry
/// snapshot that attests it, the as-issued `grant` and its `current`
/// recorded form; all are functions of the recorded grant.
///
/// A recorded revocation changes the grant's resolved form, so attesting it
/// lets the evaluator answer a revoked Principal `revoked` rather than
/// `unauthorized`. The evidence has no expiry: loopback reachability, not a
/// credential, is the Local trust boundary (D1), so it is valid from the
/// epoch on.
fn authority_for(
    grant: &CapabilityGrantV1,
    current: &CapabilityGrantV1,
) -> Result<(AuthenticatedPrincipalResultV1, AuthorityRegistrySnapshotV1), AuthorityErrorV1> {
    AssuranceLevelV1::try_new(1)
        .and_then(|assurance| {
            AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
                principal: grant.grantee().principal().clone(),
                adapter_id: LOCAL_ADAPTER_ID.to_owned(),
                assurance,
                issued_at: WallTime::from_micros(0),
                expires_at: WallTime::from_micros(u64::MAX),
                binding_digest: grant.authority_registry_digest(),
            })
        })
        .and_then(|evidence| {
            [grant, current]
                .into_iter()
                .map(CapabilityGrantV1::binding_digest)
                .collect::<Result<Vec<_>, _>>()
                .and_then(|mut bindings| {
                    bindings.sort_unstable();
                    bindings.dedup();
                    AuthorityRegistrySnapshotV1::try_new(
                        grant.authority_registry_digest(),
                        vec![evidence.registry_binding_digest()],
                        bindings,
                        Vec::new(),
                    )
                })
                .map(|registry| (evidence, registry))
        })
}

/// A Local Principal store fault: a different recorded Principal conflicts,
/// every other failure is unavailable.
const fn persistence_failure(error: AuthorityPersistenceErrorV1) -> LocalPrincipalErrorV1 {
    match error {
        AuthorityPersistenceErrorV1::Conflict
        | AuthorityPersistenceErrorV1::StaleEpoch
        | AuthorityPersistenceErrorV1::TimelineOrder => LocalPrincipalErrorV1::Conflict,
        AuthorityPersistenceErrorV1::InvalidRecord | AuthorityPersistenceErrorV1::Unavailable => {
            LocalPrincipalErrorV1::Unavailable
        }
    }
}

/// The registry digest committing to one whole provisioning document.
fn registry_digest(
    principal: &PrincipalRefV1,
    actors: &[EntityId],
    operations: &[GatewayOperationV1],
) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key("pigloros gateway local principal registry v1");
    hasher.update(principal.principal_id());
    framed(&mut hasher, principal.trust_domain().as_bytes());
    hasher.update(&(actors.len() as u64).to_be_bytes());
    for actor in actors {
        hasher.update(&actor.inner().to_bytes());
    }
    hasher.update(&(operations.len() as u64).to_be_bytes());
    for operation in operations {
        framed(&mut hasher, operation.name().as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn framed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn derived_hash(context: &str) -> Hash {
    Hash::from_bytes(blake3::derive_key(context, &[]))
}

/// The one grant identity a store's Local Principal is recorded under.
fn local_principal_grant_id() -> Hash {
    derived_hash("pigloros gateway local principal grant v1")
}

/// The authority Timeline the Local Principal's grant is issued on.
fn local_principal_authority_timeline() -> TimelineId {
    let digest = blake3::derive_key(
        "pigloros gateway local principal authority timeline v1",
        &[],
    );
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    TimelineId::from_ulid(Ulid::from_bytes(identity))
}

const fn operation_name(operation: &GatewayOperationV1) -> &'static str {
    operation.name()
}

fn sorted_set<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut values = values.map(str::to_owned).collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use piglor_ledger::LedgerView;
    use pos_core::{
        AuthorityViewV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
        ErasureRecoveryLimitsV1,
    };
    use pos_runtime::ErasureCoordinatorCompositionV1;
    use pos_store::{memory::MemoryStore, sqlite::SqliteStore, StoreConfig};
    use serde_json::{json, Value};
    use std::time::Duration;
    use tower::ServiceExt;

    use crate::{
        operation::{CreateTimelineOperation, OperationAuthority, ACTOR_ENTITY_HEADER},
        router,
        startup::{open_recovered_erasure_host, GatewayHostStoreV1},
        AppState, GatewayError, LedgerWriteMode,
    };
    use axum::response::IntoResponse;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    const PRINCIPAL: &str = "01JC0GATEWAYQ0CA1PR1NC1PA1";
    const ACTOR: &str = "01JC0GATEWAYQ0CA1ACT0R0000";

    fn principal() -> TestResult<PrincipalRefV1> {
        Ok(PrincipalRefV1::try_new(
            Ulid::from_string(PRINCIPAL)?.to_bytes(),
            "local",
        )?)
    }

    fn actor() -> TestResult<EntityId> {
        Ok(EntityId::from_ulid(Ulid::from_string(ACTOR)?))
    }

    fn provision(
        operations: impl IntoIterator<Item = GatewayOperationV1>,
    ) -> TestResult<LocalPrincipalProvisionV1> {
        Ok(LocalPrincipalProvisionV1::try_new(
            &principal()?,
            [actor()?],
            operations,
        )?)
    }

    /// The Principal of the HTTP cases: Timelines, signals and reads, no
    /// predictions and no actions.
    fn served_provision() -> TestResult<LocalPrincipalProvisionV1> {
        provision([
            GatewayOperationV1::CREATE_TIMELINE,
            GatewayOperationV1::APPEND_SIGNAL,
            GatewayOperationV1::READ_EVENTS,
        ])
    }

    fn document(actors: &str, operations: &str) -> String {
        format!(
            "principal_id = \"{PRINCIPAL}\"\ntrust_domain = \"local\"\n\
             actor_entity_ids = [{actors}]\noperations = [{operations}]\n"
        )
    }

    fn loaded(provision: &LocalPrincipalProvisionV1) -> TestResult<GatewayAuthorization> {
        let mut store = MemoryStore::new();
        provision_local_principal(&mut store, provision)?;
        load_local_principal(&store)?.ok_or_else(|| "a provisioned store recomposes".into())
    }

    fn revocation(grant: &CapabilityGrantV1) -> TestResult<CapabilityRevocationV1> {
        Ok(CapabilityRevocationV1::try_from_draft(
            CapabilityRevocationDraftV1 {
                grant_id: grant.grant_id(),
                authority_timeline: grant.issuance_timeline(),
                fence_position: Seq::from_u64(2),
                revocation_epoch: 1,
                policy_revision: grant.policy_revision(),
                authority_registry_digest: grant.authority_registry_digest(),
            },
        )?)
    }

    fn revoked_view(provision: &LocalPrincipalProvisionV1) -> TestResult<AuthorityViewV1> {
        let host = AuthorityPersistenceHostV1::new(&provision.registry);
        let mut state = AuthorityPersistenceStateV1::new();
        state.issue_grant(
            host.authorize_grant(&provision.grant)?,
            provision.grant.clone(),
        )?;
        let revocation = revocation(&provision.grant)?;
        state.revoke_grant(
            host.authorize_revocation(&provision.grant, &revocation)?,
            revocation,
        )?;
        Ok(state.view(provision.grant.grant_id())?)
    }

    fn memory_host() -> TestResult<ErasureExecutionHostV1> {
        Ok(ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?)
    }

    fn app_of(gateway: Gateway) -> Router {
        router(AppState {
            gateway,
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        })
    }

    /// An in-memory Gateway that requires `authorization`; `None` is an
    /// unprovisioned host.
    fn served(authorization: Option<GatewayAuthorization>) -> TestResult<(Gateway, Router)> {
        let gateway = Gateway::new_with_erasure_host(memory_host()?, authorization)?;
        Ok((gateway.clone(), app_of(gateway)))
    }

    fn sqlite_path(directory: &tempfile::TempDir) -> TestResult<String> {
        Ok(directory
            .path()
            .join("gateway.db")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned())
    }

    /// Bind the empty store at `path` to `id`, as the first `serve` does, and
    /// return the handle `serve` composes with.
    fn bind_mode(
        path: &str,
        id: crate::mode_profile::GatewayModeProfileIdV1,
    ) -> TestResult<crate::mode_profile::GatewayModeBindingV1> {
        crate::mode_profile::bind_test_store(&mut SqliteStore::open(path)?, id)?;
        Ok(crate::mode_profile::test_binding(id, []))
    }

    fn bind_local(path: &str) -> TestResult<crate::mode_profile::GatewayModeBindingV1> {
        bind_mode(path, crate::mode_profile::GatewayModeProfileIdV1::Local)
    }

    fn sqlite_host(path: &str) -> TestResult<ErasureExecutionHostV1> {
        Ok(open_recovered_erasure_host(
            StoreConfig::Sqlite {
                path: path.to_owned(),
            },
            GatewayHostStoreV1::Standard,
            &ErasureCoordinatorCompositionV1::closed(),
        )?)
    }

    /// A `SQLite` store provisioned with one Local Principal and served by the
    /// production composition.
    struct Served {
        _directory: tempfile::TempDir,
        path: String,
        gateway: Gateway,
        app: Router,
    }

    impl Served {
        fn authorization(&self) -> TestResult<Arc<GatewayAuthorization>> {
            Ok(self
                .gateway
                .authorization
                .clone()
                .ok_or("a provisioned host has an authorizer")?)
        }
    }

    fn served_store(provision: &LocalPrincipalProvisionV1) -> TestResult<Served> {
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        let mode = bind_local(&path)?;
        provision_local_principal(&mut SqliteStore::open(&path)?, provision)?;
        let gateway = local_gateway(sqlite_host(&path)?, None, &mode)?;
        Ok(Served {
            _directory: directory,
            path,
            app: app_of(gateway.clone()),
            gateway,
        })
    }

    /// Record the revocation of the Local Principal's grant, as an offline
    /// writer would, through a separate adapter of the store.
    fn record_revocation(path: &str, provision: &LocalPrincipalProvisionV1) -> TestResult {
        let host = AuthorityPersistenceHostV1::new(&provision.registry);
        let mut store = SqliteStore::open(path)?;
        store.bind_authority_persistence(host.persistence_binding())?;
        let revocation = revocation(&provision.grant)?;
        store.revoke_capability_grant(
            host.authorize_revocation(&provision.grant, &revocation)?,
            &revocation,
        )?;
        Ok(())
    }

    /// A copy of `grant` with another identity, issuance and epoch.
    fn reissued(
        grant: &CapabilityGrantV1,
        grant_id: Hash,
        issuance: u64,
        revocation_epoch: u64,
    ) -> TestResult<CapabilityGrantV1> {
        Ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id,
            grantor: grant.grantor().clone(),
            grantee: grant.grantee().clone(),
            trust_domain: grant.trust_domain().to_owned(),
            scope: grant.scope().clone(),
            valid_from_position: Seq::from_u64(issuance),
            valid_until_position: grant.valid_until_position(),
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            permitted_delegate_classes: Vec::new(),
            consent_references: Vec::new(),
            policy_revision: grant.policy_revision(),
            issuance_timeline: grant.issuance_timeline(),
            issuance_seq: Seq::from_u64(issuance),
            revocation_epoch,
            revocation_fence: None,
            authority_registry_digest: grant.authority_registry_digest(),
        })?)
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        actor: Option<EntityId>,
        body: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("idempotency-key", "local-principal");
        if let Some(actor) = actor {
            builder = builder.header(ACTOR_ENTITY_HEADER, actor.to_string());
        }
        let request = builder
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))?;
        let response = app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    }

    async fn create(app: &Router, actor: Option<EntityId>) -> TestResult<(StatusCode, Value)> {
        send(
            app,
            "POST",
            "/v1/timelines",
            actor,
            Some(json!({"name": "local-principal"})),
        )
        .await
    }

    fn signal(actor: EntityId) -> Value {
        json!({"entity_id": actor.to_string(), "dimension": "trust", "value": 0.5})
    }

    fn prediction() -> Value {
        json!({
            "title": "Test",
            "statement": "Something will happen",
            "predicted_outcome": "Yes",
            "confidence": 0.75,
            "made_at": "2026-07-26T12:00:00Z",
            "resolve_by": "2026-08-01",
            "osf_link": "https://osf.io/test"
        })
    }

    fn action(actor: EntityId) -> Value {
        json!({
            "entity_id": actor.to_string(),
            "event_type": "world.action.v1",
            "capability": "world.action.v1.submit",
            "payload": {
                "actor_entity_id": actor.to_string(),
                "body_entity_id": actor.to_string(),
                "action_kind": "impulse",
                "params": [0.5, 0.25],
                "action_scope": 0,
                "catalogue_version": 1,
                "tick": 1
            }
        })
    }

    /// A store whose every authority operation fails with one error.
    struct FailingStore(AuthorityPersistenceErrorV1);

    impl AuthorityPersistencePortV1 for FailingStore {
        fn bind_authority_persistence(
            &mut self,
            _binding: pos_core::AuthorityPersistenceBindingV1,
        ) -> Result<(), AuthorityPersistenceErrorV1> {
            Ok(())
        }

        fn issue_capability_grant(
            &mut self,
            _permit: pos_core::AuthorityMutationPermitV1,
            _grant: &CapabilityGrantV1,
        ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn revoke_capability_grant(
            &mut self,
            _permit: pos_core::AuthorityMutationPermitV1,
            _revocation: &CapabilityRevocationV1,
        ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn load_authority(
            &self,
            _leaf_grant_id: Hash,
        ) -> Result<PersistedAuthorityV1, AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn record_authorization_denial(
            &mut self,
            _permit: pos_core::AuthorizationDenialPermitV1,
        ) -> Result<(), AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn load_authorization_denials(
            &self,
            _after: u64,
            _limit: usize,
        ) -> Result<Vec<(u64, pos_core::AuthorizationDenialEvidenceV1)>, AuthorityPersistenceErrorV1>
        {
            Err(self.0)
        }
    }

    #[test]
    fn the_toml_document_names_exactly_the_granted_operations() -> TestResult {
        let parsed = LocalPrincipalProvisionV1::from_toml(&document(
            &format!("\"{ACTOR}\", \"{ACTOR}\""),
            "\"timeline.events.read\", \"timeline.create\", \"timeline.create\"",
        ))?;
        let built = provision([
            GatewayOperationV1::CREATE_TIMELINE,
            GatewayOperationV1::READ_EVENTS,
        ])?;
        assert_eq!(parsed, built);
        let scope = built.grant.scope();
        assert_eq!(scope.resources(), ["timeline", "timeline.events"]);
        assert_eq!(scope.actions(), ["create", "read"]);
        assert_eq!(scope.purposes(), ["operation", "read"]);
        assert_eq!(scope.actor_entity_ids(), [actor()?]);
        // No participant is ever granted, so a signal acting as another
        // entity than its header actor can never be covered (M4).
        assert!(scope.participant_ids().is_empty());
        assert_eq!(built.grant.grant_id(), local_principal_grant_id());
        // The registry digest commits to the whole document: every field,
        // even at equal set sizes.
        assert_eq!(MAX_LOCAL_PRINCIPAL_CREDENTIAL_BYTES, 16_384);
        let digest =
            |provision: &LocalPrincipalProvisionV1| provision.grant.authority_registry_digest();
        let create = provision([GatewayOperationV1::CREATE_TIMELINE])?;
        for other in [
            provision([GatewayOperationV1::READ_EVENTS])?,
            LocalPrincipalProvisionV1::try_new(
                &PrincipalRefV1::try_new(Ulid::from_string(PRINCIPAL)?.to_bytes(), "other")?,
                [actor()?],
                [GatewayOperationV1::CREATE_TIMELINE],
            )?,
            LocalPrincipalProvisionV1::try_new(
                &principal()?,
                [EntityId::new()],
                [GatewayOperationV1::CREATE_TIMELINE],
            )?,
            served_provision()?,
        ] {
            assert_ne!(digest(&create), digest(&other));
        }
        Ok(())
    }

    #[test]
    fn malformed_or_empty_documents_are_refused() -> TestResult {
        let actor = format!("\"{ACTOR}\"");
        let create = "\"timeline.create\"";
        for text in [
            "principal_id = ".to_owned(),
            format!("{}extra = 1\n", document(&actor, create)),
            document(&actor, create).replace(PRINCIPAL, "not-a-ulid"),
            document(&actor, create).replace(PRINCIPAL, "00000000000000000000000000"),
            document("\"not-a-ulid\"", create),
            document(&actor, "\"timeline.delete\""),
            document(&actor, ""),
            document("", create),
        ] {
            assert_eq!(
                LocalPrincipalProvisionV1::from_toml(&text),
                Err(LocalPrincipalErrorV1::Invalid),
                "{text}"
            );
        }
        let too_many = (0..33_u128).map(|index| EntityId::from_ulid(Ulid(index + 1)));
        assert_eq!(
            LocalPrincipalProvisionV1::try_new(
                &principal()?,
                too_many,
                [GatewayOperationV1::CREATE_TIMELINE]
            ),
            Err(LocalPrincipalErrorV1::Invalid)
        );
        Ok(())
    }

    #[test]
    fn provisioning_is_explicit_idempotent_and_holds_one_principal() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("gateway.db")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        let served = served_provision()?;
        // Nothing is provisioned implicitly.
        assert!(load_local_principal(&SqliteStore::open(&path)?)?.is_none());
        assert_eq!(
            provision_local_principal(&mut SqliteStore::open(&path)?, &served)?,
            AuthorityCommitOutcomeV1::Committed
        );
        assert_eq!(
            provision_local_principal(&mut SqliteStore::open(&path)?, &served)?,
            AuthorityCommitOutcomeV1::Unchanged
        );
        let conflict = provision_local_principal(
            &mut SqliteStore::open(&path)?,
            &provision([GatewayOperationV1::CREATE_TIMELINE])?,
        );
        assert_eq!(conflict, Err(LocalPrincipalErrorV1::Conflict));
        // The refusal says how to recover.
        assert!(LocalPrincipalErrorV1::Conflict
            .to_string()
            .contains("create a new store"));
        assert!(load_local_principal(&SqliteStore::open(&path)?)?.is_some());
        Ok(())
    }

    #[test]
    fn store_faults_map_to_closed_failures() -> TestResult {
        let provision = served_provision()?;
        for (error, expected) in [
            (
                AuthorityPersistenceErrorV1::Conflict,
                LocalPrincipalErrorV1::Conflict,
            ),
            (
                AuthorityPersistenceErrorV1::StaleEpoch,
                LocalPrincipalErrorV1::Conflict,
            ),
            (
                AuthorityPersistenceErrorV1::TimelineOrder,
                LocalPrincipalErrorV1::Conflict,
            ),
            (
                AuthorityPersistenceErrorV1::InvalidRecord,
                LocalPrincipalErrorV1::Unavailable,
            ),
            (
                AuthorityPersistenceErrorV1::Unavailable,
                LocalPrincipalErrorV1::Unavailable,
            ),
        ] {
            let mut store = FailingStore(error);
            assert_eq!(
                provision_local_principal(&mut store, &provision),
                Err(expected)
            );
            assert!(store
                .revoke_capability_grant(
                    AuthorityPersistenceHostV1::new(&provision.registry)
                        .authorize_grant(&provision.grant)?,
                    &revocation(&provision.grant)?
                )
                .is_err());
            assert!(store
                .record_authorization_denial(
                    AuthorityPersistenceHostV1::new(&provision.registry).authorize_denial(
                        pos_core::AuthorizationDenialEvidenceV1::Suppressed(
                            pos_core::AuthorizationDenialSuppressionV1::try_new(
                                pos_core::AuthorizationDenialScopeV1::Host,
                                1
                            )
                            .ok_or("a positive count is a marker")?
                        )
                    )
                )
                .is_err());
            assert!(store.load_authorization_denials(0, 1).is_err());
        }
        assert!(
            load_local_principal(&FailingStore(AuthorityPersistenceErrorV1::Conflict))?.is_none()
        );
        assert_eq!(
            load_local_principal(&FailingStore(AuthorityPersistenceErrorV1::InvalidRecord)).err(),
            Some(LocalPrincipalErrorV1::Corrupt)
        );
        assert_eq!(
            load_local_principal(&FailingStore(AuthorityPersistenceErrorV1::Unavailable)).err(),
            Some(LocalPrincipalErrorV1::Unavailable)
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_unprovisioned_host_answers_every_protected_route_401() -> TestResult {
        let (gateway, app) = served(None)?;
        let actor = actor()?;
        let timeline = gateway.create_timeline("unprovisioned").await?.id();
        for (method, uri, body) in [
            (
                "POST",
                "/v1/timelines".to_owned(),
                Some(json!({"name": "x"})),
            ),
            (
                "POST",
                format!("/v1/timelines/{timeline}/signals"),
                Some(signal(actor)),
            ),
            (
                "POST",
                "/v1/ledger/predictions".to_owned(),
                Some(prediction()),
            ),
            (
                "POST",
                format!("/v1/timelines/{timeline}/actions"),
                Some(action(actor)),
            ),
            ("GET", format!("/v1/timelines/{timeline}/events"), None),
        ] {
            let (status, problem) = send(&app, method, &uri, Some(actor), body).await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(problem["code"], "unauthenticated", "{uri}");
        }
        assert!(matches!(
            gateway.read_events_page(&timeline.to_string(), 0, 1).await,
            Err(GatewayError::AuthorizationUnavailable)
        ));
        assert!(gateway
            .authorize_operation(GatewayOperationV1::CREATE_TIMELINE, Some(actor), None, None)
            .await
            .is_err());
        // The host refuses before any body is read: a malformed or an
        // oversized body is still `401`.
        for body in [
            Body::from("{"),
            Body::from(vec![b' '; crate::MAX_HTTP_BODY_BYTES + 1]),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/timelines")
                        .header("content-type", "application/json")
                        .header(ACTOR_ENTITY_HEADER, actor.to_string())
                        .body(body)?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        // Unprotected routes still answer.
        assert_eq!(
            send(&app, "GET", "/health", None, None).await?.0,
            StatusCode::OK
        );
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    #[tokio::test]
    async fn a_provisioned_principal_is_admitted_only_for_its_grants() -> TestResult {
        let Served {
            _directory,
            gateway,
            app,
            ..
        } = served_store(&served_provision()?)?;
        let actor = actor()?;
        let (status, created) = create(&app, Some(actor)).await?;
        assert_eq!(status, StatusCode::CREATED);
        let timeline = created["id"]
            .as_str()
            .ok_or("a created Timeline has an id")?;

        let (status, problem) = create(&app, None).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem["code"], "unauthenticated");
        let (status, problem) = create(&app, Some(EntityId::new())).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], "unauthorized");

        let signals = format!("/v1/timelines/{timeline}/signals");
        let (status, _) = send(&app, "POST", &signals, Some(actor), Some(signal(actor))).await?;
        assert_eq!(status, StatusCode::CREATED);
        // A signal acts as its own entity, which must be the header actor.
        let (status, problem) = send(
            &app,
            "POST",
            &signals,
            Some(actor),
            Some(signal(EntityId::new())),
        )
        .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], "unauthorized");
        let (status, _) = send(
            &app,
            "POST",
            "/v1/timelines/not-a-timeline/signals",
            Some(actor),
            Some(signal(actor)),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, page) = send(
            &app,
            "GET",
            &format!("/v1/timelines/{timeline}/events"),
            Some(actor),
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["events"].as_array().map(Vec::len), Some(1));

        for (uri, body) in [
            ("/v1/ledger/predictions".to_owned(), prediction()),
            (format!("/v1/timelines/{timeline}/actions"), action(actor)),
        ] {
            let (status, problem) = send(&app, "POST", &uri, Some(actor), Some(body)).await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(problem["code"], "unauthorized", "{uri}");
        }

        let permit = gateway
            .authorize_operation(GatewayOperationV1::CREATE_TIMELINE, Some(actor), None, None)
            .await?;
        assert_eq!(
            permit
                .decision()
                .map(crate::GatewayAuthorizationDecision::actor_entity_id),
            Some(actor)
        );
        drop(permit);
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    #[tokio::test]
    async fn an_unprotected_composition_admits_without_a_decision() -> TestResult {
        let gateway = Gateway::unprotected_for_harness(memory_host()?)?;
        let permit = gateway
            .authorize_operation(GatewayOperationV1::CREATE_TIMELINE, None, None, None)
            .await?;
        assert!(permit.decision().is_none());
        drop(permit);
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    #[tokio::test]
    async fn a_revocation_takes_effect_before_the_next_mutation() -> TestResult {
        let provision = served_provision()?;
        let Served {
            _directory,
            gateway,
            app,
            ..
        } = served_store(&provision)?;
        let authorization = gateway
            .authorization
            .clone()
            .ok_or("a provisioned host has an authorizer")?;
        let actor = actor()?;
        assert_eq!(create(&app, Some(actor)).await?.0, StatusCode::CREATED);

        // An admitted operation holds the authority fence: the replacement
        // waits for it and never lands under it.
        let permit = gateway
            .authorize_operation(GatewayOperationV1::CREATE_TIMELINE, Some(actor), None, None)
            .await?;
        let revoked = revoked_view(&provision)?;
        let replacing = authorization.clone();
        let replacement = tokio::spawn(async move { replacing.replace_authority(revoked).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!replacement.is_finished());
        drop(permit);
        replacement.await??;

        // The next mutation is denied as revoked and commits nothing; the
        // older store record never rolls the revocation back.
        let (status, problem) = create(&app, Some(actor)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], "revoked");
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    #[tokio::test]
    async fn a_revocation_recorded_while_serving_is_current_at_the_next_decision() -> TestResult {
        let provision = served_provision()?;
        let served = served_store(&provision)?;
        let actor = actor()?;
        assert_eq!(
            create(&served.app, Some(actor)).await?.0,
            StatusCode::CREATED
        );
        record_revocation(&served.path, &provision)?;
        let (status, problem) = create(&served.app, Some(actor)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], "revoked");
        served.gateway.shutdown().await?;
        drop(served);
        Ok(())
    }

    #[tokio::test]
    async fn a_cancelled_request_keeps_its_admitted_mutation_ahead_of_a_revocation() -> TestResult {
        let provision = served_provision()?;
        let served = served_store(&provision)?;
        let authorization = served.authorization()?;
        let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (release, release_rx) = tokio::sync::oneshot::channel::<()>();
        let mut request = Box::pin(
            OperationAuthority::<CreateTimelineOperation>::for_test(Some(actor()?)).run(
                &served.gateway,
                None,
                move |gateway| async move {
                    match started.send(()) {
                        Ok(()) | Err(()) => {}
                    }
                    drop(release_rx.await);
                    gateway.create_timeline("admitted").await
                },
            ),
        );
        tokio::select! {
            _ = &mut request => return Err("the admitted mutation waits for its release".into()),
            admitted = started_rx => admitted?,
        }
        // The client goes away after the decision; the mutation keeps the
        // fence, so the revocation lands only after it completes.
        drop(request);
        let revoked = revoked_view(&provision)?;
        let replacement =
            tokio::spawn(async move { authorization.replace_authority(revoked).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!replacement.is_finished());
        match release.send(()) {
            Ok(()) | Err(()) => {}
        }
        replacement.await??;
        let (status, problem) = create(&served.app, Some(actor()?)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], "revoked");
        served.gateway.shutdown().await?;
        drop(served);
        Ok(())
    }

    #[tokio::test]
    async fn an_authorizer_without_a_readable_store_fails_closed() -> TestResult {
        let gateway = Gateway::new_with_world_bodies_and_authorization(
            pos_store::open_store(StoreConfig::Memory)?,
            std::iter::empty(),
            loaded(&served_provision()?)?,
        );
        // An unreadable authority store is stale revocation state: `503`
        // and retryable, never `401` (D3); here its denial evidence cannot
        // be recorded either.
        let refused = gateway
            .authorize_operation(
                GatewayOperationV1::CREATE_TIMELINE,
                Some(actor()?),
                None,
                None,
            )
            .await
            .err()
            .ok_or("an unreadable store admits nothing")?;
        assert!(matches!(
            refused,
            GatewayError::AuthorizationEvidenceUnavailable
        ));
        assert_eq!(
            refused.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    #[test]
    fn only_a_store_record_ahead_of_the_pinned_chain_is_reloaded() -> TestResult {
        let provision = served_provision()?;
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        provision_local_principal(&mut SqliteStore::open(&path)?, &provision)?;
        let authorization =
            load_local_principal(&SqliteStore::open(&path)?)?.ok_or("provisioned")?;
        let recorded = SqliteStore::open(&path)?.load_authority(local_principal_grant_id())?;
        assert!(!authorization.is_behind(&recorded));
        record_revocation(&path, &provision)?;
        let revoked = SqliteStore::open(&path)?.load_authority(local_principal_grant_id())?;
        assert!(authorization.is_behind(&revoked));
        Ok(())
    }

    #[tokio::test]
    async fn an_older_record_never_rolls_a_newer_pin_back() -> TestResult {
        let provision = served_provision()?;
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        provision_local_principal(&mut SqliteStore::open(&path)?, &provision)?;
        let authorization =
            load_local_principal(&SqliteStore::open(&path)?)?.ok_or("provisioned")?;
        let older = SqliteStore::open(&path)?.load_authority(local_principal_grant_id())?;
        record_revocation(&path, &provision)?;
        let newer = SqliteStore::open(&path)?.load_authority(local_principal_grant_id())?;
        authorization.refresh(&newer).await?;
        assert!(!authorization.is_behind(&newer));
        // A refresh that read the store before the revocation lands later.
        authorization.refresh(&older).await?;
        assert!(!authorization.is_behind(&newer));
        Ok(())
    }

    #[tokio::test]
    async fn a_current_pin_decides_alongside_an_admitted_operation() -> TestResult {
        let served = served_store(&served_provision()?)?;
        let actor = actor()?;
        let admitted = served
            .gateway
            .authorize_operation(GatewayOperationV1::CREATE_TIMELINE, Some(actor), None, None)
            .await?;
        // The store is not ahead, so the next decision takes no write guard
        // and never queues behind the admitted operation.
        let next = tokio::time::timeout(
            Duration::from_secs(5),
            served.gateway.authorize_operation(
                GatewayOperationV1::CREATE_TIMELINE,
                Some(actor),
                None,
                None,
            ),
        )
        .await??;
        drop(next);
        drop(admitted);
        served.gateway.shutdown().await?;
        drop(served);
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_abandons_a_hung_mutation_at_its_deadline() -> TestResult {
        let served = served_store(&served_provision()?)?;
        let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
        let gateway = served.gateway.clone();
        let hung = tokio::spawn(async move {
            OperationAuthority::<CreateTimelineOperation>::for_test(Some(actor()?))
                .run(&gateway, None, move |_gateway| async move {
                    match started.send(()) {
                        Ok(()) | Err(()) => {}
                    }
                    std::future::pending::<Result<(), GatewayError>>().await
                })
                .await
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })
        });
        started_rx.await?;
        tokio::time::timeout(
            crate::executor::SHUTDOWN_DEADLINE + Duration::from_secs(10),
            served.gateway.shutdown(),
        )
        .await??;
        hung.abort();
        drop(served);
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_waits_for_an_admitted_mutation() -> TestResult {
        let served = served_store(&served_provision()?)?;
        let (release, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (started, started_rx) = tokio::sync::oneshot::channel::<()>();
        let gateway = served.gateway.clone();
        let request = tokio::spawn(async move {
            OperationAuthority::<CreateTimelineOperation>::for_test(Some(actor()?))
                .run(&gateway, None, move |gateway| async move {
                    match started.send(()) {
                        Ok(()) | Err(()) => {}
                    }
                    drop(release_rx.await);
                    gateway.create_timeline("before-shutdown").await
                })
                .await
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })
        });
        started_rx.await?;
        let stopping = served.gateway.clone();
        let shutdown = tokio::spawn(async move { stopping.shutdown().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!shutdown.is_finished());
        match release.send(()) {
            Ok(()) | Err(()) => {}
        }
        request.await??;
        shutdown.await??;
        drop(served);
        Ok(())
    }

    #[tokio::test]
    async fn a_conflicting_authority_record_fails_startup() -> TestResult {
        let provision = served_provision()?;
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        let mode = bind_local(&path)?;
        // A foreign grant revoked on the Local Principal's authority
        // Timeline before a Local Principal grant was recorded after it.
        let foreign = reissued(&provision.grant, Hash::from_bytes([9; 32]), 1, 0)?;
        let local = reissued(&provision.grant, local_principal_grant_id(), 3, 1)?;
        let mut bindings = vec![foreign.binding_digest()?, local.binding_digest()?];
        bindings.sort_unstable();
        let registry = AuthorityRegistrySnapshotV1::try_new(
            provision.grant.authority_registry_digest(),
            vec![Hash::from_bytes([1; 32])],
            bindings,
            Vec::new(),
        )?;
        let host = AuthorityPersistenceHostV1::new(&registry);
        let mut store = SqliteStore::open(&path)?;
        store.bind_authority_persistence(host.persistence_binding())?;
        store.issue_capability_grant(host.authorize_grant(&foreign)?, &foreign)?;
        let revoked = revocation(&foreign)?;
        store.revoke_capability_grant(host.authorize_revocation(&foreign, &revoked)?, &revoked)?;
        store.issue_capability_grant(host.authorize_grant(&local)?, &local)?;
        assert_eq!(
            load_local_principal(&store).err(),
            Some(LocalPrincipalErrorV1::Corrupt)
        );
        drop(store);
        let error = local_gateway(sqlite_host(&path)?, None, &mode)
            .err()
            .ok_or("a conflicting record never serves")?;
        assert!(error.to_string().contains("restore the store"));
        Ok(())
    }

    #[test]
    fn binary_compositions_never_reach_the_harness_constructor() {
        let production =
            |source: &'static str| source.split("\nmod tests {").next().unwrap_or(source);
        for source in [
            include_str!("main.rs"),
            include_str!("startup.rs"),
            production(include_str!("local_principal.rs")),
            production(include_str!("local_fork_service.rs")),
        ] {
            assert!(!source.contains("unprotected_for_harness"));
        }
    }

    /// ADR-134 §6 and D10: every serve composition binds the authorizer to
    /// the mode it serves, so its admissions carry that mode's revision and
    /// Air-Gapped revocation state is current by construction.
    #[tokio::test]
    async fn every_serve_composition_binds_the_served_mode() -> TestResult {
        use crate::mode_profile::GatewayModeProfileIdV1;
        for id in [
            GatewayModeProfileIdV1::Local,
            GatewayModeProfileIdV1::AirGapped,
        ] {
            for owner_key in [None, Some(OwnTracksOwnerKey([7; 32]))] {
                let directory = tempfile::tempdir()?;
                let path = sqlite_path(&directory)?;
                let mode = bind_mode(&path, id)?;
                provision_local_principal(&mut SqliteStore::open(&path)?, &served_provision()?)?;
                let store = owner_key
                    .as_ref()
                    .map_or(GatewayHostStoreV1::Standard, |_| {
                        GatewayHostStoreV1::OwnTracks
                    });
                let host = open_recovered_erasure_host(
                    StoreConfig::Sqlite { path: path.clone() },
                    store,
                    &ErasureCoordinatorCompositionV1::closed(),
                )?;
                let gateway = local_gateway(host, owner_key.as_ref(), &mode)?;
                let authorization = gateway
                    .authorization
                    .clone()
                    .ok_or("a provisioned host has an authorizer")?;
                let (_, revocation_current, revision) = authorization.execution_profile();
                assert_eq!(revision, Some(&mode.revision_input()));
                assert_eq!(
                    mode.revision_input().revocation_current_by_construction(),
                    id == GatewayModeProfileIdV1::AirGapped
                );
                assert!(revocation_current);
                gateway.shutdown().await?;
                drop(gateway);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_recorded_revocation_is_answered_revoked() -> TestResult {
        let provision = served_provision()?;
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        let mode = bind_local(&path)?;
        provision_local_principal(&mut SqliteStore::open(&path)?, &provision)?;
        record_revocation(&path, &provision)?;
        let gateway = local_gateway(sqlite_host(&path)?, None, &mode)?;
        let app = app_of(gateway.clone());
        let (status, problem) = create(&app, Some(actor()?)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], "revoked");
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    #[tokio::test]
    async fn serve_reads_the_host_store_and_never_rewrites_it() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("gateway.db")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        let open_host = || {
            open_recovered_erasure_host(
                StoreConfig::Sqlite { path: path.clone() },
                GatewayHostStoreV1::Standard,
                &ErasureCoordinatorCompositionV1::closed(),
            )
        };

        // Unprovisioned: protected routes fail closed and nothing is written.
        let mode = bind_local(&path)?;
        let gateway = local_gateway(open_host()?, None, &mode)?;
        assert!(gateway.has_authorization());
        gateway.shutdown().await?;
        drop(gateway);
        assert!(load_local_principal(&SqliteStore::open(&path)?)?.is_none());

        provision_local_principal(&mut SqliteStore::open(&path)?, &served_provision()?)?;
        let recorded = SqliteStore::open(&path)?.load_authority(local_principal_grant_id())?;
        let gateway = local_gateway(open_host()?, None, &mode)?;
        let app = router(AppState {
            gateway: gateway.clone(),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        });
        assert_eq!(create(&app, Some(actor()?)).await?.0, StatusCode::CREATED);
        gateway.shutdown().await?;
        drop(gateway);
        drop(app);
        assert_eq!(
            SqliteStore::open(&path)?.load_authority(local_principal_grant_id())?,
            recorded
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credentials_provision_the_sqlite_store() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let credentials = directory.path().join("credentials");
        std::fs::create_dir(&credentials)?;
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("gateway.db");
        let path = database.to_str().ok_or("temporary path is not UTF-8")?;
        let credential = credentials.join(LOCAL_PRINCIPAL_CREDENTIAL_NAME);
        let install = |bytes: &[u8]| -> TestResult {
            drop(std::fs::remove_file(&credential));
            std::fs::write(&credential, bytes)?;
            std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o400))?;
            Ok(())
        };
        let actor = format!("\"{ACTOR}\"");

        install(&[0xff, 0xfe])?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        install(b"principal_id = ")?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        install(document(&actor, "\"timeline.create\"").as_bytes())?;
        // ADR-134 §8: an offline writer refuses an unbound store and a store
        // `migrate-mode` holds; the first `serve` binds it.
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        crate::mode_profile::bind_test_store(
            &mut SqliteStore::open(path)?,
            crate::mode_profile::GatewayModeProfileIdV1::Local,
        )?;
        let migrating = crate::mode_profile::GatewayModeStoreLockV1::exclusive(path)?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        drop(migrating);
        assert!(load_local_principal(&SqliteStore::open(path)?)?.is_none());
        assert!(provision_local_principal_from_credentials(
            directory
                .path()
                .to_str()
                .ok_or("temporary path is not UTF-8")?,
            &credentials
        )
        .is_err());
        provision_local_principal_from_credentials(path, &credentials)?;
        // An exact retry succeeds unchanged.
        provision_local_principal_from_credentials(path, &credentials)?;
        assert!(load_local_principal(&SqliteStore::open(path)?)?.is_some());

        // The credential bound is 16 KiB, exact: a padded document at the
        // bound is read, one byte over it is refused.
        let padded = |size: usize| -> TestResult<Vec<u8>> {
            let mut text = document(&actor, "\"timeline.create\"").into_bytes();
            let padding = size
                .checked_sub(text.len() + 2)
                .ok_or("the document fits the bound")?;
            text.push(b'#');
            text.extend(std::iter::repeat_n(b'x', padding));
            text.push(b'\n');
            Ok(text)
        };
        install(&padded(MAX_LOCAL_PRINCIPAL_CREDENTIAL_BYTES)?)?;
        provision_local_principal_from_credentials(path, &credentials)?;
        install(&padded(MAX_LOCAL_PRINCIPAL_CREDENTIAL_BYTES + 1)?)?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());

        install(document(&actor, "\"timeline.events.read\"").as_bytes())?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        std::fs::write(credentials.join("extra"), b"")?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        Ok(())
    }
}
