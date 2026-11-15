//! The production Local Principal: explicit provisioning and the authorized
//! serve composition (#1361; owner decisions D1 and D4 on #302).
//!
//! Loopback reachability is the Local trust boundary, and one host-pinned
//! Principal acts behind it (D1). An operator provisions that Principal once,
//! offline, with `piglor-gateway provision-local-principal <sqlite-path>`
//! under its systemd unit (D4). The unit's one credential,
//! [`LOCAL_PRINCIPAL_CREDENTIAL_NAME`], is a TOML document naming the
//! Principal, the entities it may act as and its explicit operation grants,
//! and optionally the consents some of those operations require (#309):
//!
//! ```toml
//! principal_id = "01JC0GATEWAYQ0CA1PR1NC1PA1"
//! trust_domain = "local"
//! actor_entity_ids = ["01JC0GATEWAYQ0CA1ACT0R0000"]
//! operations = ["consent.revoke", "session.read", "timeline.create", "timeline.events.read"]
//!
//! [consent]
//! subject_entity_id = "01JC0GATEWAYQ0CA1ACT0R0000"
//! grantee_entity_id = "01JC0GATEWAYQ0CA1ACT0R0000"
//!
//! [[consent.grants]]
//! purpose = "operation"
//! data_categories = ["timeline"]
//! export_permitted = false
//! ```
//!
//! Provisioning persists one root capability grant through
//! [`AuthorityPersistenceHostV1`] into the store's authority records: the
//! Principal is its grantor and grantee, its scope lists exactly the granted
//! operations ([`GatewayOperationV1::named`]) and the listed actors, and its
//! `authority_registry_digest` commits to the whole document. The authority
//! registry snapshot and the Principal's authentication evidence are a pure
//! function of the recorded grants, so the store holds one source of truth and
//! `serve` recomposes exactly what was provisioned. Nothing is provisioned
//! implicitly: a host without the record serves every protected operation
//! `401 unauthenticated`. A store holds at most one Local Principal; a
//! different document is refused before anything is written.
//!
//! A document with a `[consent]` table (owner decisions 1(a) and 2(b) on
//! #309) records each consent as one `consent.granted.v1` Event on the
//! Principal's one consent Timeline, [`local_principal_consent_timeline`].
//! A consent governs the granted operations whose purpose is its `purpose`
//! (the ADR-059 purpose an operation is evaluated for: `operation`, `read`
//! or `action`) and whose resource is one of its `data_categories`; every
//! operation is governed by at most one consent, at least one operation by
//! none, and no consent governs an exempt operation
//! ([`GatewayOperationV1::consent_exempt`]). The root grant keeps the
//! operations no consent governs, and each consent has its own consent-bound
//! root grant on its own authority Timeline that covers exactly the
//! operations it governs, names the consent subject and references exactly
//! that consent, by the BLAKE3 derivation of its canonical
//! `consent.granted.v1` payload, so the document alone fixes every grant. The
//! consents of one document share one subject and one grantee, the subject of
//! the Principal's one consent Timeline.
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
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityViewV1, CanonicalBytes,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    ConsentAuthority, ConsentGrantRefDraftV1, ConsentGrantRefV1, ConsentGrantStatusV1,
    ConsentGrantedV1, ConsentRevokedV1, EntityId, Event, EventDraft, EventReadBounds, Hash, Kind,
    PersistedAuthorityV1, PrincipalRefV1, Seq, SeqRange, TimelineId, WallTime,
    EVENT_TYPE_CONSENT_GRANTED_V1, EVENT_TYPE_CONSENT_REVOKED_V1,
    MAX_CAPABILITY_CONSENT_REFERENCES, MAX_CONSENT_HISTORY_EVENTS,
};
use pos_runtime::ErasureExecutionHostV1;
use serde::Deserialize;
use thiserror::Error;
use ulid::Ulid;

use crate::{
    startup::erasure_host_failure, Gateway, GatewayAuthorityRecordV1, GatewayAuthoritySourceV1,
    GatewayAuthorization, GatewayConsentRecordV1, GatewayConsentRevocationV1, GatewayConsentV1,
    GatewayConsentedAuthorityV1, GatewayConsentsV1, GatewayOperationV1, GatewayPinnedAuthorityV1,
    LocalAuthenticationAdapter, OwnTracksOwnerKey,
};

/// The one systemd credential `provision-local-principal` reads.
pub const LOCAL_PRINCIPAL_CREDENTIAL_NAME: &str = "pigloros.local-principal";
/// The largest Local Principal credential accepted.
pub const MAX_LOCAL_PRINCIPAL_CREDENTIAL_BYTES: usize = 16 * 1_024;
/// The authentication adapter the Local Principal's evidence names.
const LOCAL_ADAPTER_ID: &str = "local-loopback";
/// The one audience every Gateway operation is evaluated for.
const GATEWAY_AUDIENCE: &str = "gateway";
/// The name of the Principal's consent Timeline.
const CONSENT_TIMELINE_NAME: &str = "pigloros.local-principal.consents";
/// The ADR-059 withdrawal policy of every Local consent: it is withdrawn at
/// its ADR-039 revocation fence.
const CONSENT_WITHDRAWAL_POLICY: &str = "adr-039-revocation-fence";

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
    #[serde(default)]
    consent: Option<LocalConsentDocumentV1>,
}

/// The document's `[consent]` table.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalConsentDocumentV1 {
    subject_entity_id: String,
    grantee_entity_id: String,
    grants: Vec<LocalConsentGrantDraftV1>,
}

/// One consent of a provisioning: the ADR-059 purpose and the data
/// categories (operation resources) it governs, and whether it permits
/// export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalConsentGrantDraftV1 {
    /// The purpose the subject consents to: the purpose of the operations
    /// it governs, recorded as the `consent.granted.v1` purpose.
    pub purpose: String,
    /// The resources of the operations it governs.
    pub data_categories: Vec<String>,
    /// Whether the consent permits export.
    pub export_permitted: bool,
}

/// The consents of a provisioning (#309): the subject who consents and the
/// actor they grant, shared by every consent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalConsentDraftV1 {
    /// The entity whose data the consents govern; one of the actors.
    pub subject: EntityId,
    /// The actor the consents grant; one of the actors.
    pub grantee: EntityId,
    /// The consents, recorded in this order.
    pub grants: Vec<LocalConsentGrantDraftV1>,
}

/// One validated Local Principal provisioning: its root capability grant,
/// each consent's consent-bound grant and `consent.granted.v1` record, and
/// the authority registry snapshot that attests them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPrincipalProvisionV1 {
    grant: CapabilityGrantV1,
    consents: Vec<(CapabilityGrantV1, ConsentGrantedV1)>,
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
        Self::try_new_with_consent(principal, actor_entity_ids, operations, None)
    }

    /// Grant `principal` exactly `operations`, acting as `actor_entity_ids`,
    /// with `consent` governing some of them.
    ///
    /// # Errors
    /// Returns [`LocalPrincipalErrorV1::Invalid`] for an empty or oversized
    /// actor or operation set, an invalid Principal or entity, or a consent
    /// whose subject or grantee does not act, that names no grant or more
    /// than [`MAX_CAPABILITY_CONSENT_REFERENCES`], a grant that governs no
    /// granted operation, an exempt one or one another grant governs, an
    /// over-long purpose, or that leaves no operation ungoverned.
    pub fn try_new_with_consent(
        principal: &PrincipalRefV1,
        actor_entity_ids: impl IntoIterator<Item = EntityId>,
        operations: impl IntoIterator<Item = GatewayOperationV1>,
        consent: Option<LocalConsentDraftV1>,
    ) -> Result<Self, LocalPrincipalErrorV1> {
        let mut actors = actor_entity_ids.into_iter().collect::<Vec<_>>();
        actors.sort_unstable();
        actors.dedup();
        let operations = sorted_operations(operations);
        let registry_digest = registry_digest(principal, &actors, &operations, consent.as_ref());
        consent
            .as_ref()
            .map_or(Ok(Vec::new()), |consent| {
                governed(consent, &actors, &operations)
            })
            .and_then(|governed| {
                let ungoverned = operations
                    .iter()
                    .copied()
                    .filter(|operation| !governed.iter().flatten().any(|g| g == operation))
                    .collect::<Vec<_>>();
                root_grant(
                    principal,
                    LocalGrantKindV1::Root,
                    (actors.as_slice(), ungoverned.as_slice()),
                    None,
                    registry_digest,
                )
                .map_err(|_| LocalPrincipalErrorV1::Invalid)
                .and_then(|grant| {
                    consent
                        .as_ref()
                        .map_or(Ok(Vec::new()), |consent| {
                            consented_grants(
                                principal,
                                &actors,
                                consent,
                                &governed,
                                registry_digest,
                            )
                        })
                        .map(|consents| (grant, consents))
                })
            })
            .and_then(|(grant, consents)| {
                consents
                    .iter()
                    .map(|(consented, record)| {
                        consent_reference(consented, record)
                            .map(|reference| reference.binding_digest())
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .and_then(|bindings| {
                        let consented = consents
                            .iter()
                            .map(|(consented, _)| (consented, consented))
                            .collect::<Vec<_>>();
                        authority_for((&grant, &grant), &consented, bindings)
                    })
                    .map(|(_, registry)| Self {
                        grant,
                        consents,
                        registry,
                    })
                    .map_err(|_| LocalPrincipalErrorV1::Invalid)
            })
    }

    /// Parse and validate the operator's TOML provisioning document.
    ///
    /// # Errors
    /// Returns [`LocalPrincipalErrorV1::Invalid`] for malformed TOML, an
    /// unknown member, a malformed ULID, an unknown operation name, or a
    /// document [`Self::try_new_with_consent`] refuses.
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
                    .map(|text| entity(text))
                    .collect::<Option<Vec<_>>>();
                let operations = document
                    .operations
                    .iter()
                    .map(|name| GatewayOperationV1::named(name))
                    .collect::<Option<Vec<_>>>();
                let consent = document.consent.map_or(Some(None), |consent| {
                    entity(&consent.subject_entity_id)
                        .zip(entity(&consent.grantee_entity_id))
                        .map(|(subject, grantee)| {
                            Some(LocalConsentDraftV1 {
                                subject,
                                grantee,
                                grants: consent.grants,
                            })
                        })
                });
                principal.zip(actors).zip(operations).zip(consent)
            })
            .ok_or(LocalPrincipalErrorV1::Invalid)
            .and_then(|(((principal, actors), operations), consent)| {
                Self::try_new_with_consent(&principal, actors, operations, consent)
            })
    }
}

/// The root grants a Local Principal may hold: its root grant and one
/// consent-bound grant per consent, by position.
#[derive(Clone, Copy)]
enum LocalGrantKindV1 {
    /// The grant of the operations no consent governs.
    Root,
    /// The consent-bound grant of the consent at this position.
    Consented(usize),
}

impl LocalGrantKindV1 {
    /// The grant's identity and its authority Timeline.
    fn identity(self) -> (Hash, TimelineId) {
        match self {
            Self::Root => (
                local_principal_grant_id(),
                local_principal_authority_timeline(),
            ),
            Self::Consented(position) => (
                derived_hash(&format!(
                    "pigloros gateway local principal consent grant v1 {position}"
                )),
                derived_timeline(&format!(
                    "pigloros gateway local principal consent authority timeline v1 {position}"
                )),
            ),
        }
    }
}

/// One root grant of `principal` of `kind` for `operations` acting as
/// `actors`, bound to `consent` (its subject and consent references) when
/// given.
fn root_grant(
    principal: &PrincipalRefV1,
    kind: LocalGrantKindV1,
    (actors, operations): (&[EntityId], &[GatewayOperationV1]),
    consent: Option<(EntityId, Vec<Hash>)>,
    registry_digest: Hash,
) -> Result<CapabilityGrantV1, AuthorityErrorV1> {
    let (grant_id, issuance_timeline) = kind.identity();
    let (subject_ids, consent_references) = consent.map_or_else(
        || (Vec::new(), Vec::new()),
        |(subject, references)| (vec![subject], references),
    );
    CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: sorted_set(operations.iter().copied().map(GatewayOperationV1::resource)),
        actions: sorted_set(operations.iter().copied().map(GatewayOperationV1::action)),
        purposes: sorted_set(operations.iter().copied().map(GatewayOperationV1::purpose)),
        audiences: vec![GATEWAY_AUDIENCE.to_owned()],
        actor_entity_ids: actors.to_vec(),
        subject_ids,
        participant_ids: Vec::new(),
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 1,
        budget: 1,
        environment_constraints: Vec::new(),
    })
    .and_then(|scope| {
        CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id,
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
            consent_references,
            policy_revision: derived_hash("pigloros gateway local principal policy v1"),
            issuance_timeline,
            issuance_seq: Seq::from_u64(1),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: registry_digest,
        })
    })
}

/// The granted operations each consent of `consent` governs, in consent
/// order, when the consent is in contract: its subject and grantee act, it
/// has 1 to [`MAX_CAPABILITY_CONSENT_REFERENCES`] grants, and each grant
/// governs at least one granted operation, no exempt one and none another
/// grant governs.
fn governed(
    consent: &LocalConsentDraftV1,
    actors: &[EntityId],
    operations: &[GatewayOperationV1],
) -> Result<Vec<Vec<GatewayOperationV1>>, LocalPrincipalErrorV1> {
    let governed = consent
        .grants
        .iter()
        .map(|grant| {
            operations
                .iter()
                .copied()
                .filter(|operation| {
                    operation.purpose() == grant.purpose
                        && grant
                            .data_categories
                            .iter()
                            .any(|category| category == operation.resource())
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut every = governed.iter().flatten().copied().collect::<Vec<_>>();
    let count = every.len();
    every.sort_unstable_by_key(operation_name);
    every.dedup();
    let in_contract = actors.contains(&consent.subject)
        && actors.contains(&consent.grantee)
        && (1..=MAX_CAPABILITY_CONSENT_REFERENCES).contains(&consent.grants.len())
        && governed.iter().all(|operations| !operations.is_empty())
        && every.len() == count
        && every.iter().all(|operation| !operation.consent_exempt());
    in_contract
        .then_some(governed)
        .ok_or(LocalPrincipalErrorV1::Invalid)
}

/// Each consent's consent-bound grant of the operations it governs, and its
/// `consent.granted.v1` record, the `n`-th at consent Timeline sequence `n`.
fn consented_grants(
    principal: &PrincipalRefV1,
    actors: &[EntityId],
    consent: &LocalConsentDraftV1,
    governed: &[Vec<GatewayOperationV1>],
    registry_digest: Hash,
) -> Result<Vec<(CapabilityGrantV1, ConsentGrantedV1)>, LocalPrincipalErrorV1> {
    consent
        .grants
        .iter()
        .zip(governed)
        .zip(1_u64..)
        .enumerate()
        .map(|(position, ((grant, operations), grant_seq))| {
            let record = ConsentGrantedV1 {
                subject_id: consent.subject,
                grantee_id: consent.grantee,
                purpose: grant.purpose.clone(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: grant.export_permitted,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq,
            };
            record
                .encode()
                .map_err(|_| LocalPrincipalErrorV1::Invalid)
                .and_then(|payload| {
                    root_grant(
                        principal,
                        LocalGrantKindV1::Consented(position),
                        (actors, operations.as_slice()),
                        Some((consent.subject, vec![consent_id(&payload)])),
                        registry_digest,
                    )
                    .map_err(|_| LocalPrincipalErrorV1::Invalid)
                })
                .map(|grant| (grant, record))
        })
        .collect()
}

/// Record the consents of `provision` on the Principal's consent Timeline
/// of the store `host` owns, after checking that the Timeline holds no
/// other consents; a provisioning that binds none records nothing.
///
/// The consent Timeline is opened under its well-known identity and each
/// consent is appended as one `consent.granted.v1` Event, in document order,
/// in one bounded commit. An exact retry finds the same grants (and any
/// revocation recorded since) and records nothing.
///
/// # Errors
/// Returns [`LocalPrincipalErrorV1::Conflict`] when the consent Timeline
/// holds other consents, including any for a provisioning that binds none,
/// and [`LocalPrincipalErrorV1::Unavailable`] when the host cannot open,
/// read or append it.
pub fn provision_local_consents(
    host: &mut ErasureExecutionHostV1,
    provision: &LocalPrincipalProvisionV1,
) -> Result<(), LocalPrincipalErrorV1> {
    let timeline = local_principal_consent_timeline();
    let records = provision
        .consents
        .iter()
        .map(|(_, record)| record.clone())
        .collect::<Vec<_>>();
    let existing = host
        .command_sender()
        .and_then(|mut sender| sender.timeline(timeline))
        .map_err(|_| LocalPrincipalErrorV1::Unavailable);
    let recorded = match existing {
        Ok(Some(_)) => host
            .read_sender()
            .and_then(|mut reads| reads.read_bounded(timeline, SeqRange::all(), consent_bounds()))
            .map_err(|_| LocalPrincipalErrorV1::Unavailable),
        Ok(None) => Ok(Vec::new()),
        Err(error) => Err(error),
    };
    recorded.and_then(|recorded| {
        if !recorded.is_empty() || records.is_empty() {
            return recorded_grants_are(&recorded, &records)
                .then_some(())
                .ok_or(LocalPrincipalErrorV1::Conflict);
        }
        append_consents(host, timeline, &records)
    })
}

/// Open the consent Timeline and append `records` as its first Events.
fn append_consents(
    host: &mut ErasureExecutionHostV1,
    timeline: TimelineId,
    records: &[ConsentGrantedV1],
) -> Result<(), LocalPrincipalErrorV1> {
    let authority = ConsentAuthority::new();
    let drafts = records
        .iter()
        .map(|record| {
            record.encode().map(|payload| {
                EventDraft::new(
                    record.subject_id,
                    Kind::new(EVENT_TYPE_CONSENT_GRANTED_V1),
                    payload,
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LocalPrincipalErrorV1::Invalid);
    let bound = drafts.and_then(|drafts| {
        host.bind_consent_authority(authority.append_permit())
            .map(|()| drafts)
            .map_err(|_| LocalPrincipalErrorV1::Unavailable)
    });
    bound.and_then(|drafts| {
        host.command_sender()
            .and_then(|mut sender| {
                sender
                    .open_root_timeline(timeline, CONSENT_TIMELINE_NAME)
                    .and_then(|_| {
                        sender.append_consent_bounded(
                            timeline,
                            &drafts,
                            authority.append_permit(),
                            u64::try_from(MAX_CONSENT_HISTORY_EVENTS).unwrap_or(u64::MAX),
                        )
                    })
            })
            .ok()
            .flatten()
            .map(drop)
            .ok_or(LocalPrincipalErrorV1::Unavailable)
    })
}

/// Whether the `consent.granted.v1` Events of `recorded` are exactly
/// `records`, in order; revocations may follow them.
fn recorded_grants_are(recorded: &[Event], records: &[ConsentGrantedV1]) -> bool {
    let granted = recorded
        .iter()
        .filter(|event| event.event_type.as_str() == EVENT_TYPE_CONSENT_GRANTED_V1)
        .map(|event| ConsentGrantedV1::decode(&event.payload).ok())
        .collect::<Vec<_>>();
    granted.len() == records.len()
        && granted
            .iter()
            .zip(records)
            .all(|(granted, record)| granted.as_ref() == Some(record))
}

/// Persist `provision` as the store's one Local Principal.
///
/// Its root capability grant commits first and each consent-bound grant
/// after it, every one under a permit of the [`AuthorityPersistenceHostV1`]
/// its registry snapshot attests. The root grant commits to the whole
/// document, so a store that holds another Principal refuses the root grant
/// before any consent-bound grant is written. An exact retry is
/// [`AuthorityCommitOutcomeV1::Unchanged`]. Record the consents first with
/// [`provision_local_consents`].
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
        .and_then(|outcome| {
            provision
                .consents
                .iter()
                .try_for_each(|(consented, _)| {
                    host.authorize_grant(consented)
                        .and_then(|permit| store.issue_capability_grant(permit, consented))
                        .map(drop)
                })
                .map(|()| outcome)
        })
        .map_err(persistence_failure)
}

/// Refuse `provision` on a store whose recorded root grant is another
/// Principal's, before anything is written.
fn check_recorded_root<S>(
    store: &S,
    provision: &LocalPrincipalProvisionV1,
) -> Result<(), LocalPrincipalErrorV1>
where
    S: AuthorityPersistencePortV1 + ?Sized,
{
    load_chain(store, LocalGrantKindV1::Root).and_then(|chain| {
        chain
            .as_ref()
            .and_then(|chain| chain.chain().grants().first())
            .map(as_issued)
            .is_none_or(|recorded| recorded.as_ref() == Ok(&provision.grant))
            .then_some(())
            .ok_or(LocalPrincipalErrorV1::Conflict)
    })
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
                let provisioned = crate::startup::open_recovered_erasure_host(
                    pos_store::StoreConfig::Sqlite {
                        path: sqlite_path.to_owned(),
                    },
                    crate::startup::GatewayHostStoreV1::Standard,
                    &pos_runtime::ErasureCoordinatorCompositionV1::closed(),
                )
                .and_then(|mut host| provision_on_host(&mut host, &provision));
                drop(lock);
                provisioned
            })
    })
}

/// Attach the offline writer to the store `host` owns, refuse a Principal
/// its mode does not allow or a store that holds another Principal, then
/// record the consents and persist the Principal of `provision`.
///
/// Nothing is written before every check passed: the store's recorded root
/// grant must be this document's, and its consent Timeline must hold no
/// other consents.
///
/// # Errors
/// Returns an error when the store is unbound or bound to a mode that
/// refuses the Principal, it holds another Principal, or provisioning fails.
pub fn provision_on_host(
    host: &mut ErasureExecutionHostV1,
    provision: &LocalPrincipalProvisionV1,
) -> io::Result<()> {
    crate::mode_profile::attach_offline_writer_v1(host.gateway_mode_binding())
        .and_then(|mode| admit_in_mode(provision, mode))
        .map_err(io::Error::other)
        .and_then(|()| {
            host.command_sender()
                .and_then(|mut sender| {
                    sender.with_scheduled_admission(|ports| check_recorded_root(&*ports, provision))
                })
                .map_err(erasure_host_failure)
                .and_then(|checked| checked.map_err(io::Error::other))
        })
        .and_then(|()| provision_local_consents(host, provision).map_err(io::Error::other))
        .and_then(|()| {
            host.command_sender()
                .and_then(|mut sender| {
                    sender.with_scheduled_admission(|ports| {
                        provision_local_principal(&mut *ports, provision)
                    })
                })
                .map_err(erasure_host_failure)
                .and_then(|provisioned| provisioned.map(drop).map_err(io::Error::other))
        })
}

/// ADR-134 §4 and D6: a store bound to a mode without network refuses a
/// Principal grant that names the network capability.
fn admit_in_mode(
    provision: &LocalPrincipalProvisionV1,
    mode: crate::mode_profile::GatewayModeProfileIdV1,
) -> Result<(), crate::mode_profile::GatewayModeErrorV1> {
    crate::mode_profile::refuse_principal_network_v1(
        mode,
        crate::authorization::scope_names(provision.grant.scope(), GatewayOperationV1::NETWORK),
    )
}

/// Whether the Local Principal recorded in `store` holds the network
/// capability. A store that records no Local Principal holds none.
///
/// # Errors
/// Returns the unavailable store error when the authority records cannot be
/// read or decoded, so a caller fails closed instead of treating an
/// unreadable store as one without the capability.
pub(crate) fn names_network_capability<S>(
    store: &S,
) -> Result<bool, crate::mode_profile::GatewayModeErrorV1>
where
    S: AuthorityPersistencePortV1 + ?Sized,
{
    match store.load_authority(local_principal_grant_id()) {
        // The store resolves no chain for an absent leaf grant.
        Err(AuthorityPersistenceErrorV1::Conflict) => Ok(false),
        Err(_) => Err(crate::mode_profile::GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Unavailable,
        )),
        Ok(persisted) => Ok(persisted.chain().grants().iter().any(|grant| {
            crate::authorization::scope_names(grant.scope(), GatewayOperationV1::NETWORK)
        })),
    }
}

/// Compose the Local Principal recorded in `store` as the Gateway
/// authorizer, or `None` when the store has none (an unprovisioned host).
///
/// Reading never writes the store. A Principal whose provisioning binds
/// consents is composed with its consent-bound chains and unread consents:
/// the host reads its consent Timeline before its first decision.
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
    load_chain(store, LocalGrantKindV1::Root).and_then(|chain| {
        chain.map_or(Ok(None), |chain| {
            consented_chains(store).and_then(|chains| {
                compose(&GatewayAuthorityRecordV1 {
                    chain,
                    consented: (!chains.is_empty()).then_some(GatewayConsentRecordV1 {
                        chains,
                        head: Seq::ZERO,
                        events: None,
                    }),
                })
                .map(Some)
                .ok_or(LocalPrincipalErrorV1::Corrupt)
            })
        })
    })
}

/// Every consent-bound chain `store` records, by position, up to the first
/// position it records none at.
fn consented_chains<S>(store: &S) -> Result<Vec<PersistedAuthorityV1>, LocalPrincipalErrorV1>
where
    S: AuthorityPersistencePortV1 + ?Sized,
{
    let mut chains = Vec::new();
    for position in 0..MAX_CAPABILITY_CONSENT_REFERENCES {
        match load_chain(store, LocalGrantKindV1::Consented(position)) {
            Ok(Some(chain)) => chains.push(chain),
            Ok(None) => break,
            Err(error) => return Err(error),
        }
    }
    Ok(chains)
}

/// The chain `store` records under the grant of `kind`, or `None` when it
/// records none.
fn load_chain<S>(
    store: &S,
    kind: LocalGrantKindV1,
) -> Result<Option<PersistedAuthorityV1>, LocalPrincipalErrorV1>
where
    S: AuthorityPersistencePortV1 + ?Sized,
{
    match store.load_authority(kind.identity().0) {
        // The store resolves no chain for an absent leaf grant.
        Err(AuthorityPersistenceErrorV1::Conflict) => Ok(None),
        Err(AuthorityPersistenceErrorV1::Unavailable) => Err(LocalPrincipalErrorV1::Unavailable),
        Err(_) => Err(LocalPrincipalErrorV1::Corrupt),
        Ok(persisted) => Ok(Some(persisted)),
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
/// store's record under the one Local Principal grant identity, and its
/// consent-bound grants and consent Timeline when its provisioning binds
/// consents.
struct LocalPrincipalSourceV1;

impl GatewayAuthoritySourceV1 for LocalPrincipalSourceV1 {
    fn leaf_grant_id(&self) -> Hash {
        local_principal_grant_id()
    }

    fn recompose(&self, record: &GatewayAuthorityRecordV1) -> Option<GatewayPinnedAuthorityV1> {
        recompose(record).map(|(pinned, _)| pinned)
    }
}

/// The authorizer of one recorded Local Principal, which brings itself
/// current with the store's record before each decision.
fn compose(record: &GatewayAuthorityRecordV1) -> Option<GatewayAuthorization> {
    recompose(record).map(|(pinned, evidence)| {
        GatewayAuthorization::new_pinned(
            Arc::new(LocalAuthenticationAdapter::new(evidence)),
            pinned,
        )
        .with_source(Arc::new(LocalPrincipalSourceV1))
    })
}

/// Recompose the pinned authority and pinned evidence of one recorded Local
/// Principal.
///
/// Each chain is its as-issued root grant plus the revocations the store
/// holds on its authority Timeline, and the consents are those of the read
/// consent Timeline; a state this host cannot reproduce exactly is refused,
/// never merged.
fn recompose(
    record: &GatewayAuthorityRecordV1,
) -> Option<(GatewayPinnedAuthorityV1, AuthenticatedPrincipalResultV1)> {
    issued_root(&record.chain).and_then(|(issued, root)| {
        record
            .consented
            .as_ref()
            .map_or(Some(None), |consented| {
                RecordedConsentV1::of(consented).map(Some)
            })
            .and_then(|consented| {
                let bindings = consented
                    .as_ref()
                    .map_or_else(Vec::new, RecordedConsentV1::bindings);
                let grants = consented
                    .as_ref()
                    .map_or_else(Vec::new, RecordedConsentV1::grants);
                authority_for((&issued, root), &grants, bindings)
                    .ok()
                    .and_then(|(evidence, registry)| {
                        let host = AuthorityPersistenceHostV1::new(&registry);
                        replayed_view(&host, &issued, &record.chain)
                            .zip(consented.map_or(Some(None), |consented| {
                                consented.authority(&host).map(Some)
                            }))
                            .map(|(view, consented)| {
                                (
                                    GatewayPinnedAuthorityV1::new(view, registry, consented),
                                    evidence,
                                )
                            })
                    })
            })
    })
}

/// The recorded consent-bound chains of one Principal: the record, each
/// chain's as-issued root grant, and the consents once read.
struct RecordedConsentV1<'a> {
    record: &'a GatewayConsentRecordV1,
    issued: Vec<CapabilityGrantV1>,
    consents: Option<GatewayConsentsV1>,
}

impl<'a> RecordedConsentV1<'a> {
    /// The recorded consent-bound chains of `record`, or `None` when a root
    /// grant or the read consent Timeline cannot be reproduced.
    fn of(record: &'a GatewayConsentRecordV1) -> Option<Self> {
        record
            .chains
            .iter()
            .map(|chain| issued_root(chain).map(|(issued, _)| issued))
            .collect::<Option<Vec<_>>>()
            .and_then(|issued| {
                record
                    .events
                    .as_deref()
                    .map_or(Some(None), |events| {
                        local_consents(&issued, events).map(Some)
                    })
                    .map(|consents| Self {
                        record,
                        issued,
                        consents,
                    })
            })
    }

    /// Each chain's as-issued and recorded root grant.
    fn grants(&self) -> Vec<(&CapabilityGrantV1, &CapabilityGrantV1)> {
        self.issued
            .iter()
            .zip(&self.record.chains)
            .filter_map(|(issued, chain)| chain.chain().grants().first().map(|root| (issued, root)))
            .collect()
    }

    /// The registry bindings of the read consents.
    fn bindings(&self) -> Vec<Hash> {
        self.consents
            .as_ref()
            .map_or_else(Vec::new, |consents| consents.bindings().collect())
    }

    /// The consent-bound authority, when every chain reproduces its record.
    fn authority(self, host: &AuthorityPersistenceHostV1) -> Option<GatewayConsentedAuthorityV1> {
        self.issued
            .iter()
            .zip(&self.record.chains)
            .map(|(issued, chain)| replayed_view(host, issued, chain))
            .collect::<Option<Vec<_>>>()
            .map(|views| {
                GatewayConsentedAuthorityV1::new(
                    views,
                    local_principal_consent_timeline(),
                    self.consents,
                )
            })
    }
}

/// The as-issued root grant of `persisted` and its recorded form.
fn issued_root(
    persisted: &PersistedAuthorityV1,
) -> Option<(CapabilityGrantV1, &CapabilityGrantV1)> {
    persisted
        .chain()
        .grants()
        .first()
        .and_then(|root| as_issued(root).ok().map(|issued| (issued, root)))
}

/// The view of the as-issued `grant` with the revocations `persisted`
/// records, when it reproduces `persisted` exactly.
fn replayed_view(
    host: &AuthorityPersistenceHostV1,
    grant: &CapabilityGrantV1,
    persisted: &PersistedAuthorityV1,
) -> Option<AuthorityViewV1> {
    let mut state = AuthorityPersistenceStateV1::new();
    host.authorize_grant(grant)
        .and_then(|permit| state.issue_grant(permit, grant.clone()))
        .and_then(|_| {
            persisted.revocations().iter().try_for_each(|revocation| {
                host.authorize_revocation(grant, revocation)
                    .and_then(|permit| state.revoke_grant(permit, revocation.clone()))
                    .map(|_| ())
            })
        })
        .and_then(|()| state.view(grant.grant_id()))
        .ok()
        .filter(|view| view.authority() == persisted)
}

/// One replayed consent, the ADR-059 identity of its grant payload and the
/// consent-bound grant that references it.
type ReplayedConsentV1<'a> = (GatewayConsentV1, Hash, &'a CapabilityGrantV1);

/// The consents of the consent-bound `grants` recorded in `events`, the
/// consent Timeline in order.
///
/// Every Event is the subject's: a `consent.granted.v1` at its own sequence
/// that exactly one grant references, or a `consent.revoked.v1` at its own
/// sequence of an earlier grant (a later revocation of a revoked consent
/// keeps the first fence); every grant's consent is granted. Anything else
/// is refused.
fn local_consents(grants: &[CapabilityGrantV1], events: &[Event]) -> Option<GatewayConsentsV1> {
    grants
        .first()
        .and_then(|grant| grant.scope().subject_ids().first().copied())
        .filter(|subject| {
            grants
                .iter()
                .all(|grant| grant.scope().subject_ids() == [*subject])
        })
        .and_then(|subject| {
            events
                .iter()
                .try_fold(Vec::new(), |consents, event| {
                    replay_consent_event(consents, grants, subject, event)
                })
                .and_then(|consents| {
                    let head = events.last().map_or(Seq::ZERO, |event| event.seq);
                    consent_state(grants.len(), subject, head, consents)
                })
        })
}

/// `consents` after the consent Timeline Event `event` of `subject`.
fn replay_consent_event<'a>(
    mut consents: Vec<ReplayedConsentV1<'a>>,
    grants: &'a [CapabilityGrantV1],
    subject: EntityId,
    event: &Event,
) -> Option<Vec<ReplayedConsentV1<'a>>> {
    let own = |entity: EntityId, seq: u64| {
        event.entity == subject && entity == subject && seq == event.seq.as_u64()
    };
    match event.event_type.as_str() {
        EVENT_TYPE_CONSENT_GRANTED_V1 => ConsentGrantedV1::decode(&event.payload)
            .ok()
            .filter(|granted| own(granted.subject_id, granted.grant_seq))
            .and_then(|granted| {
                let id = consent_id(&event.payload);
                grants
                    .iter()
                    .find(|grant| grant.consent_references() == [id])
                    .filter(|_| consents.iter().all(|(_, known, _)| *known != id))
                    .map(|grant| {
                        consents.push((
                            GatewayConsentV1::new(
                                event.id,
                                granted.grantee_id,
                                event.seq,
                                granted.export_permitted,
                            ),
                            id,
                            grant,
                        ));
                        consents
                    })
            }),
        EVENT_TYPE_CONSENT_REVOKED_V1 => ConsentRevokedV1::decode(&event.payload)
            .ok()
            .filter(|revoked| own(revoked.subject_id, revoked.fence_seq))
            .and_then(|revoked| {
                consents
                    .iter_mut()
                    .find(|(consent, _, _)| {
                        consent.grant_seq().as_u64() == revoked.grant_seq
                            && consent.grantee() == revoked.grantee_id
                    })
                    .map(|(consent, _, _)| {
                        if consent.revocation().is_none() {
                            *consent = consent.revoked_by(GatewayConsentRevocationV1::new(
                                event.id,
                                event.seq,
                                event.correlation_id,
                            ));
                        }
                    })
            })
            .map(|()| consents),
        _ => None,
    }
}

/// The consents of `subject` at `head`, when every one of the `granted`
/// consent-bound grants' consents was granted.
fn consent_state(
    granted: usize,
    subject: EntityId,
    head: Seq,
    consents: Vec<ReplayedConsentV1<'_>>,
) -> Option<GatewayConsentsV1> {
    consents
        .iter()
        .map(|(consent, id, grant)| {
            consent_reference_of(
                grant,
                (*id, subject, consent.grantee()),
                consent.grant_seq(),
                consent.revocation().map(|revocation| revocation.fence()),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .ok()
        .filter(|_| consents.len() == granted)
        .map(|mut references| {
            references.sort_unstable_by_key(ConsentGrantRefV1::consent_id);
            GatewayConsentsV1::new(
                local_principal_consent_timeline(),
                head,
                subject,
                references,
                consents
                    .into_iter()
                    .map(|(consent, _, _)| consent)
                    .collect(),
            )
        })
}

/// The ADR-059 record of the provisioned, active `record`.
fn consent_reference(
    grant: &CapabilityGrantV1,
    record: &ConsentGrantedV1,
) -> Result<ConsentGrantRefV1, AuthorityErrorV1> {
    record
        .encode()
        .map_err(|_| AuthorityErrorV1::InvalidEncoding)
        .and_then(|payload| {
            consent_reference_of(
                grant,
                (consent_id(&payload), record.subject_id, record.grantee_id),
                Seq::from_u64(record.grant_seq),
                None,
            )
        })
}

/// The ADR-059 record of the consent `(consent_id, subject, grantee)` the
/// consent-bound `grant` references: it covers exactly the grant's
/// resources, actions, purposes and audiences, has no wall-clock expiry and
/// is withdrawn at its ADR-039 fence.
fn consent_reference_of(
    grant: &CapabilityGrantV1,
    (consent_id, subject, grantee): (Hash, EntityId, EntityId),
    grant_position: Seq,
    fence: Option<Seq>,
) -> Result<ConsentGrantRefV1, AuthorityErrorV1> {
    let scope = grant.scope();
    ConsentGrantRefV1::try_from_draft(ConsentGrantRefDraftV1 {
        consent_id,
        subject_id: subject,
        grantee_id: grantee,
        data_categories: scope.resources().to_vec(),
        purposes: scope.purposes().to_vec(),
        audiences: scope.audiences().to_vec(),
        action_classes: scope.actions().to_vec(),
        valid_from: WallTime::from_micros(0),
        valid_until: WallTime::from_micros(u64::MAX),
        withdrawal_retention_policy: CONSENT_WITHDRAWAL_POLICY.to_owned(),
        policy_revision: grant.policy_revision(),
        issuer: grant.grantor().clone(),
        issuer_evidence: grant.authority_registry_digest(),
        consent_timeline: local_principal_consent_timeline(),
        grant_position,
        status: fence.map_or(ConsentGrantStatusV1::Active, |_| {
            ConsentGrantStatusV1::RevokedAtFence
        }),
        revocation_fence: fence,
        authority_registry_digest: grant.authority_registry_digest(),
    })
}

/// The ADR-059 identity of the consent whose canonical
/// `consent.granted.v1` payload is `payload`.
fn consent_id(payload: &CanonicalBytes) -> Hash {
    Hash::from_bytes(blake3::derive_key(
        "pigloros gateway local consent v1",
        payload.as_slice(),
    ))
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
/// recorded form, each consent-bound grant's two forms, and the registry
/// bindings of its consents; all are functions of the recorded
/// grants and consent Timeline.
///
/// A recorded revocation changes a grant's resolved form, and a consent
/// revocation its ADR-059 record, so attesting them lets the evaluator answer
/// a revoked Principal or consent `revoked` rather than `unauthorized`. The
/// evidence has no expiry: loopback reachability, not a credential, is the
/// Local trust boundary (D1), so it is valid from the epoch on.
fn authority_for(
    grant: (&CapabilityGrantV1, &CapabilityGrantV1),
    consented: &[(&CapabilityGrantV1, &CapabilityGrantV1)],
    mut consent_bindings: Vec<Hash>,
) -> Result<(AuthenticatedPrincipalResultV1, AuthorityRegistrySnapshotV1), AuthorityErrorV1> {
    let (issued, current) = grant;
    AssuranceLevelV1::try_new(1)
        .and_then(|assurance| {
            AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
                principal: issued.grantee().principal().clone(),
                adapter_id: LOCAL_ADAPTER_ID.to_owned(),
                assurance,
                issued_at: WallTime::from_micros(0),
                expires_at: WallTime::from_micros(u64::MAX),
                binding_digest: issued.authority_registry_digest(),
            })
        })
        .and_then(|evidence| {
            [issued, current]
                .into_iter()
                .chain(
                    consented
                        .iter()
                        .flat_map(|(issued, current)| [*issued, *current]),
                )
                .map(CapabilityGrantV1::binding_digest)
                .collect::<Result<Vec<_>, _>>()
                .and_then(|mut bindings| {
                    bindings.sort_unstable();
                    bindings.dedup();
                    consent_bindings.sort_unstable();
                    AuthorityRegistrySnapshotV1::try_new(
                        issued.authority_registry_digest(),
                        vec![evidence.registry_binding_digest()],
                        bindings,
                        consent_bindings,
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

/// The registry digest committing to one whole provisioning document; a
/// document without consents commits to its Principal, actors and
/// operations only.
fn registry_digest(
    principal: &PrincipalRefV1,
    actors: &[EntityId],
    operations: &[GatewayOperationV1],
    consent: Option<&LocalConsentDraftV1>,
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
    if let Some(consent) = consent {
        hasher.update(&consent.subject.inner().to_bytes());
        hasher.update(&consent.grantee.inner().to_bytes());
        hasher.update(&(consent.grants.len() as u64).to_be_bytes());
        for grant in &consent.grants {
            framed(&mut hasher, grant.purpose.as_bytes());
            hasher.update(&(grant.data_categories.len() as u64).to_be_bytes());
            for category in &grant.data_categories {
                framed(&mut hasher, category.as_bytes());
            }
            hasher.update(&[u8::from(grant.export_permitted)]);
        }
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

/// The Timeline identity of the derivation `context`.
fn derived_timeline(context: &str) -> TimelineId {
    let digest = blake3::derive_key(context, &[]);
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    TimelineId::from_ulid(Ulid::from_bytes(identity))
}

/// The one grant identity a store's Local Principal is recorded under.
fn local_principal_grant_id() -> Hash {
    derived_hash("pigloros gateway local principal grant v1")
}

/// The authority Timeline the Local Principal's grant is issued on.
fn local_principal_authority_timeline() -> TimelineId {
    derived_timeline("pigloros gateway local principal authority timeline v1")
}

/// The one consent Timeline of a store's Local Principal (#309): a root
/// Timeline under this well-known identity, which no client can create.
#[must_use]
pub fn local_principal_consent_timeline() -> TimelineId {
    derived_timeline("pigloros gateway local principal consent timeline v1")
}

/// The bounds of one complete consent Timeline read.
pub(crate) fn consent_bounds() -> EventReadBounds {
    EventReadBounds::new(
        crate::MAX_EVENT_PAYLOAD_BYTES,
        crate::MAX_EVENT_TYPE_BYTES,
        crate::MAX_FORK_DEPTH,
        MAX_CONSENT_HISTORY_EVENTS,
    )
}

fn entity(text: &str) -> Option<EntityId> {
    Ulid::from_string(text).ok().map(EntityId::from_ulid)
}

fn sorted_operations(
    operations: impl IntoIterator<Item = GatewayOperationV1>,
) -> Vec<GatewayOperationV1> {
    let mut operations = operations.into_iter().collect::<Vec<_>>();
    operations.sort_unstable_by_key(operation_name);
    operations.dedup();
    operations
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
        let gateway = local_gateway(
            crate::mode_profile::test_attach_host(sqlite_host(&path)?, &mode),
            None,
            &mode,
        )?;
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
        // The Session read and the network capability are granted by name too.
        assert_eq!(
            LocalPrincipalProvisionV1::from_toml(&document(
                &format!("\"{ACTOR}\""),
                "\"session.read\", \"gateway.network.v1\"",
            ))?,
            provision([
                GatewayOperationV1::NETWORK,
                GatewayOperationV1::READ_SESSION
            ])?
        );
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
    fn the_network_capability_check_fails_closed_on_an_unreadable_store() -> TestResult {
        use crate::mode_profile::GatewayModeErrorV1;
        let unavailable = Err(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Unavailable,
        ));
        // No Principal recorded: no capability, and a migration may proceed.
        assert_eq!(names_network_capability(&MemoryStore::new()), Ok(false));
        assert_eq!(
            names_network_capability(&FailingStore(AuthorityPersistenceErrorV1::Conflict)),
            Ok(false)
        );
        for error in [
            AuthorityPersistenceErrorV1::Unavailable,
            AuthorityPersistenceErrorV1::InvalidRecord,
            AuthorityPersistenceErrorV1::StaleEpoch,
            AuthorityPersistenceErrorV1::TimelineOrder,
        ] {
            assert_eq!(names_network_capability(&FailingStore(error)), unavailable);
        }
        for (operations, names) in [
            (
                vec![
                    GatewayOperationV1::READ_SESSION,
                    GatewayOperationV1::NETWORK,
                ],
                true,
            ),
            (vec![GatewayOperationV1::READ_SESSION], false),
        ] {
            let mut store = MemoryStore::new();
            provision_local_principal(&mut store, &provision(operations)?)?;
            assert_eq!(names_network_capability(&store), Ok(names));
        }
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
            ("GET", "/v1/session".to_owned(), None),
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

    const LOCAL_MODE_DIGEST: &str =
        "26d6c7e75b11df673a1ef2d3210733b4ca431648eab0b9ae93bf4a6f6e69da3f";
    const AIR_GAPPED_MODE_DIGEST: &str =
        "455883a475edbf5cc24907a03e6e46a476ceec6227ecdb8429999646dac447e5";

    /// `actor`'s answer to `GET /v1/session` from the production composition
    /// over a store bound to `mode` with its operator network grants and
    /// provisioned with `provision`, whose grant is revoked when `revoked`.
    async fn read_session(
        provision: &LocalPrincipalProvisionV1,
        mode: (
            crate::mode_profile::GatewayModeProfileIdV1,
            &[crate::mode_profile::GatewayNetworkGrantV1],
        ),
        revoked: bool,
        actor: Option<EntityId>,
    ) -> TestResult<(StatusCode, Value)> {
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        crate::mode_profile::bind_test_store(&mut SqliteStore::open(&path)?, mode.0)?;
        let binding = crate::mode_profile::test_binding(mode.0, mode.1.iter().copied());
        provision_local_principal(&mut SqliteStore::open(&path)?, provision)?;
        if revoked {
            record_revocation(&path, provision)?;
        }
        let gateway = local_gateway(
            crate::mode_profile::test_attach_host(sqlite_host(&path)?, &binding),
            None,
            &binding,
        )?;
        let answer = send(&app_of(gateway.clone()), "GET", "/v1/session", actor, None).await?;
        gateway.shutdown().await?;
        drop(gateway);
        Ok(answer)
    }

    /// The Session the v1 contract prescribes for the test Principal at
    /// generation and binding epoch 1, its provenance recomputed here.
    fn expected_session(
        mode: (&str, &str, &str),
        grants: &[&str],
        network_grants: &[&str],
        network: &str,
    ) -> TestResult<Value> {
        let (mode_profile_id, mode_name, digest) = mode;
        let mut record = b"PiglorOS.GatewaySession.v1\0".to_vec();
        record.extend_from_slice(&Ulid::from_string(PRINCIPAL)?.to_bytes());
        record.extend_from_slice(&1_u64.to_be_bytes());
        record.extend_from_slice(digest.as_bytes());
        record.extend_from_slice(&1_u64.to_be_bytes());
        Ok(json!({
            "schema_id": "urn:pigloros:gateway:v1:schema:session",
            "id": PRINCIPAL,
            "generation": 1,
            "provenance": {
                "digest": blake3::hash(&record).to_hex().to_string(),
                "origin": "host-derived",
            },
            "mode_profile": {
                "profile_kind": "gateway-mode-v1",
                "mode_profile_id": mode_profile_id,
                "mode": mode_name,
                "mode_profile_digest": digest,
                "binding_epoch": 1,
                "network_grants": network_grants,
                "network": network,
            },
            "execution_profile": {
                "profile_kind": "epf1",
                "state": "unavailable",
                "reason": "not-installed",
            },
            "availability": {"state": "available", "withheld": []},
            "principal": {"principal_id": PRINCIPAL, "entity_ids": [ACTOR]},
            "grants": grants,
            "consents": [],
            "contract": {"api_major": "v1", "contract_version": "1.0.0-draft"},
        }))
    }

    /// #1362: the Session is derived from the recorded grant, the evaluator
    /// and the bound mode only; the request names nothing but its actor.
    #[tokio::test]
    async fn the_session_discloses_the_recorded_principal_grants_and_bound_mode() -> TestResult {
        use crate::mode_profile::{GatewayModeProfileIdV1, GatewayNetworkGrantV1};
        let reader = provision([
            GatewayOperationV1::CREATE_TIMELINE,
            GatewayOperationV1::READ_EVENTS,
            GatewayOperationV1::READ_SESSION,
        ])?;
        let granted = ["session.read", "timeline.create", "timeline.events.read"];
        let local = read_session(
            &reader,
            (GatewayModeProfileIdV1::Local, &[]),
            false,
            Some(actor()?),
        )
        .await?;
        assert_eq!(local.0, StatusCode::OK);
        assert_eq!(
            local.1,
            expected_session(
                ("gateway-mode-local-v1", "local", LOCAL_MODE_DIGEST),
                &granted,
                &[],
                "denied",
            )?
        );
        let air_gapped = read_session(
            &reader,
            (GatewayModeProfileIdV1::AirGapped, &[]),
            false,
            Some(actor()?),
        )
        .await?;
        assert_eq!(air_gapped.0, StatusCode::OK);
        assert_eq!(
            air_gapped.1,
            expected_session(
                (
                    "gateway-mode-air-gapped-v1",
                    "air-gapped",
                    AIR_GAPPED_MODE_DIGEST
                ),
                &granted,
                &[],
                "absent",
            )?
        );
        // Only an explicitly provisioned network capability is granted
        // network; the operator grants are disclosed beside it.
        let networked = provision([
            GatewayOperationV1::READ_SESSION,
            GatewayOperationV1::NETWORK,
        ])?;
        let operator = [
            GatewayNetworkGrantV1::PublicReadOnly,
            GatewayNetworkGrantV1::OwnTracks,
        ];
        let (status, session) = read_session(
            &networked,
            (GatewayModeProfileIdV1::Local, &operator),
            false,
            Some(actor()?),
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            session,
            expected_session(
                ("gateway-mode-local-v1", "local", LOCAL_MODE_DIGEST),
                &["gateway.network.v1", "session.read"],
                &["owntracks", "public-read-only"],
                "capability-granted",
            )?
        );
        Ok(())
    }

    /// ADR-134 §4 and D6: an Air-Gapped store refuses a Principal network
    /// grant when it is provisioned and when a Gateway composes over it, so
    /// an Air-Gapped Session never lists it.
    #[tokio::test]
    async fn an_air_gapped_store_refuses_the_principal_network_capability() -> TestResult {
        use crate::mode_profile::GatewayModeProfileIdV1::{AirGapped, Local};
        let networked = provision([
            GatewayOperationV1::READ_SESSION,
            GatewayOperationV1::NETWORK,
        ])?;
        let reader = provision([GatewayOperationV1::READ_SESSION])?;
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                admit_in_mode(&networked, AirGapped),
                Err(crate::mode_profile::GatewayModeErrorV1::PrincipalNetworkRefused)
            );
            assert_eq!(admit_in_mode(&networked, Local), Ok(()));
            assert_eq!(admit_in_mode(&reader, AirGapped), Ok(()));
        }
        let refused = read_session(&networked, (AirGapped, &[]), false, Some(actor()?)).await;
        assert!(
            refused.is_err_and(|error| error.to_string().contains("gateway.network.v1")),
            "an Air-Gapped composition refuses a networked Principal"
        );
        let (status, session) =
            read_session(&networked, (Local, &[]), false, Some(actor()?)).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            session["grants"],
            json!(["gateway.network.v1", "session.read"])
        );
        let (status, session) =
            read_session(&reader, (AirGapped, &[]), false, Some(actor()?)).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(session["grants"], json!(["session.read"]));
        Ok(())
    }

    /// A Session read is a protected operation: no actor is `401`, an actor
    /// or a grant that does not cover it is `403 unauthorized`, a revoked
    /// grant `403 revoked`, and a composition with no Principal or no bound
    /// mode has nothing to disclose.
    #[tokio::test]
    async fn a_session_read_is_authorized_like_every_operation() -> TestResult {
        use crate::mode_profile::GatewayModeProfileIdV1::Local;
        let reader = provision([GatewayOperationV1::READ_SESSION])?;
        for (provision, revoked, actor, status, code) in [
            (
                &reader,
                false,
                None,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            ),
            (
                &reader,
                false,
                Some(EntityId::new()),
                StatusCode::FORBIDDEN,
                "unauthorized",
            ),
            (
                &served_provision()?,
                false,
                Some(actor()?),
                StatusCode::FORBIDDEN,
                "unauthorized",
            ),
            (
                &reader,
                true,
                Some(actor()?),
                StatusCode::FORBIDDEN,
                "revoked",
            ),
        ] {
            let (answered, problem) = read_session(provision, (Local, &[]), revoked, actor).await?;
            assert_eq!(answered, status, "{code}");
            assert_eq!(problem["code"], code);
            assert_eq!(problem["instance"], "/v1/session");
        }
        // A store-backed authorizer that is bound to no execution mode.
        let mut host = memory_host()?;
        let authorization = host
            .command_sender()?
            .with_scheduled_admission(|ports| {
                provision_local_principal(&mut *ports, &reader)
                    .and_then(|_| load_local_principal(&*ports))
            })??
            .ok_or("a provisioned store recomposes")?;
        let unbound = Gateway::new_with_erasure_host(host, Some(authorization))?;
        let unprotected = Gateway::unprotected_for_harness(memory_host()?)?;
        for gateway in [unbound, unprotected] {
            let (status, problem) = send(
                &app_of(gateway.clone()),
                "GET",
                "/v1/session",
                Some(actor()?),
                None,
            )
            .await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(problem["code"], "unauthenticated");
            gateway.shutdown().await?;
            drop(gateway);
        }
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
        let recorded = chain_record(&path)?;
        assert!(!authorization.is_behind(&recorded));
        record_revocation(&path, &provision)?;
        let revoked = chain_record(&path)?;
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
        let older = chain_record(&path)?;
        record_revocation(&path, &provision)?;
        let newer = chain_record(&path)?;
        authorization.refresh(newer.clone()).await?;
        assert!(!authorization.is_behind(&newer));
        // A refresh that read the store before the revocation lands later.
        authorization.refresh(older).await?;
        assert!(!authorization.is_behind(&newer));
        Ok(())
    }

    /// The record of the Local Principal chain the store at `path` holds,
    /// for a Principal whose provisioning binds no consent.
    fn chain_record(path: &str) -> TestResult<GatewayAuthorityRecordV1> {
        Ok(GatewayAuthorityRecordV1 {
            chain: SqliteStore::open(path)?.load_authority(local_principal_grant_id())?,
            consented: None,
        })
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
        let error = local_gateway(
            crate::mode_profile::test_attach_host(sqlite_host(&path)?, &mode),
            None,
            &mode,
        )
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
                let gateway = local_gateway(
                    crate::mode_profile::test_attach_host(host, &mode),
                    owner_key.as_ref(),
                    &mode,
                )?;
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
        let gateway = local_gateway(
            crate::mode_profile::test_attach_host(sqlite_host(&path)?, &mode),
            None,
            &mode,
        )?;
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
        let gateway = local_gateway(
            crate::mode_profile::test_attach_host(open_host()?, &mode),
            None,
            &mode,
        )?;
        assert!(gateway.has_authorization());
        gateway.shutdown().await?;
        drop(gateway);
        assert!(load_local_principal(&SqliteStore::open(&path)?)?.is_none());

        provision_local_principal(&mut SqliteStore::open(&path)?, &served_provision()?)?;
        let recorded = SqliteStore::open(&path)?.load_authority(local_principal_grant_id())?;
        let gateway = local_gateway(
            crate::mode_profile::test_attach_host(open_host()?, &mode),
            None,
            &mode,
        )?;
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

        // ADR-134 §4: an Air-Gapped store refuses a Principal network grant
        // at provisioning, and records nothing.
        let air_gapped = directory.path().join("air-gapped.db");
        let air_gapped = air_gapped.to_str().ok_or("temporary path is not UTF-8")?;
        crate::mode_profile::bind_test_store(
            &mut SqliteStore::open(air_gapped)?,
            crate::mode_profile::GatewayModeProfileIdV1::AirGapped,
        )?;
        install(document(&actor, "\"session.read\", \"gateway.network.v1\"").as_bytes())?;
        assert!(
            provision_local_principal_from_credentials(air_gapped, &credentials)
                .is_err_and(|error| error.to_string().contains("gateway.network.v1"))
        );
        assert!(load_local_principal(&SqliteStore::open(air_gapped)?)?.is_none());
        install(document(&actor, "\"session.read\"").as_bytes())?;
        provision_local_principal_from_credentials(air_gapped, &credentials)?;
        assert!(load_local_principal(&SqliteStore::open(air_gapped)?)?.is_some());

        install(document(&actor, "\"timeline.events.read\"").as_bytes())?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        std::fs::write(credentials.join("extra"), b"")?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        Ok(())
    }

    // --- #309: provisioned consents and their revocation ---

    fn grant_draft(purpose: &str, categories: &[&str], export: bool) -> LocalConsentGrantDraftV1 {
        LocalConsentGrantDraftV1 {
            purpose: purpose.to_owned(),
            data_categories: categories
                .iter()
                .map(|category| (*category).to_owned())
                .collect(),
            export_permitted: export,
        }
    }

    fn consent_of(grants: Vec<LocalConsentGrantDraftV1>) -> TestResult<LocalConsentDraftV1> {
        Ok(LocalConsentDraftV1 {
            subject: actor()?,
            grantee: actor()?,
            grants,
        })
    }

    /// The operations of the consent tests.
    const CONSENTED_OPERATIONS: [GatewayOperationV1; 6] = [
        GatewayOperationV1::CREATE_TIMELINE,
        GatewayOperationV1::APPEND_SIGNAL,
        GatewayOperationV1::SUBMIT_WORLD_ACTION,
        GatewayOperationV1::READ_EVENTS,
        GatewayOperationV1::READ_SESSION,
        GatewayOperationV1::REVOKE_CONSENT,
    ];

    /// The Principal of the consent tests: one consent governs Timeline
    /// creation, one Society Signals and one World actions; reads, the
    /// Session and revocation are governed by none.
    fn consented_provision() -> TestResult<LocalPrincipalProvisionV1> {
        Ok(LocalPrincipalProvisionV1::try_new_with_consent(
            &principal()?,
            [actor()?],
            CONSENTED_OPERATIONS,
            Some(consent_of(vec![
                grant_draft("operation", &["timeline"], false),
                grant_draft("operation", &["society.signal"], true),
                grant_draft("action", &["world.action.v1"], false),
            ])?),
        )?)
    }

    /// The Gateway `serve` composes over the Local store at `path`.
    fn serve_local(path: &str) -> TestResult<(Gateway, Router)> {
        let mode = crate::mode_profile::test_binding(
            crate::mode_profile::GatewayModeProfileIdV1::Local,
            [],
        );
        let gateway = local_gateway(
            crate::mode_profile::test_attach_host(sqlite_host(path)?, &mode),
            None,
            &mode,
        )?;
        Ok((gateway.clone(), app_of(gateway)))
    }

    /// A Local store at `path` provisioned with `provision` through the
    /// production host path, and a Gateway over it that requires its
    /// recorded Principal, as `serve` composes it, with a World action
    /// catalogue that knows the actor's body, so an admitted action commits.
    fn consented_gateway(
        path: &str,
        provision: &LocalPrincipalProvisionV1,
    ) -> TestResult<(Gateway, Router)> {
        provision_on_host(&mut sqlite_host(path)?, provision)?;
        let mode = crate::mode_profile::test_binding(
            crate::mode_profile::GatewayModeProfileIdV1::Local,
            [],
        );
        let mut host = crate::mode_profile::test_attach_host(sqlite_host(path)?, &mode);
        let authorization =
            load_host_local_principal(&mut host, &mode)?.ok_or("a provisioned store recomposes")?;
        let gateway =
            crate::gateway_with_erasure_host_and_authorization(host, [actor()?], authorization)?;
        Ok((gateway.clone(), app_of(gateway)))
    }

    /// Submit one World action numbered `marker` on `timeline` as `actor`,
    /// under its own idempotency key.
    async fn act(
        app: &Router,
        timeline: &str,
        actor: EntityId,
        marker: u8,
    ) -> TestResult<(StatusCode, Value)> {
        let mut body = action(actor);
        body["payload"]["params"] = json!([f64::from(marker), 0.0]);
        body["payload"]["tick"] = json!(marker);
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/timelines/{timeline}/actions"))
            .header("idempotency-key", format!("action-{marker}"))
            .header(ACTOR_ENTITY_HEADER, actor.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let response = app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    }

    async fn revoke_with(
        app: &Router,
        actor: EntityId,
        consent_ref: &Value,
        key: &str,
    ) -> TestResult<(StatusCode, Value)> {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/me/consent-revocations")
            .header("idempotency-key", key)
            .header(ACTOR_ENTITY_HEADER, actor.to_string())
            .header("content-type", "application/json")
            .body(Body::from(json!({"consent_ref": consent_ref}).to_string()))?;
        let response = app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    async fn session_of(app: &Router, actor: EntityId) -> TestResult<Value> {
        let (status, body) = send(app, "GET", "/v1/session", Some(actor), None).await?;
        assert_eq!(status, StatusCode::OK);
        Ok(body)
    }

    /// Owner decisions 1(a) and 2(b) on #309, end to end through the
    /// production provisioning and serve composition: each consent governs
    /// exactly the operations of its purpose and data categories; revoking
    /// one blocks exactly those, a World action included, while the others
    /// and the ungoverned operations stay available; the revocation is
    /// recorded once and every later answer is the original, byte for byte,
    /// across a later consent change and a restart.
    #[tokio::test]
    async fn a_revoked_consent_stops_only_the_operations_it_governs() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        bind_local(&path)?;
        let actor = actor()?;
        let (gateway, app) = consented_gateway(&path, &consented_provision()?)?;

        let granted = session_of(&app, actor).await?;
        // The root grant, three consent-bound grants and three consents.
        assert_eq!(granted["generation"], 7);
        assert_eq!(
            granted["grants"],
            json!([
                "consent.revoke",
                "session.read",
                "timeline.create",
                "timeline.events.read",
                "timeline.signals.append",
                "world.action.v1.submit"
            ])
        );
        let refs = (0..3)
            .map(|index| granted["consents"][index]["consent_ref"].clone())
            .collect::<Vec<_>>();
        assert_eq!(granted["consents"][1]["export_permitted"], true);
        let (created, timeline) = create(&app, Some(actor)).await?;
        assert_eq!(created, StatusCode::CREATED);
        let timeline = timeline["id"].as_str().unwrap_or_default().to_owned();
        let signals = format!("/v1/timelines/{timeline}/signals");
        let (admitted, _) = act(&app, &timeline, actor, 1).await?;
        assert_eq!(admitted, StatusCode::CREATED);

        let (recorded, revocation) = revoke_with(&app, actor, &refs[0], "revoke-first").await?;
        assert_eq!(recorded, StatusCode::CREATED);
        assert_eq!(revocation["consent_ref"], refs[0]);
        assert_eq!(revocation["generation"], 4);
        assert_eq!(revocation["mode_profile"]["binding_epoch"], 1);
        assert_ne!(revocation["id"], refs[0]);
        // Only Timeline creation is revoked: Society Signals, governed by
        // the second consent, and reads stay available.
        let (denied, problem) = create(&app, Some(actor)).await?;
        assert_eq!(
            (denied, problem["code"].clone()),
            (StatusCode::FORBIDDEN, json!("revoked"))
        );
        assert_eq!(
            send(&app, "POST", &signals, Some(actor), Some(signal(actor)))
                .await?
                .0,
            StatusCode::CREATED
        );
        let events = format!("/v1/timelines/{timeline}/events");
        assert_eq!(
            send(&app, "GET", &events, Some(actor), None).await?.0,
            StatusCode::OK
        );
        // An exact retry and a fresh key return the original revocation.
        for key in ["revoke-first", "revoke-again"] {
            assert_eq!(
                revoke_with(&app, actor, &refs[0], key).await?,
                (StatusCode::OK, revocation.clone())
            );
        }
        // The key names the consent it revoked; an unknown consent is not found.
        let (conflict, problem) = revoke_with(&app, actor, &refs[1], "revoke-first").await?;
        assert_eq!(
            (conflict, problem["code"].clone()),
            (StatusCode::CONFLICT, json!("idempotency-conflict"))
        );
        let unknown = json!(EntityId::new().to_string());
        let (missing, problem) = revoke_with(&app, actor, &unknown, "missing").await?;
        assert_eq!(
            (missing, problem["code"].clone()),
            (StatusCode::NOT_FOUND, json!("not-found-or-unavailable"))
        );

        // Revoking the action consent revokes the World action.
        assert_eq!(
            revoke_with(&app, actor, &refs[2], "revoke-action").await?.0,
            StatusCode::CREATED
        );
        let (_, problem) = act(&app, &timeline, actor, 2).await?;
        assert_eq!(problem["code"], "revoked");
        let revoked = session_of(&app, actor).await?;
        assert_eq!(revoked["generation"], 9);
        assert_eq!(
            [0, 1, 2].map(|index| revoked["consents"][index]["state"].clone()),
            [json!("revoked"), json!("granted"), json!("revoked")]
        );
        assert_eq!(
            revoked["grants"],
            json!([
                "consent.revoke",
                "session.read",
                "timeline.events.read",
                "timeline.signals.append"
            ])
        );
        // After another consent changed, the original answer is unchanged.
        assert_eq!(
            revoke_with(&app, actor, &refs[0], "revoke-first").await?,
            (StatusCode::OK, revocation.clone())
        );
        gateway.shutdown().await?;
        drop(gateway);
        drop(app);

        // A restarted host recomposes every revocation from the consent
        // Timeline; the key still names the consent it revoked, and the
        // original answer is byte-identical.
        let (gateway, app) = consented_gateway(&path, &consented_provision()?)?;
        assert_eq!(
            session_of(&app, actor).await?["consents"],
            revoked["consents"]
        );
        let (conflict, _) = revoke_with(&app, actor, &refs[1], "revoke-first").await?;
        assert_eq!(conflict, StatusCode::CONFLICT);
        assert_eq!(
            revoke_with(&app, actor, &refs[0], "revoke-first").await?,
            (StatusCode::OK, revocation.clone())
        );
        gateway.shutdown().await?;
        drop(gateway);
        drop(app);

        // Under a later binding epoch, the answer still names the binding
        // the revocation was produced under.
        crate::mode_profile::migrate_gateway_mode_v1(
            &path,
            crate::mode_profile::GatewayModeProfileIdV1::Local,
            crate::mode_profile::GatewayModeProfileIdV1::AirGapped,
        )?;
        let mut host = sqlite_host(&path)?;
        let mode = crate::mode_profile::bind_gateway_mode_v1(
            crate::mode_profile::GatewayModeProfileIdV1::AirGapped,
            crate::mode_profile::GatewayServeCompositionV1 {
                tcp_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                owntracks_owner_key: None,
                fork_admission_socket: None,
                ledger_source: None,
                network_grants: std::collections::BTreeSet::new(),
            },
            &mut host,
        )?;
        let gateway = local_gateway(host, None, &mode)?;
        let app = app_of(gateway.clone());
        assert_eq!(
            revoke_with(&app, actor, &refs[0], "after-migration").await?,
            (StatusCode::OK, revocation)
        );
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    /// A consent the acting entity is not a party to is neither listed in
    /// its Session nor revocable, consent-governed operations are refused
    /// as consent-invalid, and a host without an authorizer revokes nothing.
    #[tokio::test]
    async fn only_a_party_sees_or_revokes_a_consent() -> TestResult {
        let other = EntityId::new();
        let provision = LocalPrincipalProvisionV1::try_new_with_consent(
            &principal()?,
            [actor()?, other],
            [
                GatewayOperationV1::CREATE_TIMELINE,
                GatewayOperationV1::REVOKE_CONSENT,
                GatewayOperationV1::READ_SESSION,
            ],
            Some(consent_of(vec![grant_draft(
                "operation",
                &["timeline"],
                false,
            )])?),
        )?;
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        bind_local(&path)?;
        let (gateway, app) = consented_gateway(&path, &provision)?;
        let consent = session_of(&app, actor()?).await?["consents"][0]["consent_ref"].clone();
        assert_eq!(session_of(&app, other).await?["consents"], json!([]));
        assert_eq!(
            revoke_with(&app, other, &consent, "other").await?.0,
            StatusCode::NOT_FOUND
        );
        let (refused, problem) = create(&app, Some(other)).await?;
        assert_eq!(
            (refused, problem["code"].clone()),
            (StatusCode::FORBIDDEN, json!("consent-invalid"))
        );
        gateway.shutdown().await?;
        drop(gateway);

        let open = Gateway::unprotected_for_harness(memory_host()?)?;
        let (status, problem) = revoke_with(&app_of(open.clone()), other, &consent, "open").await?;
        assert_eq!(
            (status, problem["code"].clone()),
            (StatusCode::UNAUTHORIZED, json!("unauthenticated"))
        );
        open.shutdown().await?;
        drop(open);
        Ok(())
    }

    /// A revocation waits for the operations admitted before it, and the
    /// next decision after it sees it.
    #[tokio::test]
    async fn a_revocation_waits_for_an_admitted_operation() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        bind_local(&path)?;
        let actor = actor()?;
        let (gateway, app) = consented_gateway(&path, &consented_provision()?)?;
        let consent = session_of(&app, actor).await?["consents"][0]["consent_ref"].clone();
        let admitted = gateway
            .authorize_operation(GatewayOperationV1::CREATE_TIMELINE, Some(actor), None, None)
            .await?;
        let revoking = tokio::spawn({
            let app = app.clone();
            async move {
                revoke_with(&app, actor, &consent, "racing")
                    .await
                    .map(|(status, _)| status)
                    .ok()
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !revoking.is_finished(),
            "the revocation waits for the admitted operation"
        );
        drop(admitted);
        assert_eq!(revoking.await?, Some(StatusCode::CREATED));
        assert_eq!(create(&app, Some(actor)).await?.0, StatusCode::FORBIDDEN);
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    /// No client seam reads or appends the consent Timeline.
    #[tokio::test]
    async fn no_client_seam_reaches_the_consent_timeline() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        bind_local(&path)?;
        let actor = actor()?;
        let (gateway, app) = consented_gateway(&path, &consented_provision()?)?;
        let consents = local_principal_consent_timeline();
        for (method, uri, body) in [
            ("GET", format!("/v1/timelines/{consents}/events"), None),
            (
                "POST",
                format!("/v1/timelines/{consents}/signals"),
                Some(signal(actor)),
            ),
            (
                "POST",
                format!("/v1/timelines/{consents}/actions"),
                Some(action(actor)),
            ),
        ] {
            let (status, problem) = send(&app, method, &uri, Some(actor), body).await?;
            assert_eq!(
                (status, problem["code"].clone()),
                (StatusCode::NOT_FOUND, json!("not-found-or-unavailable")),
                "{uri}"
            );
        }
        // The consents are intact.
        assert_eq!(
            session_of(&app, actor).await?["consents"][0]["state"],
            "granted"
        );
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    /// A permit's decision pins the consent Timeline as the store holds it:
    /// a revocation another serving process recorded is seen by the next
    /// decision.
    #[tokio::test]
    async fn a_decision_pins_the_current_consent_timeline() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        bind_local(&path)?;
        let actor = actor()?;
        let (gateway, app) = consented_gateway(&path, &consented_provision()?)?;
        let (other, other_app) = serve_local(&path)?;
        let consent = session_of(&app, actor).await?["consents"][0]["consent_ref"].clone();
        let consent_ref =
            pos_core::EventId::from_ulid(Ulid::from_string(consent.as_str().unwrap_or_default())?);
        let read = || {
            gateway.authorize_operation(GatewayOperationV1::READ_SESSION, Some(actor), None, None)
        };
        let permit = read().await?;
        assert!(gateway
            .consent_pinned(&permit, consent_ref)
            .is_some_and(|consent| consent.revocation().is_none()));
        drop(permit);
        // Another serving process revokes it.
        assert_eq!(
            revoke_with(&other_app, actor, &consent, "elsewhere")
                .await?
                .0,
            StatusCode::CREATED
        );
        let permit = read().await?;
        assert!(gateway
            .consent_pinned(&permit, consent_ref)
            .is_some_and(|consent| consent.revocation().is_some()));
        drop(permit);
        for gateway in [gateway, other] {
            gateway.shutdown().await?;
            drop(gateway);
        }
        drop((app, other_app));
        Ok(())
    }

    /// H1: a re-provisioning with another document is refused before it
    /// writes anything, whether it adds consents or replaces them.
    #[test]
    fn a_failed_reprovisioning_writes_nothing() -> TestResult {
        let without = provision([
            GatewayOperationV1::CREATE_TIMELINE,
            GatewayOperationV1::READ_SESSION,
            GatewayOperationV1::REVOKE_CONSENT,
        ])?;
        let with = consented_provision()?;
        let other = LocalPrincipalProvisionV1::try_new_with_consent(
            &principal()?,
            [actor()?],
            CONSENTED_OPERATIONS,
            Some(consent_of(vec![grant_draft(
                "operation",
                &["timeline", "society.signal"],
                false,
            )])?),
        )?;
        for (first, second) in [(&without, &with), (&with, &other), (&with, &without)] {
            let directory = tempfile::tempdir()?;
            let path = sqlite_path(&directory)?;
            bind_local(&path)?;
            provision_on_host(&mut sqlite_host(&path)?, first)?;
            let before = recorded_state(&path)?;
            assert!(provision_on_host(&mut sqlite_host(&path)?, second).is_err());
            assert_eq!(recorded_state(&path)?, before);
            // The first document is still an exact retry.
            provision_on_host(&mut sqlite_host(&path)?, first)?;
        }
        Ok(())
    }

    /// The authority chains and consent Timeline Events the store at `path`
    /// records.
    fn recorded_state(path: &str) -> TestResult<(Vec<Option<PersistedAuthorityV1>>, Vec<Vec<u8>>)> {
        let store = SqliteStore::open(path)?;
        let chains = [LocalGrantKindV1::Root]
            .into_iter()
            .chain((0..4).map(LocalGrantKindV1::Consented))
            .map(|kind| load_chain(&store, kind))
            .collect::<Result<Vec<_>, _>>()?;
        let mut host = sqlite_host(path)?;
        let timeline = local_principal_consent_timeline();
        let events = if host.command_sender()?.timeline(timeline)?.is_some() {
            host.read_sender()?
                .read_bounded(timeline, SeqRange::all(), consent_bounds())?
                .into_iter()
                .map(|event| event.payload.as_slice().to_vec())
                .collect()
        } else {
            Vec::new()
        };
        Ok((chains, events))
    }

    #[test]
    fn a_consent_document_is_validated_before_anything_is_recorded() -> TestResult {
        let refused = |granted: &[GatewayOperationV1], consent| -> TestResult<bool> {
            Ok(LocalPrincipalProvisionV1::try_new_with_consent(
                &principal()?,
                [actor()?],
                granted.iter().copied(),
                Some(consent),
            ) == Err(LocalPrincipalErrorV1::Invalid))
        };
        let operations = &CONSENTED_OPERATIONS[..];
        let timeline = || grant_draft("operation", &["timeline"], false);
        assert!(!refused(operations, consent_of(vec![timeline()])?)?);
        let too_many = vec![timeline(); MAX_CAPABILITY_CONSENT_REFERENCES + 1];
        for (label, granted, consent) in [
            ("no grant", operations, consent_of(Vec::new())?),
            ("too many grants", operations, consent_of(too_many)?),
            (
                "a long purpose",
                operations,
                consent_of(vec![grant_draft(&"p".repeat(129), &["timeline"], false)])?,
            ),
            (
                "an unknown purpose",
                operations,
                consent_of(vec![grant_draft("marketing", &["timeline"], false)])?,
            ),
            (
                "an ungranted category",
                operations,
                consent_of(vec![grant_draft(
                    "operation",
                    &["ledger.prediction"],
                    false,
                )])?,
            ),
            (
                "an exempt operation",
                operations,
                consent_of(vec![grant_draft("read", &["session"], false)])?,
            ),
            (
                "an operation two consents govern",
                operations,
                consent_of(vec![
                    timeline(),
                    grant_draft("operation", &["timeline", "society.signal"], false),
                ])?,
            ),
            (
                "no ungoverned operation",
                &operations[..1],
                consent_of(vec![timeline()])?,
            ),
            (
                "a subject who does not act",
                operations,
                LocalConsentDraftV1 {
                    subject: EntityId::new(),
                    ..consent_of(vec![timeline()])?
                },
            ),
            (
                "a grantee who does not act",
                operations,
                LocalConsentDraftV1 {
                    grantee: EntityId::new(),
                    ..consent_of(vec![timeline()])?
                },
            ),
        ] {
            assert!(refused(granted, consent)?, "{label}");
        }
        assert!(GatewayOperationV1::REVOKE_CONSENT.consent_exempt());
        assert!(!GatewayOperationV1::SUBMIT_WORLD_ACTION.consent_exempt());
        Ok(())
    }

    #[test]
    fn a_consent_table_is_parsed_from_the_document() -> TestResult {
        let base = document(
            &format!("\"{ACTOR}\""),
            "\"consent.revoke\", \"session.read\", \"timeline.create\"",
        );
        let table = format!(
            "{base}[consent]\nsubject_entity_id = \"{ACTOR}\"\ngrantee_entity_id = \"{ACTOR}\"\n\n\
             [[consent.grants]]\npurpose = \"operation\"\ndata_categories = [\"timeline\"]\n\
             export_permitted = true\n"
        );
        let parsed = LocalPrincipalProvisionV1::from_toml(&table)?;
        let built = LocalPrincipalProvisionV1::try_new_with_consent(
            &principal()?,
            [actor()?],
            [
                GatewayOperationV1::REVOKE_CONSENT,
                GatewayOperationV1::READ_SESSION,
                GatewayOperationV1::CREATE_TIMELINE,
            ],
            Some(consent_of(vec![grant_draft(
                "operation",
                &["timeline"],
                true,
            )])?),
        )?;
        assert_eq!(parsed, built);
        assert_ne!(parsed, LocalPrincipalProvisionV1::from_toml(&base)?);
        for broken in [
            table.replace("subject_entity_id = \"", "subject_entity_id = \"x"),
            table.replace("grantee_entity_id = \"", "grantee_entity_id = \"x"),
            table.replace(
                "export_permitted = true",
                "export_permitted = true\nextra = 1",
            ),
        ] {
            assert_eq!(
                LocalPrincipalProvisionV1::from_toml(&broken),
                Err(LocalPrincipalErrorV1::Invalid)
            );
        }
        Ok(())
    }

    /// A store's consent Timeline holds one provisioning's consents: other
    /// consents, or consents for a provisioning that binds none, conflict.
    #[test]
    fn a_consent_timeline_holds_one_provisioning() -> TestResult {
        let mut host = memory_host()?;
        provision_local_consents(&mut host, &served_provision()?)?;
        provision_local_consents(&mut host, &consented_provision()?)?;
        provision_local_consents(&mut host, &consented_provision()?)?;
        for conflicting in [
            served_provision()?,
            LocalPrincipalProvisionV1::try_new_with_consent(
                &principal()?,
                [actor()?],
                CONSENTED_OPERATIONS,
                Some(consent_of(vec![grant_draft(
                    "operation",
                    &["timeline"],
                    true,
                )])?),
            )?,
        ] {
            assert_eq!(
                provision_local_consents(&mut host, &conflicting),
                Err(LocalPrincipalErrorV1::Conflict)
            );
        }
        Ok(())
    }

    /// The consent-bound grants of `provision` and its consents as Events of
    /// the consent Timeline at sequences 1, 2, ...
    fn consent_events(
        provision: &LocalPrincipalProvisionV1,
    ) -> TestResult<(Vec<CapabilityGrantV1>, Vec<Event>)> {
        let grants = provision
            .consents
            .iter()
            .map(|(grant, _)| grant.clone())
            .collect();
        let events = provision
            .consents
            .iter()
            .map(|(_, record)| -> TestResult<Event> {
                Ok(consent_event(
                    record.subject_id,
                    EVENT_TYPE_CONSENT_GRANTED_V1,
                    record.encode()?,
                    record.grant_seq,
                ))
            })
            .collect::<TestResult<Vec<_>>>()?;
        Ok((grants, events))
    }

    fn consent_event(
        entity: EntityId,
        event_type: &str,
        payload: CanonicalBytes,
        seq: u64,
    ) -> Event {
        Event {
            id: pos_core::EventId::new(),
            entity,
            event_type: Kind::new(event_type),
            payload,
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: pos_core::SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0; 32]),
        }
    }

    /// A consent Timeline this host cannot reproduce exactly is refused; an
    /// exact duplicate revocation keeps the first fence (L3).
    #[test]
    fn a_consent_timeline_out_of_contract_is_refused() -> TestResult {
        let (grants, events) = consent_events(&consented_provision()?)?;
        let consents = local_consents(&grants, &events).ok_or("the recorded consents replay")?;
        assert_eq!(consents.disclosed().len(), 3);
        assert_eq!(consents.head(), Seq::from_u64(3));
        let revocation = |grant_seq: u64, seq: u64| -> TestResult<Event> {
            Ok(consent_event(
                actor()?,
                EVENT_TYPE_CONSENT_REVOKED_V1,
                ConsentRevokedV1 {
                    subject_id: actor()?,
                    grantee_id: actor()?,
                    grant_seq,
                    fence_seq: seq,
                }
                .encode()?,
                seq,
            ))
        };
        let duplicated = [events.clone(), vec![revocation(1, 4)?, revocation(1, 5)?]].concat();
        let replayed =
            local_consents(&grants, &duplicated).ok_or("a duplicate revocation replays")?;
        assert_eq!(
            replayed.disclosed()[0]
                .revocation()
                .map(|revocation| revocation.fence()),
            Some(Seq::from_u64(4))
        );
        assert!(replayed.disclosed()[1].revocation().is_none());
        let mut foreign = events.clone();
        foreign[0].entity = EntityId::new();
        let mut shifted = events.clone();
        shifted[1].seq = Seq::from_u64(4);
        let mut unknown = events.clone();
        unknown[0].event_type = Kind::new("consent.renewed.v1");
        let mut garbled = events.clone();
        garbled[1].payload = CanonicalBytes::from_static(b"garbled");
        let mut late_revocation = revocation(1, 4)?;
        late_revocation.seq = Seq::from_u64(5);
        let mut foreign_revocation = revocation(1, 4)?;
        foreign_revocation.entity = EntityId::new();
        let mixed = vec![grants[0].clone(), local_grant_without_subject(&grants[1])?];
        for (label, grants, events) in [
            ("a foreign entity", &grants, foreign),
            ("a grant at another sequence", &grants, shifted),
            ("an unknown event type", &grants, unknown),
            ("a garbled payload", &grants, garbled),
            ("a missing grant", &grants, events[..2].to_vec()),
            (
                "a repeated grant",
                &grants,
                [events.clone(), vec![events[0].clone()]].concat(),
            ),
            (
                "a revocation of no grant",
                &grants,
                [events.clone(), vec![revocation(7, 4)?]].concat(),
            ),
            (
                "a revocation at another sequence",
                &grants,
                [events.clone(), vec![late_revocation]].concat(),
            ),
            (
                "a revocation by a foreign entity",
                &grants,
                [events.clone(), vec![foreign_revocation]].concat(),
            ),
            ("grants without one subject", &mixed, events.clone()),
        ] {
            assert!(local_consents(grants, &events).is_none(), "{label}");
        }
        Ok(())
    }

    /// `grant` with no subject in its scope.
    fn local_grant_without_subject(grant: &CapabilityGrantV1) -> TestResult<CapabilityGrantV1> {
        Ok(root_grant(
            grant.grantor(),
            LocalGrantKindV1::Consented(1),
            (
                grant.scope().actor_entity_ids(),
                [GatewayOperationV1::APPEND_SIGNAL].as_slice(),
            ),
            None,
            grant.authority_registry_digest(),
        )?)
    }

    /// The pinned lookup #303 calls under its operation permit: it reads the
    /// decision's pin, and a revocation waits until the permit is released.
    #[tokio::test]
    async fn the_pinned_consent_lookup_holds_under_the_permit() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        bind_local(&path)?;
        let actor = actor()?;
        let (gateway, app) = consented_gateway(&path, &consented_provision()?)?;
        let consent = session_of(&app, actor).await?["consents"][0]["consent_ref"].clone();
        let consent_ref =
            pos_core::EventId::from_ulid(Ulid::from_string(consent.as_str().unwrap_or_default())?);
        let read = || {
            gateway.authorize_operation(GatewayOperationV1::READ_SESSION, Some(actor), None, None)
        };
        let permit = read().await?;
        let pinned = gateway
            .consent_pinned(&permit, consent_ref)
            .ok_or("the consent is pinned")?;
        assert!(pinned.revocation().is_none());
        assert_eq!(
            gateway.consent_pinned(&permit, pos_core::EventId::new()),
            None
        );
        let revoking = tokio::spawn({
            let app = app.clone();
            async move {
                revoke_with(&app, actor, &consent, "under-permit")
                    .await
                    .map(|(status, _)| status)
                    .ok()
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !revoking.is_finished(),
            "the revocation waits for the permit"
        );
        assert_eq!(gateway.consent_pinned(&permit, consent_ref), Some(pinned));
        drop(permit);
        assert_eq!(revoking.await?, Some(StatusCode::CREATED));
        let permit = read().await?;
        assert!(gateway
            .consent_pinned(&permit, consent_ref)
            .is_some_and(|consent| consent.revocation().is_some()));
        drop(permit);
        let open = Gateway::unprotected_for_harness(memory_host()?)?;
        let unprotected = open
            .authorize_operation(GatewayOperationV1::READ_SESSION, Some(actor), None, None)
            .await?;
        assert_eq!(open.consent_pinned(&unprotected, consent_ref), None);
        drop(unprotected);
        for gateway in [gateway, open] {
            gateway.shutdown().await?;
            drop(gateway);
        }
        drop(app);
        Ok(())
    }

    /// Actions decided on a consent-bound chain and appends decided on the
    /// root chain alternate on one Timeline, and an action decided on the
    /// root chain commits too: each admission persists and re-checks the
    /// chain its decision was taken on, and the recorded chains are the
    /// provisioned ones.
    #[tokio::test]
    async fn actions_persist_the_chain_they_were_decided_on() -> TestResult {
        let with_consents = |grants| -> TestResult<LocalPrincipalProvisionV1> {
            Ok(LocalPrincipalProvisionV1::try_new_with_consent(
                &principal()?,
                [actor()?],
                CONSENTED_OPERATIONS,
                Some(consent_of(grants)?),
            )?)
        };
        // Consented actions beside root-chain signals, then root-chain
        // actions beside consented signals.
        let consented_actions = with_consents(vec![
            grant_draft("operation", &["timeline"], false),
            grant_draft("action", &["world.action.v1"], false),
        ])?;
        let root_actions = with_consents(vec![
            grant_draft("operation", &["timeline"], false),
            grant_draft("operation", &["society.signal"], false),
        ])?;
        for (provision, actions_consented) in [(consented_actions, true), (root_actions, false)] {
            let directory = tempfile::tempdir()?;
            let path = sqlite_path(&directory)?;
            bind_local(&path)?;
            let actor = actor()?;
            let before = {
                provision_on_host(&mut sqlite_host(&path)?, &provision)?;
                recorded_state(&path)?
            };
            let (gateway, app) = consented_gateway(&path, &provision)?;
            let (created, timeline) = create(&app, Some(actor)).await?;
            assert_eq!(created, StatusCode::CREATED);
            let timeline = timeline["id"].as_str().unwrap_or_default().to_owned();
            let signals = format!("/v1/timelines/{timeline}/signals");
            for marker in 1..=3 {
                assert_eq!(
                    act(&app, &timeline, actor, marker).await?.0,
                    StatusCode::CREATED
                );
                let (status, _) =
                    send(&app, "POST", &signals, Some(actor), Some(signal(actor))).await?;
                assert_eq!(status, StatusCode::CREATED, "{actions_consented}");
            }
            gateway.shutdown().await?;
            drop((gateway, app));
            assert_eq!(recorded_state(&path)?, before, "{actions_consented}");
        }
        Ok(())
    }
}
