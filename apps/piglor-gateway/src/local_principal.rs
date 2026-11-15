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
//! operations = ["timeline.create"]
//!
//! [[consent.grants]]
//! purpose = "local decision preview"
//! export_permitted = false
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
//! A document with a `[consent]` table (owner decision 1(a) on #309) records
//! each of its grants as one `consent.granted.v1` Event on the Principal's
//! one consent Timeline, [`local_principal_consent_timeline`], and splits the
//! Principal's operations over two grants: its root grant keeps the
//! operations no consent governs, and a consent-bound root grant on its own
//! authority Timeline covers the consented operations, names the consent
//! subject and references every consent. Each referenced consent is named
//! by the BLAKE3 derivation of its canonical `consent.granted.v1` payload, so
//! the document alone fixes both grants. The consent-bound grant is decided
//! by the ADR-059 evaluator, which requires every referenced consent to be
//! active and to cover the request, so all of the document's consents cover
//! its consented operations and share one subject and one grantee. No
//! consent may govern an exempt operation
//! ([`GatewayOperationV1::consent_exempt`]).
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
    GatewayAuthorization, GatewayConsentRecordV1, GatewayConsentV1, GatewayConsentedAuthorityV1,
    GatewayConsentsV1, GatewayOperationV1, GatewayPinnedAuthorityV1, LocalAuthenticationAdapter,
    OwnTracksOwnerKey,
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
    operations: Vec<String>,
    grants: Vec<LocalConsentGrantDraftV1>,
}

/// One consent of a provisioning: its ADR-039 purpose and whether it
/// permits export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalConsentGrantDraftV1 {
    /// The purpose the subject consents to, at most 128 UTF-8 bytes.
    pub purpose: String,
    /// Whether the consent permits export.
    pub export_permitted: bool,
}

/// The consents of a provisioning (#309): the operations they govern, the
/// subject who consents and the actor they grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalConsentDraftV1 {
    /// The entity whose data the consents govern; one of the actors.
    pub subject: EntityId,
    /// The actor the consents grant; one of the actors.
    pub grantee: EntityId,
    /// The consented operations: granted operations no exempt operation.
    pub operations: Vec<GatewayOperationV1>,
    /// The consents, recorded in this order.
    pub grants: Vec<LocalConsentGrantDraftV1>,
}

/// One validated Local Principal provisioning: its root capability grant,
/// its consent-bound grant and consent records when it binds consents, and
/// the authority registry snapshot that attests them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPrincipalProvisionV1 {
    grant: CapabilityGrantV1,
    consent: Option<(CapabilityGrantV1, Vec<ConsentGrantedV1>)>,
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
    /// with `consent` governing its consented operations.
    ///
    /// # Errors
    /// Returns [`LocalPrincipalErrorV1::Invalid`] for an empty or oversized
    /// actor or operation set, an invalid Principal or entity, or a consent
    /// that names no grant, more than
    /// [`MAX_CAPABILITY_CONSENT_REFERENCES`] grants, an over-long purpose, a
    /// subject or grantee that is not an actor, or an operation that is not
    /// granted or is exempt, or that leaves no operation unconsented.
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
        let consent = consent.map(|mut consent| {
            consent.operations = sorted_operations(consent.operations);
            consent
        });
        let registry_digest = registry_digest(principal, &actors, &operations, consent.as_ref());
        consent
            .as_ref()
            .map_or(Ok(()), |consent| {
                validate_consent(consent, &actors, &operations)
            })
            .and_then(|()| {
                let unconsented = operations
                    .iter()
                    .copied()
                    .filter(|operation| {
                        consent
                            .as_ref()
                            .is_none_or(|consent| !consent.operations.contains(operation))
                    })
                    .collect::<Vec<_>>();
                let grant = root_grant(
                    principal,
                    LocalGrantKindV1::Root,
                    (actors.as_slice(), unconsented.as_slice()),
                    None,
                    registry_digest,
                );
                let consent = consent
                    .map(|consent| consented_grant(principal, &actors, &consent, registry_digest))
                    .transpose();
                grant
                    .map_err(|_| LocalPrincipalErrorV1::Invalid)
                    .and_then(|grant| consent.map(|consent| (grant, consent)))
            })
            .and_then(|(grant, consent)| {
                consent
                    .as_ref()
                    .map_or(Ok(Vec::new()), |(consented, records)| {
                        records
                            .iter()
                            .map(|record| {
                                consent_reference(consented, record)
                                    .map(|reference| reference.binding_digest())
                            })
                            .collect()
                    })
                    .and_then(|bindings| {
                        let consented = consent
                            .as_ref()
                            .map(|(consented, _)| (consented, consented));
                        authority_for((&grant, &grant), consented, bindings)
                    })
                    .map(|(_, registry)| Self {
                        grant,
                        consent,
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
                let operations = named_operations(&document.operations);
                let consent = document.consent.map_or(Some(None), |consent| {
                    entity(&consent.subject_entity_id)
                        .zip(entity(&consent.grantee_entity_id))
                        .zip(named_operations(&consent.operations))
                        .map(|((subject, grantee), operations)| {
                            Some(LocalConsentDraftV1 {
                                subject,
                                grantee,
                                operations,
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

/// The two root grants a Local Principal may hold.
#[derive(Clone, Copy)]
enum LocalGrantKindV1 {
    /// The grant of the operations no consent governs.
    Root,
    /// The consent-bound grant of the consented operations.
    Consented,
}

impl LocalGrantKindV1 {
    /// The grant's identity and its authority Timeline.
    fn identity(self) -> (Hash, TimelineId) {
        match self {
            Self::Root => (
                local_principal_grant_id(),
                local_principal_authority_timeline(),
            ),
            Self::Consented => (
                derived_hash("pigloros gateway local principal consent grant v1"),
                derived_timeline("pigloros gateway local principal consent authority timeline v1"),
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

/// The consent-bound grant of `consent` and its `consent.granted.v1`
/// records, the `n`-th at consent Timeline sequence `n`.
fn consented_grant(
    principal: &PrincipalRefV1,
    actors: &[EntityId],
    consent: &LocalConsentDraftV1,
    registry_digest: Hash,
) -> Result<(CapabilityGrantV1, Vec<ConsentGrantedV1>), LocalPrincipalErrorV1> {
    let records = consent
        .grants
        .iter()
        .zip(1_u64..)
        .map(|(grant, grant_seq)| ConsentGrantedV1 {
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
        })
        .collect::<Vec<_>>();
    records
        .iter()
        .map(|record| record.encode().map(|payload| consent_id(&payload)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LocalPrincipalErrorV1::Invalid)
        .and_then(|mut references| {
            references.sort_unstable();
            root_grant(
                principal,
                LocalGrantKindV1::Consented,
                (actors, consent.operations.as_slice()),
                Some((consent.subject, references)),
                registry_digest,
            )
            .map_err(|_| LocalPrincipalErrorV1::Invalid)
        })
        .map(|grant| (grant, records))
}

/// A consent's grants, operations and parties against the document.
fn validate_consent(
    consent: &LocalConsentDraftV1,
    actors: &[EntityId],
    operations: &[GatewayOperationV1],
) -> Result<(), LocalPrincipalErrorV1> {
    let grants_bounded = (1..=MAX_CAPABILITY_CONSENT_REFERENCES).contains(&consent.grants.len());
    let parties_act = actors.contains(&consent.subject) && actors.contains(&consent.grantee);
    let operations_consentable = !consent.operations.is_empty()
        && consent
            .operations
            .iter()
            .all(|operation| operations.contains(operation) && !operation.consent_exempt());
    (grants_bounded && parties_act && operations_consentable)
        .then_some(())
        .ok_or(LocalPrincipalErrorV1::Invalid)
}

/// Record the consents of `provision` on the Principal's consent Timeline
/// of the store `host` owns; a provisioning that binds none records nothing.
///
/// The consent Timeline is opened under its well-known identity and each
/// consent is appended as one `consent.granted.v1` Event, in document order,
/// in one bounded commit. An exact retry finds the same grants (and any
/// revocation recorded since) and records nothing.
///
/// # Errors
/// Returns [`LocalPrincipalErrorV1::Conflict`] when the consent Timeline
/// holds other consents, and [`LocalPrincipalErrorV1::Unavailable`] when the
/// host cannot open, read or append it.
pub fn provision_local_consents(
    host: &mut ErasureExecutionHostV1,
    provision: &LocalPrincipalProvisionV1,
) -> Result<(), LocalPrincipalErrorV1> {
    let Some((_, records)) = provision.consent.as_ref() else {
        return Ok(());
    };
    let authority = ConsentAuthority::new();
    let timeline = local_principal_consent_timeline();
    host.bind_consent_authority(authority.append_permit())
        .and_then(|()| {
            host.command_sender()
                .and_then(|mut sender| sender.open_root_timeline(timeline, CONSENT_TIMELINE_NAME))
        })
        .and_then(|_| {
            host.read_sender().and_then(|mut reads| {
                reads.read_bounded(timeline, SeqRange::all(), consent_bounds())
            })
        })
        .map_err(|_| LocalPrincipalErrorV1::Unavailable)
        .and_then(|recorded| {
            if !recorded.is_empty() {
                return recorded_grants_are(&recorded, records)
                    .then_some(())
                    .ok_or(LocalPrincipalErrorV1::Conflict);
            }
            records
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
                .map_err(|_| LocalPrincipalErrorV1::Invalid)
                .and_then(|drafts| {
                    host.command_sender()
                        .and_then(|mut sender| {
                            sender.append_consent_bounded(
                                timeline,
                                &drafts,
                                authority.append_permit(),
                                u64::try_from(MAX_CONSENT_HISTORY_EVENTS).unwrap_or(u64::MAX),
                            )
                        })
                        .ok()
                        .flatten()
                        .map(drop)
                        .ok_or(LocalPrincipalErrorV1::Unavailable)
                })
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
/// Its root capability grant, and its consent-bound grant when it binds
/// consents, commit under permits of the [`AuthorityPersistenceHostV1`] its
/// registry snapshot attests. An exact retry is
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
        .and_then(|()| {
            provision.consent.iter().try_for_each(|(consented, _)| {
                host.authorize_grant(consented)
                    .and_then(|permit| store.issue_capability_grant(permit, consented))
                    .map(drop)
            })
        })
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
/// its mode does not allow, then record the consents and persist the
/// Principal of `provision`.
///
/// # Errors
/// Returns an error when the store is unbound or bound to a mode that
/// refuses the Principal, or provisioning fails.
pub fn provision_on_host(
    host: &mut ErasureExecutionHostV1,
    provision: &LocalPrincipalProvisionV1,
) -> io::Result<()> {
    crate::mode_profile::attach_offline_writer_v1(host.gateway_mode_binding())
        .and_then(|mode| admit_in_mode(provision, mode))
        .map_err(io::Error::other)
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
    if crate::authorization::scope_names(provision.grant.scope(), GatewayOperationV1::NETWORK) {
        crate::mode_profile::refuse_air_gapped(mode)
    } else {
        Ok(())
    }
}

/// Compose the Local Principal recorded in `store` as the Gateway
/// authorizer, or `None` when the store has none (an unprovisioned host).
///
/// Reading never writes the store. A Principal whose provisioning binds
/// consents is composed with its consent-bound chain and unread consents: the
/// host reads its consent Timeline before its first decision.
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
            load_chain(store, LocalGrantKindV1::Consented).and_then(|consented| {
                compose(&GatewayAuthorityRecordV1 {
                    chain,
                    consented: consented.map(|chain| GatewayConsentRecordV1 {
                        chain,
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
/// store's record under the one Local Principal grant identity, and the
/// consent-bound grant and consent Timeline when its provisioning binds
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
                authority_for(
                    (&issued, root),
                    consented.as_ref().map(RecordedConsentV1::grants),
                    bindings,
                )
                .ok()
                .and_then(|(evidence, registry)| {
                    let host = AuthorityPersistenceHostV1::new(&registry);
                    replayed_view(&host, &issued, &record.chain)
                        .zip(
                            consented.map_or(Some(None), |consented| {
                                consented.authority(&host).map(Some)
                            }),
                        )
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

/// One recorded consent-bound chain: its record, its as-issued and recorded
/// root grant, and its consents once read.
struct RecordedConsentV1<'a> {
    record: &'a GatewayConsentRecordV1,
    issued: CapabilityGrantV1,
    root: &'a CapabilityGrantV1,
    consents: Option<GatewayConsentsV1>,
}

impl<'a> RecordedConsentV1<'a> {
    /// The recorded consent-bound chain of `record`, or `None` when its root
    /// grant or its read consent Timeline cannot be reproduced.
    fn of(record: &'a GatewayConsentRecordV1) -> Option<Self> {
        issued_root(&record.chain).and_then(|(issued, root)| {
            record
                .events
                .as_deref()
                .map_or(Some(None), |events| {
                    local_consents(&issued, events).map(Some)
                })
                .map(|consents| Self {
                    record,
                    issued,
                    root,
                    consents,
                })
        })
    }

    /// The as-issued and recorded root grant.
    const fn grants(&self) -> (&CapabilityGrantV1, &CapabilityGrantV1) {
        (&self.issued, self.root)
    }

    /// The registry bindings of the read consents.
    fn bindings(&self) -> Vec<Hash> {
        self.consents
            .as_ref()
            .map_or_else(Vec::new, |consents| consents.bindings().collect())
    }

    /// The consent-bound authority, when its chain reproduces the record.
    fn authority(self, host: &AuthorityPersistenceHostV1) -> Option<GatewayConsentedAuthorityV1> {
        replayed_view(host, &self.issued, &self.record.chain).map(|view| {
            GatewayConsentedAuthorityV1::new(
                view,
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

/// One replayed consent and the ADR-059 identity of its grant payload.
type ReplayedConsentV1 = (GatewayConsentV1, Hash);

/// The consents of the consent-bound `grant` recorded in `events`, the
/// consent Timeline in order.
///
/// Every Event is a `consent.granted.v1` at its own sequence or a
/// `consent.revoked.v1` of an earlier, unrevoked grant at its own sequence,
/// all of the grant's subject, and the granted consents are exactly the ones
/// the grant references. Anything else is refused.
fn local_consents(grant: &CapabilityGrantV1, events: &[Event]) -> Option<GatewayConsentsV1> {
    grant
        .scope()
        .subject_ids()
        .first()
        .copied()
        .and_then(|subject| {
            events
                .iter()
                .try_fold(Vec::new(), |consents, event| {
                    replay_consent_event(consents, subject, event)
                })
                .and_then(|consents| {
                    let head = events.last().map_or(Seq::ZERO, |event| event.seq);
                    consent_state(grant, subject, head, consents)
                })
        })
}

/// `consents` after the consent Timeline Event `event` of `subject`.
fn replay_consent_event(
    mut consents: Vec<ReplayedConsentV1>,
    subject: EntityId,
    event: &Event,
) -> Option<Vec<ReplayedConsentV1>> {
    let at_own_seq = |seq: u64| seq == event.seq.as_u64();
    match event.event_type.as_str() {
        EVENT_TYPE_CONSENT_GRANTED_V1 => ConsentGrantedV1::decode(&event.payload)
            .ok()
            .filter(|granted| {
                event.entity == subject
                    && granted.subject_id == subject
                    && at_own_seq(granted.grant_seq)
            })
            .map(|granted| {
                consents.push((
                    GatewayConsentV1::new(
                        event.id,
                        granted.grantee_id,
                        event.seq,
                        granted.export_permitted,
                        None,
                    ),
                    consent_id(&event.payload),
                ));
                consents
            }),
        EVENT_TYPE_CONSENT_REVOKED_V1 => ConsentRevokedV1::decode(&event.payload)
            .ok()
            .filter(|revoked| {
                event.entity == subject
                    && revoked.subject_id == subject
                    && at_own_seq(revoked.fence_seq)
            })
            .and_then(|revoked| {
                consents
                    .iter_mut()
                    .find(|(consent, _)| {
                        consent.grant_seq().as_u64() == revoked.grant_seq
                            && consent.grantee() == revoked.grantee_id
                            && consent.revocation().is_none()
                    })
                    .map(|(consent, _)| *consent = consent.revoked_at(event.id, event.seq))
            })
            .map(|()| consents),
        _ => None,
    }
}

/// The consents of `subject` at `head`, when the replayed grants are
/// exactly the ones the consent-bound `grant` references.
fn consent_state(
    grant: &CapabilityGrantV1,
    subject: EntityId,
    head: Seq,
    consents: Vec<ReplayedConsentV1>,
) -> Option<GatewayConsentsV1> {
    consents
        .iter()
        .map(|(consent, id)| {
            consent_reference_of(
                grant,
                (*id, subject, consent.grantee()),
                consent.grant_seq(),
                consent.revocation().map(|(_, fence)| fence),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .ok()
        .and_then(|mut references| {
            references.sort_unstable_by_key(ConsentGrantRefV1::consent_id);
            references
                .iter()
                .map(ConsentGrantRefV1::consent_id)
                .eq(grant.consent_references().iter().copied())
                .then(|| {
                    GatewayConsentsV1::new(
                        local_principal_consent_timeline(),
                        head,
                        subject,
                        references,
                        consents.into_iter().map(|(consent, _)| consent).collect(),
                    )
                })
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

/// The ADR-059 record of the consent `(consent_id, subject, grantee)` of the
/// consent-bound `grant`: it covers exactly the grant's resources, actions,
/// purposes and audiences, has no wall-clock expiry and is withdrawn at its
/// ADR-039 fence.
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
/// recorded form, the consent-bound grant's two forms when given, and the
/// registry bindings of its consents; all are functions of the recorded
/// grants and consent Timeline.
///
/// A recorded revocation changes a grant's resolved form, and a consent
/// revocation its ADR-059 record, so attesting them lets the evaluator answer
/// a revoked Principal or consent `revoked` rather than `unauthorized`. The
/// evidence has no expiry: loopback reachability, not a credential, is the
/// Local trust boundary (D1), so it is valid from the epoch on.
fn authority_for(
    grant: (&CapabilityGrantV1, &CapabilityGrantV1),
    consented: Option<(&CapabilityGrantV1, &CapabilityGrantV1)>,
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
            let consent_grants =
                consented.map_or_else(Vec::new, |(issued, current)| vec![issued, current]);
            [issued, current]
                .into_iter()
                .chain(consent_grants)
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
        hasher.update(&(consent.operations.len() as u64).to_be_bytes());
        for operation in &consent.operations {
            framed(&mut hasher, operation.name().as_bytes());
        }
        hasher.update(&(consent.grants.len() as u64).to_be_bytes());
        for grant in &consent.grants {
            framed(&mut hasher, grant.purpose.as_bytes());
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

fn named_operations(names: &[String]) -> Option<Vec<GatewayOperationV1>> {
    names
        .iter()
        .map(|name| GatewayOperationV1::named(name))
        .collect()
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
                Err(crate::mode_profile::GatewayModeErrorV1::RefusedInMode)
            );
            assert_eq!(admit_in_mode(&networked, Local), Ok(()));
            assert_eq!(admit_in_mode(&reader, AirGapped), Ok(()));
        }
        let refused = read_session(&networked, (AirGapped, &[]), false, Some(actor()?)).await;
        assert!(
            refused.is_err_and(|error| error.to_string().contains("refuses this operation")),
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

        install(document(&actor, "\"timeline.events.read\"").as_bytes())?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        std::fs::write(credentials.join("extra"), b"")?;
        assert!(provision_local_principal_from_credentials(path, &credentials).is_err());
        Ok(())
    }

    // --- #309: provisioned consents and their revocation ---

    /// The consent of the consent tests: the actor consents for itself to
    /// `operations`, once per purpose.
    fn consent_draft(
        operations: Vec<GatewayOperationV1>,
        purposes: &[&str],
    ) -> TestResult<LocalConsentDraftV1> {
        Ok(LocalConsentDraftV1 {
            subject: actor()?,
            grantee: actor()?,
            operations,
            grants: purposes
                .iter()
                .map(|purpose| LocalConsentGrantDraftV1 {
                    purpose: (*purpose).to_owned(),
                    export_permitted: purpose.starts_with("export"),
                })
                .collect(),
        })
    }

    /// The Principal of the consent tests: Timeline creation is governed by
    /// `purposes`, reads, the Session and revocation are not.
    fn consented_provision(purposes: &[&str]) -> TestResult<LocalPrincipalProvisionV1> {
        Ok(LocalPrincipalProvisionV1::try_new_with_consent(
            &principal()?,
            [actor()?],
            [
                GatewayOperationV1::CREATE_TIMELINE,
                GatewayOperationV1::READ_EVENTS,
                GatewayOperationV1::READ_SESSION,
                GatewayOperationV1::REVOKE_CONSENT,
            ],
            Some(consent_draft(
                vec![GatewayOperationV1::CREATE_TIMELINE],
                purposes,
            )?),
        )?)
    }

    /// A Local store at `path` provisioned with `provision` through the
    /// production host path, and the Gateway `serve` composes over it.
    fn consented_gateway(
        path: &str,
        provision: &LocalPrincipalProvisionV1,
    ) -> TestResult<(Gateway, Router)> {
        let mode = crate::mode_profile::test_binding(
            crate::mode_profile::GatewayModeProfileIdV1::Local,
            [],
        );
        provision_on_host(&mut sqlite_host(path)?, provision)?;
        let gateway = local_gateway(
            crate::mode_profile::test_attach_host(sqlite_host(path)?, &mode),
            None,
            &mode,
        )?;
        Ok((gateway.clone(), app_of(gateway)))
    }

    async fn revoke_with(
        app: &Router,
        consent_ref: &Value,
        key: &str,
    ) -> TestResult<(StatusCode, Value)> {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/me/consent-revocations")
            .header("idempotency-key", key)
            .header(ACTOR_ENTITY_HEADER, actor()?.to_string())
            .header("content-type", "application/json")
            .body(Body::from(json!({"consent_ref": consent_ref}).to_string()))?;
        let response = app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    async fn session(app: &Router) -> TestResult<Value> {
        let (status, body) = send(app, "GET", "/v1/session", Some(actor()?), None).await?;
        assert_eq!(status, StatusCode::OK);
        Ok(body)
    }

    /// Owner decisions 1(a) and 2(b) on #309, end to end through the
    /// production provisioning and serve composition: a provisioned consent
    /// is disclosed and governs Timeline creation only; its revocation is
    /// recorded once, answered with its original afterwards, takes effect
    /// before the next decision and survives a restart; reads, the Session
    /// and revocation itself stay available.
    #[tokio::test]
    async fn a_revoked_consent_stops_only_the_operations_it_governs() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        bind_local(&path)?;
        let provision = consented_provision(&["decision preview", "export to the subject"])?;
        let (gateway, app) = consented_gateway(&path, &provision)?;

        let granted = session(&app).await?;
        assert_eq!(granted["generation"], 4);
        assert_eq!(
            granted["grants"],
            json!([
                "consent.revoke",
                "session.read",
                "timeline.create",
                "timeline.events.read"
            ])
        );
        assert_eq!(granted["consents"][0]["state"], "granted");
        assert_eq!(granted["consents"][0]["export_permitted"], false);
        assert_eq!(granted["consents"][1]["export_permitted"], true);
        let first = granted["consents"][0]["consent_ref"].clone();
        let second = granted["consents"][1]["consent_ref"].clone();
        let (created, timeline) = create(&app, Some(actor()?)).await?;
        assert_eq!(created, StatusCode::CREATED);

        let (recorded, revocation) = revoke_with(&app, &first, "revoke-first").await?;
        assert_eq!(recorded, StatusCode::CREATED);
        assert_eq!(revocation["consent_ref"], first);
        assert_eq!(revocation["state"], "revoked");
        assert_eq!(revocation["future_protected_work"], "denied");
        assert_eq!(revocation["generation"], 5);
        assert_eq!(revocation["mode_profile"]["binding_epoch"], 1);
        assert_ne!(revocation["id"], first);
        // An exact retry, and a revocation of the revoked consent under a
        // fresh key, return the original revocation.
        assert_eq!(
            revoke_with(&app, &first, "revoke-first").await?,
            (StatusCode::OK, revocation.clone())
        );
        assert_eq!(
            revoke_with(&app, &first, "revoke-again").await?,
            (StatusCode::OK, revocation.clone())
        );
        // A key names the consent it first revoked.
        let (conflict, problem) = revoke_with(&app, &second, "revoke-first").await?;
        assert_eq!(conflict, StatusCode::CONFLICT);
        assert_eq!(problem["code"], "idempotency-conflict");
        // A consent the Principal does not hold is not found.
        let (missing, problem) =
            revoke_with(&app, &json!(Ulid::new().to_string()), "missing").await?;
        assert_eq!(missing, StatusCode::NOT_FOUND);
        assert_eq!(problem["code"], "not-found-or-unavailable");

        // The governed operation is revoked; the others stay available.
        let (denied, problem) = create(&app, Some(actor()?)).await?;
        assert_eq!(denied, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], "revoked");
        let events = format!(
            "/v1/timelines/{}/events",
            timeline["id"].as_str().unwrap_or_default()
        );
        assert_eq!(
            send(&app, "GET", &events, Some(actor()?), None).await?.0,
            StatusCode::OK
        );
        let revoked = session(&app).await?;
        assert_eq!(revoked["generation"], 5);
        assert_eq!(revoked["consents"][0]["state"], "revoked");
        assert_eq!(revoked["consents"][1]["state"], "granted");
        assert_eq!(
            revoked["grants"],
            json!(["consent.revoke", "session.read", "timeline.events.read"])
        );
        gateway.shutdown().await?;
        drop(gateway);
        drop(app);

        // A restarted host recomposes the revocation from the consent
        // Timeline, and an exact provisioning retry records nothing.
        let (gateway, app) = consented_gateway(&path, &provision)?;
        assert_eq!(session(&app).await?["consents"], revoked["consents"]);
        assert_eq!(create(&app, Some(actor()?)).await?.0, StatusCode::FORBIDDEN);
        let (second_recorded, second_revocation) =
            revoke_with(&app, &second, "revoke-second").await?;
        assert_eq!(second_recorded, StatusCode::CREATED);
        assert_eq!(second_revocation["generation"], 6);
        gateway.shutdown().await?;
        drop(gateway);
        Ok(())
    }

    /// A consent the acting entity neither gave nor holds is not found, and
    /// a host without an authorizer has no consent to revoke.
    #[tokio::test]
    async fn only_the_subject_or_grantee_revokes_and_an_open_host_revokes_nothing() -> TestResult {
        let other = EntityId::new();
        let provision = LocalPrincipalProvisionV1::try_new_with_consent(
            &principal()?,
            [actor()?, other],
            [
                GatewayOperationV1::CREATE_TIMELINE,
                GatewayOperationV1::REVOKE_CONSENT,
                GatewayOperationV1::READ_SESSION,
            ],
            Some(consent_draft(
                vec![GatewayOperationV1::CREATE_TIMELINE],
                &["one"],
            )?),
        )?;
        let directory = tempfile::tempdir()?;
        let path = sqlite_path(&directory)?;
        bind_local(&path)?;
        let (gateway, app) = consented_gateway(&path, &provision)?;
        let consent = session(&app).await?["consents"][0]["consent_ref"].clone();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/me/consent-revocations")
            .header("idempotency-key", "other")
            .header(ACTOR_ENTITY_HEADER, other.to_string())
            .header("content-type", "application/json")
            .body(Body::from(json!({"consent_ref": consent}).to_string()))?;
        assert_eq!(
            app.clone().oneshot(request).await?.status(),
            StatusCode::NOT_FOUND
        );
        // The other actor is no grantee: consent-governed creation is refused
        // as consent-invalid, never answered as revoked.
        let (refused, problem) = create(&app, Some(other)).await?;
        assert_eq!(refused, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], "consent-invalid");
        gateway.shutdown().await?;
        drop(gateway);

        let open = Gateway::unprotected_for_harness(memory_host()?)?;
        let (status, problem) = revoke_with(&app_of(open.clone()), &consent, "open").await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(problem["code"], "unauthenticated");
        open.shutdown().await?;
        drop(open);
        Ok(())
    }

    #[test]
    fn a_consent_document_is_validated_before_anything_is_recorded() -> TestResult {
        let operations = [
            GatewayOperationV1::CREATE_TIMELINE,
            GatewayOperationV1::READ_SESSION,
            GatewayOperationV1::REVOKE_CONSENT,
        ];
        let create = vec![GatewayOperationV1::CREATE_TIMELINE];
        let refused = |granted: &[GatewayOperationV1], consent| -> TestResult<bool> {
            Ok(LocalPrincipalProvisionV1::try_new_with_consent(
                &principal()?,
                [actor()?],
                granted.iter().copied(),
                Some(consent),
            ) == Err(LocalPrincipalErrorV1::Invalid))
        };
        assert!(!refused(
            &operations,
            consent_draft(create.clone(), &["one"])?
        )?);
        let too_many = vec!["many"; MAX_CAPABILITY_CONSENT_REFERENCES + 1];
        let long = "p".repeat(129);
        for (label, granted, consent) in [
            (
                "no grant",
                &operations[..],
                consent_draft(create.clone(), &[])?,
            ),
            (
                "too many grants",
                &operations[..],
                consent_draft(create.clone(), &too_many)?,
            ),
            (
                "long purpose",
                &operations[..],
                consent_draft(create.clone(), &[long.as_str()])?,
            ),
            (
                "no operation",
                &operations[..],
                consent_draft(Vec::new(), &["one"])?,
            ),
            (
                "an ungranted operation",
                &operations[..],
                consent_draft(vec![GatewayOperationV1::READ_EVENTS], &["one"])?,
            ),
            (
                "an exempt operation",
                &operations[..],
                consent_draft(vec![GatewayOperationV1::READ_SESSION], &["one"])?,
            ),
            (
                "no unconsented operation",
                &operations[..1],
                consent_draft(create.clone(), &["one"])?,
            ),
            (
                "a subject who does not act",
                &operations[..],
                LocalConsentDraftV1 {
                    subject: EntityId::new(),
                    ..consent_draft(create.clone(), &["one"])?
                },
            ),
            (
                "a grantee who does not act",
                &operations[..],
                LocalConsentDraftV1 {
                    grantee: EntityId::new(),
                    ..consent_draft(create.clone(), &["one"])?
                },
            ),
        ] {
            assert!(refused(granted, consent)?, "{label}");
        }
        assert!(GatewayOperationV1::REVOKE_CONSENT.consent_exempt());
        assert!(!GatewayOperationV1::CREATE_TIMELINE.consent_exempt());
        Ok(())
    }

    #[test]
    fn a_consent_table_is_parsed_from_the_document() -> TestResult {
        let base = document(
            &format!("\"{ACTOR}\""),
            "\"consent.revoke\", \"session.read\", \"timeline.create\"",
        );
        let table = format!(
            "{base}[consent]\nsubject_entity_id = \"{ACTOR}\"\ngrantee_entity_id = \"{ACTOR}\"\n\
             operations = [\"timeline.create\"]\n\n[[consent.grants]]\n\
             purpose = \"decision preview\"\nexport_permitted = true\n"
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
            Some(LocalConsentDraftV1 {
                subject: actor()?,
                grantee: actor()?,
                operations: vec![GatewayOperationV1::CREATE_TIMELINE],
                grants: vec![LocalConsentGrantDraftV1 {
                    purpose: "decision preview".to_owned(),
                    export_permitted: true,
                }],
            }),
        )?;
        assert_eq!(parsed, built);
        assert_ne!(parsed, LocalPrincipalProvisionV1::from_toml(&base)?);
        for broken in [
            table.replace("subject_entity_id = \"", "subject_entity_id = \"x"),
            table.replace("grantee_entity_id = \"", "grantee_entity_id = \"x"),
            table.replace(
                "operations = [\"timeline.create\"]",
                "operations = [\"timeline.delete\"]",
            ),
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

    /// A store's consent Timeline holds one provisioning's consents: a
    /// document with other consents conflicts, and a provisioning without
    /// consents records none.
    #[test]
    fn a_consent_timeline_holds_one_provisioning() -> TestResult {
        let mut host = memory_host()?;
        provision_local_consents(&mut host, &served_provision()?)?;
        provision_local_consents(&mut host, &consented_provision(&["one"])?)?;
        provision_local_consents(&mut host, &consented_provision(&["one"])?)?;
        assert_eq!(
            provision_local_consents(&mut host, &consented_provision(&["two"])?),
            Err(LocalPrincipalErrorV1::Conflict)
        );
        Ok(())
    }

    /// The recorded consents of `provision`'s consent-bound grant, as Events
    /// of the consent Timeline at sequences 1, 2, ...
    fn consent_events(
        provision: &LocalPrincipalProvisionV1,
    ) -> TestResult<(CapabilityGrantV1, Vec<Event>)> {
        let (grant, records) = provision
            .consent
            .clone()
            .ok_or("the provision binds consents")?;
        let events = records
            .iter()
            .map(|record| -> TestResult<Event> {
                Ok(consent_event(
                    record.subject_id,
                    EVENT_TYPE_CONSENT_GRANTED_V1,
                    record.encode()?,
                    record.grant_seq,
                ))
            })
            .collect::<TestResult<Vec<_>>>()?;
        Ok((grant, events))
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

    /// A consent Timeline this host cannot reproduce exactly is refused.
    #[test]
    fn a_consent_timeline_out_of_contract_is_refused() -> TestResult {
        let provision = consented_provision(&["one", "two"])?;
        let (grant, events) = consent_events(&provision)?;
        let consents = local_consents(&grant, &events).ok_or("the recorded consents replay")?;
        assert_eq!(consents.disclosed().len(), 2);
        assert_eq!(consents.head(), Seq::from_u64(2));
        let revocation = |grant_seq: u64, seq: u64| -> TestResult<Event> {
            Ok(consent_event(
                actor()?,
                EVENT_TYPE_CONSENT_REVOKED_V1,
                ConsentRevokedV1 {
                    subject_id: actor()?,
                    grantee_id: actor()?,
                    grant_seq,
                    fence_seq: 3,
                }
                .encode()?,
                seq,
            ))
        };
        let revoked = [events.clone(), vec![revocation(1, 3)?]].concat();
        let replayed = local_consents(&grant, &revoked).ok_or("a revocation replays")?;
        assert!(replayed.disclosed()[0].revocation().is_some());
        assert!(replayed.disclosed()[1].revocation().is_none());
        let mut foreign = events.clone();
        foreign[0].entity = EntityId::new();
        let mut shifted = events.clone();
        shifted[1].seq = Seq::from_u64(3);
        let mut unknown = events.clone();
        unknown[0].event_type = Kind::new("consent.renewed.v1");
        let mut garbled = events.clone();
        garbled[1].payload = CanonicalBytes::from_static(b"garbled");
        let mut foreign_revocation = revocation(1, 3)?;
        foreign_revocation.entity = EntityId::new();
        let no_subject = local_grant_without_subject(&grant)?;
        for (label, grant, events) in [
            ("a foreign entity", &grant, foreign),
            ("a grant at another sequence", &grant, shifted),
            ("an unknown event type", &grant, unknown),
            ("a garbled payload", &grant, garbled),
            ("a missing grant", &grant, events[..1].to_vec()),
            (
                "a revocation of no grant",
                &grant,
                [events.clone(), vec![revocation(7, 3)?]].concat(),
            ),
            (
                "a revocation at another sequence",
                &grant,
                [events.clone(), vec![revocation(1, 4)?]].concat(),
            ),
            (
                "a revocation by a foreign entity",
                &grant,
                [events.clone(), vec![foreign_revocation]].concat(),
            ),
            ("a grant without a subject", &no_subject, events.clone()),
        ] {
            assert!(local_consents(grant, &events).is_none(), "{label}");
        }
        Ok(())
    }

    /// `grant` with no subject in its scope.
    fn local_grant_without_subject(grant: &CapabilityGrantV1) -> TestResult<CapabilityGrantV1> {
        Ok(root_grant(
            grant.grantor(),
            LocalGrantKindV1::Consented,
            (
                grant.scope().actor_entity_ids(),
                [GatewayOperationV1::CREATE_TIMELINE].as_slice(),
            ),
            None,
            grant.authority_registry_digest(),
        )?)
    }
}
