//! The Local owner host commands of the single-host erasure executor
//! (ADR-136 §4a and §5; owner decisions of 2026-11-17 on #1412, ticket
//! #1430).
//!
//! `LocalErasureExecutorV1` runs every owner effect through these host
//! commands. Each command first proves that it serves a coordinator-dispatched
//! command: the command's obligation and command identity must be a pair of
//! the request's committed active attempt, the command must name that
//! attempt, and its category, target and owner must re-derive the obligation
//! address. Its acknowledgement class is the one whose
//! `CA("ELOWN1", [store_identity, category, ack_class])` names the command's
//! owner. Every owner outcome is then an ELO1 owner result, positive or
//! negative, that [`pos_core::PreparedLocalOwnerEffectV1::new`] assembles
//! with its `effect_digest` derived from the effect it binds, committed
//! with that effect through
//! [`pos_core::ErasureInventoryPersistencePortV1::commit_local_owner_effect`].
//!
//! Only a genuine owner outcome becomes an ELO1. A store that cannot be read
//! or written is a host error: nothing is committed, the host is not
//! poisoned, and the driver runs the command again.
//!
//! | ack class | effect |
//! |---|---|
//! | `key-registry` | the two key-destruction phases, the tombstone bound to ELO1 |
//! | `artifact-store`, `managed-report` | ELAD1 when the ARD1 row depends on keys and every one is tombstoned (Q7), else ELNEG1 `ArtifactDeletionFailed` |
//! | `client-cache-signal` | ELCG1 at the attempt's admitted position (Q8) |
//! | `export-recipient`, `timeline-payload` | ELNEG1 `ArtifactDeletionFailed` |
//! | `local-backup-inventory` | ELNEG1 `BackupInventoryIncomplete` |
//! | `local-replica` | once every other owner has an ELO1, the F1 purge outside every fence, then ELRP1 or ELNEG1 (Q3) |
//!
//! The only transient code is the purge's `ReplicaTimeout`; the Local
//! executor never emits `KeyRegistryUnavailable` (Q19).

use pos_core::{
    deletion_receipt, local_erasure_key_digest_v1, local_erasure_owner_ref_v1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureHostErrorV1, ErasureInventoryCategoryV1,
    ErasureObligationInputV1, ErasureObligationV1, ErasureOwnerCommandV1, ErasureOwnerResultV1,
    ErasurePersistencePortV1, ErasureProtectedOperationV1, ErasureRecordedAttemptReadV1,
    ErasureRecordedProgressV1, ErasureRecordedScopeReadV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequiredTargetV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentV1, ErasureScopeExtensionV1, EventStore, Hash, KeyDestructionRequestV1,
    KeyIdentityV1, KeyRegistryStateV1, LocalErasureArtifactDispositionV1,
    LocalErasureCacheGenerationV1, LocalErasureNegativeResultV1, LocalErasureOwnerResultV1,
    LocalErasureRedactionV1, LocalErasureReplicaPurgeV1, LocalOwnerEffectV1,
    LocalOwnerResultBindingV1, PreparedLocalOwnerEffectV1,
};

use super::{map_erasure_error, ErasureCommandSenderV1, ErasureHostStore};
use crate::erasure_authority_view::VIEW_LIST_MAX;

use ErasureInventoryCategoryV1::{Artifact, Backup, Key, Replica};

/// The owner work of one acknowledgement class.
#[derive(Clone, Copy, Eq, PartialEq)]
enum OwnerWorkV1 {
    /// ARD1 redaction (Q7).
    Disposition,
    /// The client-cache redaction generation (Q8).
    CacheGeneration,
    /// A class with no destruction primitive: always this permanent code.
    Refused(ErasureErrorV1),
    /// The two-phase key destruction.
    KeyDestruction,
    /// The F1 local-replica purge.
    ReplicaPurge,
}

/// Every acknowledgement class of the compiled ELP1 with its category and
/// owner work (ADR-136 §5, *Acknowledgement classes*).
const LOCAL_OWNER_WORK: [(ErasureInventoryCategoryV1, &str, OwnerWorkV1); 8] = [
    (Artifact, "artifact-store", OwnerWorkV1::Disposition),
    (
        Artifact,
        "client-cache-signal",
        OwnerWorkV1::CacheGeneration,
    ),
    (
        Artifact,
        "export-recipient",
        OwnerWorkV1::Refused(ErasureErrorV1::ArtifactDeletionFailed),
    ),
    (Artifact, "managed-report", OwnerWorkV1::Disposition),
    (
        Artifact,
        "timeline-payload",
        OwnerWorkV1::Refused(ErasureErrorV1::ArtifactDeletionFailed),
    ),
    (Key, "key-registry", OwnerWorkV1::KeyDestruction),
    (Replica, "local-replica", OwnerWorkV1::ReplicaPurge),
    (
        Backup,
        "local-backup-inventory",
        OwnerWorkV1::Refused(ErasureErrorV1::BackupInventoryIncomplete),
    ),
];

/// Every negative code the Local executor commits.
const NEGATIVE_CODES: [ErasureErrorV1; 5] = [
    ErasureErrorV1::ArtifactDeletionFailed,
    ErasureErrorV1::BackupInventoryIncomplete,
    ErasureErrorV1::KeyDestructionFailed,
    ErasureErrorV1::ReplicaTimeout,
    ErasureErrorV1::ReplicaNegativeAcknowledgement,
];

/// A request's committed ERSC1 and its ERSE1 chain.
type RecordedScopeV1 = (ErasureScopeCommitmentV1, Vec<ErasureScopeExtensionV1>);

/// One acknowledgement class of the store: its category, owner reference
/// and work.
type StoreOwnerV1 = (ErasureInventoryCategoryV1, ErasureReferenceV1, OwnerWorkV1);

/// One effect the Local executor can commit for a command, with its
/// outcome.
type CandidateEffectV1 = (
    Option<ErasureErrorV1>,
    Result<LocalOwnerEffectV1, ErasureErrorV1>,
);

/// The order owners of one attempt run in: keys first, so an artifact
/// whose keys the attempt destroys is then redacted (Q7); the single local
/// replica last, after every other owner of the request (F1).
const fn execution_rank(category: ErasureInventoryCategoryV1) -> u8 {
    match category {
        Key => 0,
        Artifact => 1,
        Backup => 2,
        Replica => 3,
    }
}

impl ErasureCommandSenderV1<'_> {
    /// The dispatch outbox of `request`: one [`ErasureOwnerCommandV1`] for
    /// each obligation of its committed active attempt that has no
    /// acknowledgement in that attempt yet, keys first and the local
    /// replica last, otherwise in the attempt's obligation order.
    ///
    /// The coordinator commits the attempt and its outbox intents before it
    /// dispatches them (ADR-136 §6), so after a crash this read is what the
    /// executor replays. It is the complete core recovery of the request
    /// (`recorded_progress`) under the host's own verifiers; nothing is
    /// written. A request without a manifest or without an active attempt
    /// has an empty outbox.
    ///
    /// # Errors
    /// Returns a payload-free stale-generation, recovery or authorization
    /// error; a host without an authority composition is
    /// [`ErasureHostErrorV1::AuthorizationDenied`].
    pub fn dispatched_owner_commands(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureOwnerCommandV1>, ErasureHostErrorV1> {
        self.recorded_local_progress(request).map(|progress| {
            let mut commands =
                progress.map_or_else(Vec::new, |progress| outbox(request, &progress));
            commands.sort_by_key(|command| execution_rank(command.destruction.category));
            commands
        })
    }

    /// Destroy the key of one `key-registry` command (ADR-136 §4a).
    ///
    /// The command runs under the protected-append fence of the store's
    /// Erasure Host Timeline, `ELHT1` of its erasure store identity, which
    /// the host derives itself (owner decision of 2026-11-18 on #1431: no
    /// caller supplies the Timeline). Every bundle lists it as a host
    /// Timeline, so no erasure ever freezes it. Inside that one fence it
    /// commits two transactions: the pending destruction of `identity`, then
    /// its tombstone together with the positive ELO1 through
    /// `commit_local_owner_effect`. The destruction request's
    /// `authorization_digest` is the command identity `CA(request, target)`,
    /// and the tombstone's deletion receipt is the key registry's
    /// request-bound `deletion_receipt`, which the ELO1 binds as its effect
    /// (owner decision Q5).
    ///
    /// A crash between the transactions leaves the pending destruction; the
    /// next run of the same command finds it and completes it. A key the
    /// registry already tombstoned, under any authorization, yields a
    /// positive ELO1 bound to that tombstone's existing receipt, committed
    /// only while the registry still holds it, so a repeat is idempotent. A
    /// key without registered private material, or one whose pending phase
    /// the registry refuses (another authorization is pending), is the
    /// permanent negative `KeyDestructionFailed`.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::Conflict`] unless `command` is a dispatched
    /// `key-registry` command of the request's active attempt whose target
    /// is `identity`'s key; the payload-free error of a store identity that
    /// cannot be read, or the fence error when the Erasure Host Timeline is
    /// unavailable; [`ErasureHostErrorV1::AdapterFailure`]
    /// or another payload-free error when the registry cannot be read or
    /// written, which commits no owner result.
    pub fn destroy_key_for_erasure(
        &mut self,
        command: &ErasureOwnerCommandV1,
        identity: KeyIdentityV1,
    ) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
        self.local_erasure_host_timeline()
            .and_then(|host_timeline| {
                self.host.with_store_fence(
                    self.generation,
                    host_timeline,
                    ErasureProtectedOperationV1::Append,
                    |store| Ok(destroyed_key(store, command, identity)),
                )
            })
            .and_then(std::convert::identity)
    }

    /// Run the owner work of one dispatched command and return its owner
    /// result; `LocalErasureExecutorV1` is the only caller.
    ///
    /// A `key-registry` command whose target names no registered key is the
    /// permanent negative `KeyDestructionFailed`; every other key command
    /// runs [`Self::destroy_key_for_erasure`]. A
    /// `local-replica` command runs only once every other obligation of the
    /// attempt has a retained ELO1 (F1).
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::Conflict`] for a command that is not
    /// dispatched in the request's active attempt, or a `local-replica`
    /// command that comes before another owner of the attempt; otherwise a
    /// payload-free host error when no owner result could be made durable.
    pub(crate) fn execute_local_owner(
        &mut self,
        command: &ErasureOwnerCommandV1,
    ) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
        self.host
            .ensure_generation(self.generation)
            .and_then(|()| owner_work(self.host.store.host_store(), command))
            .and_then(|(work, active)| match work {
                OwnerWorkV1::KeyDestruction => self.registered_key_destruction(command),
                OwnerWorkV1::ReplicaPurge => {
                    let store = self.host.store.host_store();
                    others_executed(store, command, &active)
                        .and_then(|()| purged_replica(store, command))
                }
                OwnerWorkV1::Disposition => disposition(self.host.store.host_store(), command),
                OwnerWorkV1::CacheGeneration => {
                    let store = self.host.store.host_store();
                    cache_effect(store, command, &active)
                        .and_then(|effect| committed(store, command, None, effect))
                }
                OwnerWorkV1::Refused(error) => {
                    negative(self.host.store.host_store(), command, error)
                }
            })
    }

    /// Re-derive the owner result `owner_result` names before the Local
    /// signer signs it (ADR-136 §5 purpose 1; owner decision of 2026-11-18
    /// on #1431).
    ///
    /// The retained ELO1 must answer a command the request's active attempt
    /// dispatches, rebuilt from its retained obligation, and must be exactly
    /// the ELO1 one of the Local executor's outcomes for that command
    /// assembles: its `effect_digest` is `CA(effect)` of that effect by the
    /// `PreparedLocalOwnerEffectV1` rule, the deletion receipt of the key's
    /// tombstone or the address of its ELAD1, ELCG1, ELNEG1 or ELRP1. The
    /// effect must be committed: the registry holds that tombstone, or the
    /// store holds that exact record.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::AuthorizationDenied`] for an ELO1 or obligation
    /// that cannot be read, an ELO1 whose effect digest no committed effect
    /// of its command yields; [`ErasureHostErrorV1::Conflict`] for a command
    /// the active attempt does not dispatch; otherwise the payload-free read
    /// error.
    pub(crate) fn verified_owner_result(
        &mut self,
        owner_result: ErasureReferenceV1,
    ) -> Result<(), ErasureHostErrorV1> {
        self.host
            .ensure_generation(self.generation)
            .and_then(|()| bound_command(self.host.store.host_store(), owner_result))
            .and_then(|command| {
                committed_owner_result(self.host.store.host_store(), &command, owner_result)
            })
    }

    /// Destroy the registered key a `key-registry` command targets; a target
    /// that names no registered key is the permanent negative
    /// `KeyDestructionFailed`.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::AdapterFailure`] when the registry cannot be
    /// read; otherwise as [`Self::destroy_key_for_erasure`].
    fn registered_key_destruction(
        &mut self,
        command: &ErasureOwnerCommandV1,
    ) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
        let key_digest = command.destruction.target.key_digest;
        loaded_registry(self.host.store.host_store())
            .map(|registry| key_identity(registry.as_ref(), key_digest))
            .and_then(|identity| {
                let Some(identity) = identity else {
                    return negative(
                        self.host.store.host_store(),
                        command,
                        ErasureErrorV1::KeyDestructionFailed,
                    );
                };
                self.destroy_key_for_erasure(command, identity)
            })
    }
}

/// The commands of the active attempt in `progress` that have no
/// acknowledgement in that attempt.
fn outbox(
    request: ErasureReferenceV1,
    progress: &ErasureRecordedProgressV1,
) -> Vec<ErasureOwnerCommandV1> {
    progress.active.as_ref().map_or_else(Vec::new, |active| {
        let attempt = active.reference();
        active
            .unresolved_obligations()
            .iter()
            .filter(|obligation| {
                !progress.effective.iter().any(|acknowledgement| {
                    acknowledgement.attempt() == attempt
                        && acknowledgement.obligation() == **obligation
                })
            })
            .filter_map(|reference| {
                progress
                    .obligations
                    .iter()
                    .find(|obligation| obligation.reference() == *reference)
            })
            .map(|obligation| ErasureOwnerCommandV1 {
                request,
                destruction: ErasureDestructionCommandV1::from_obligation(obligation, attempt),
            })
            .collect()
    })
}

/// The key registry, `None` when the store has none.
///
/// # Errors
/// [`ErasureHostErrorV1::AdapterFailure`] when it cannot be read.
fn loaded_registry(
    store: &dyn ErasureHostStore,
) -> Result<Option<KeyRegistryStateV1>, ErasureHostErrorV1> {
    store
        .load_key_registry()
        .ok()
        .ok_or(ErasureHostErrorV1::AdapterFailure)
}

/// The request's committed ERSC1 and ERSE1 chain.
///
/// # Errors
/// [`ErasureHostErrorV1::RecoveryUnavailable`] when it cannot be read or,
/// which a dispatched request never is, is not committed.
fn committed_scope(
    store: &dyn ErasureHostStore,
    request: ErasureReferenceV1,
) -> Result<RecordedScopeV1, ErasureHostErrorV1> {
    store
        .recorded_scope(request)
        .map_err(map_erasure_error)
        .and_then(|scope| scope.ok_or(ErasureHostErrorV1::RecoveryUnavailable))
}

/// Whether `active` dispatches `command`: it is the request's attempt the
/// command names, and it pairs the command's obligation, whose address
/// `obligation` re-derives, with the command identity.
fn dispatches(
    active: &ErasureRetryAdmissionV1,
    command: &ErasureOwnerCommandV1,
    obligation: ErasureReferenceV1,
) -> bool {
    let destruction = command.destruction;
    active.request() == command.request
        && active.reference() == destruction.provenance
        && obligation == destruction.obligation
        && destruction.command
            == pos_core::destruction_command_reference(command.request, destruction.target)
        && active
            .unresolved_obligations()
            .iter()
            .zip(active.command_identities())
            .any(|pair| pair == (&destruction.obligation, &destruction.command))
}

/// The committed active attempt `command` was dispatched in.
///
/// # Errors
/// [`ErasureHostErrorV1::Conflict`] unless the request has an active
/// attempt that dispatches `command`; otherwise the payload-free read error.
fn dispatched_admission(
    store: &dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
) -> Result<ErasureRetryAdmissionV1, ErasureHostErrorV1> {
    let destruction = command.destruction;
    // A command whose fields do not even form an obligation is not
    // dispatched.
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: destruction.category,
        target: destruction.target,
        owner: destruction.owner,
        command_identity: destruction.command,
    })
    .map(|obligation| obligation.reference())
    .ok();
    store
        .recorded_active_attempt(command.request)
        .map_err(map_erasure_error)
        .and_then(|active| {
            active
                .zip(obligation)
                .filter(|(active, obligation)| dispatches(active, command, *obligation))
                .map(|(active, _)| active)
                .ok_or(ErasureHostErrorV1::Conflict)
        })
}

/// The owner reference and work of every acknowledgement class of the
/// store, derived once per command.
fn store_owners(store: &mut dyn ErasureHostStore) -> Result<Vec<StoreOwnerV1>, ErasureHostErrorV1> {
    store
        .erasure_store_identity()
        .and_then(|identity| identity.ok_or(ErasureErrorV1::PolicyConflict))
        .and_then(|identity| {
            let store_identity = ErasureReferenceV1::from_digest(*identity.as_bytes());
            LOCAL_OWNER_WORK
                .iter()
                .map(|(category, ack_class, work)| {
                    local_erasure_owner_ref_v1(store_identity, u64::from(*category), ack_class)
                        .map(|owner| (*category, owner, *work))
                })
                .collect()
        })
        .map_err(map_erasure_error)
}

/// The owner work of a dispatched `command` and its active attempt.
///
/// The store identity always exists on a composed Local host, whose bundle
/// composition requires it; a store without one owns no class here.
///
/// # Errors
/// [`ErasureHostErrorV1::Conflict`] for a command that is not dispatched or
/// whose owner is no acknowledgement class of this store; otherwise the
/// payload-free read error.
fn owner_work(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
) -> Result<(OwnerWorkV1, ErasureRetryAdmissionV1), ErasureHostErrorV1> {
    let destruction = command.destruction;
    dispatched_admission(store, command).and_then(|active| {
        store_owners(store).and_then(|owners| {
            owners
                .into_iter()
                .find(|(category, owner, _)| {
                    *category == destruction.category && *owner == destruction.owner
                })
                .map(|(_, _, work)| (work, active))
                .ok_or(ErasureHostErrorV1::Conflict)
        })
    })
}

/// The ELO1 binding of `command` with outcome `error`; its effect digest
/// is derived from the effect it is committed with.
const fn owner_binding(
    command: &ErasureOwnerCommandV1,
    error: Option<ErasureErrorV1>,
) -> LocalOwnerResultBindingV1 {
    LocalOwnerResultBindingV1 {
        request: command.request,
        attempt: command.destruction.provenance,
        obligation: command.destruction.obligation,
        command: command.destruction.command,
        owner_ref: command.destruction.owner,
        error,
    }
}

/// Commit `effect` with the ELO1 of `command` and outcome `error` that
/// binds it, in one adapter transaction, and bind that ELO1 to `command`.
fn committed(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    error: Option<ErasureErrorV1>,
    effect: LocalOwnerEffectV1,
) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
    PreparedLocalOwnerEffectV1::new(effect, owner_binding(command, error))
        .and_then(|prepared| {
            ErasureOwnerResultV1::bind(command, prepared.owner_result().canonical_cbor())
                .map(|result| (prepared, result))
        })
        .and_then(|(prepared, result)| store.commit_local_owner_effect(prepared).map(|_| result))
        .map_err(map_erasure_error)
}

/// The ELNEG1 effect of the negative owner result `error` of `command`.
fn negative_effect(
    command: &ErasureOwnerCommandV1,
    error: ErasureErrorV1,
) -> Result<LocalOwnerEffectV1, ErasureErrorV1> {
    LocalErasureNegativeResultV1 {
        command: command.destruction.command,
        owner_ref: command.destruction.owner,
        error,
    }
    .to_canonical_cbor()
    .map(LocalOwnerEffectV1::Negative)
}

/// Commit the negative owner result `error` of `command`.
fn negative(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    error: ErasureErrorV1,
) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
    negative_effect(command, error)
        .map_err(map_erasure_error)
        .and_then(|effect| committed(store, command, Some(error), effect))
}

/// The ELCG1 effect of `command` over the committed ERSC1 `scope` at
/// `generation`.
fn cache_record(
    command: &ErasureOwnerCommandV1,
    scope: ErasureReferenceV1,
    generation: u64,
) -> Result<LocalOwnerEffectV1, ErasureErrorV1> {
    LocalErasureCacheGenerationV1 {
        request: command.request,
        scope_commitment: scope,
        generation,
    }
    .to_canonical_cbor()
    .map(LocalOwnerEffectV1::CacheGeneration)
}

/// The ELAD1 effect of `command`: its artifact redacted with its views.
fn disposition_record(
    command: &ErasureOwnerCommandV1,
) -> Result<LocalOwnerEffectV1, ErasureErrorV1> {
    let target = command.destruction.target;
    LocalErasureArtifactDispositionV1 {
        request: command.request,
        artifact_class: target.artifact_class,
        artifact_digest: target.artifact_digest,
        redaction: LocalErasureRedactionV1::Redacted,
        replay_claim_to: ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
    }
    .to_canonical_cbor()
    .map(LocalOwnerEffectV1::ArtifactDisposition)
}

/// The ELRP1 effect of `command`'s purged replica.
fn purge_record(command: &ErasureOwnerCommandV1) -> Result<LocalOwnerEffectV1, ErasureErrorV1> {
    LocalErasureReplicaPurgeV1 {
        request: command.request,
        command: command.destruction.command,
        replica_id: command.destruction.target.replica_id,
    }
    .to_canonical_cbor()
    .map(LocalOwnerEffectV1::ReplicaPurge)
}

/// The registered key whose ADR-136 key digest is `key_digest`, destroyed
/// or not.
fn key_identity(
    registry: Option<&KeyRegistryStateV1>,
    key_digest: ErasureReferenceV1,
) -> Option<KeyIdentityV1> {
    registry.and_then(|registry| {
        registry
            .key_records()
            .map(|record| record.identity)
            .find(|identity| local_erasure_key_digest_v1(identity) == Ok(key_digest))
    })
}

/// The key destruction of `command` inside the Erasure Host Timeline
/// fence.
///
/// # Errors
/// [`ErasureHostErrorV1::Conflict`] unless `command` is a dispatched
/// `key-registry` command whose target is `identity`'s key; otherwise the
/// payload-free error of a registry or commit that failed.
fn destroyed_key(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    identity: KeyIdentityV1,
) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
    owner_work(store, command)
        .and_then(|(work, _)| {
            (work == OwnerWorkV1::KeyDestruction
                && local_erasure_key_digest_v1(&identity)
                    == Ok(command.destruction.target.key_digest))
            .then_some(())
            .ok_or(ErasureHostErrorV1::Conflict)
        })
        .and_then(|()| loaded_registry(store))
        .and_then(|registry| {
            let Some(tombstone) = registry
                .as_ref()
                .and_then(|registry| registry.tombstone(identity))
            else {
                return key_phases(store, command, identity, registry);
            };
            committed(
                store,
                command,
                None,
                LocalOwnerEffectV1::ExistingTombstone(Box::new(tombstone)),
            )
        })
}

/// The two destruction transactions of a key the loaded `registry` has not
/// tombstoned: the pending phase, then the tombstone with its ELO1.
///
/// The registry's own rule, applied to the loaded state, decides the
/// outcome: a key without registered private material, or a pending phase
/// the registry refuses, is the permanent negative `KeyDestructionFailed`.
/// A store that then fails to persist an admitted pending phase is a host
/// error and commits no owner result.
fn key_phases(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    identity: KeyIdentityV1,
    registry: Option<KeyRegistryStateV1>,
) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
    registry
        .and_then(|mut registry| {
            registry
                .key_record(identity)
                .and_then(|record| record.private_material_digest)
                .map(|material| {
                    KeyDestructionRequestV1::new(
                        identity,
                        material,
                        Hash::from_bytes(command.destruction.command.digest()),
                    )
                })
                .filter(|request| registry.begin_key_destruction(*request).is_ok())
        })
        .map_or_else(
            || {
                negative_effect(command, ErasureErrorV1::KeyDestructionFailed)
                    .map(|effect| (Some(ErasureErrorV1::KeyDestructionFailed), effect, None))
            },
            |request| {
                Ok((
                    None,
                    LocalOwnerEffectV1::KeyTombstone {
                        request: Box::new(request),
                        deletion_receipt: deletion_receipt(&request),
                    },
                    Some(request),
                ))
            },
        )
        .map_err(map_erasure_error)
        .and_then(|(error, effect, pending)| {
            pending
                .map_or(Ok(()), |request| {
                    store
                        .begin_key_registry_destruction(request)
                        .map(drop)
                        .ok()
                        .ok_or(ErasureHostErrorV1::AdapterFailure)
                })
                .and_then(|()| committed(store, command, error, effect))
        })
}

/// The key identities the ARD1 row of `target` depends on, when a Timeline
/// of the request's committed scope registers that row.
///
/// A dispatched request's frozen closure already read every registration
/// list of its scope within the 4,096-row bound, so an over-bound or
/// unreadable list is a host error here, never an owner outcome.
fn registered_dependencies(
    store: &dyn ErasureHostStore,
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<Option<Vec<KeyIdentityV1>>, ErasureHostErrorV1> {
    committed_scope(store, request)
        .and_then(|(commitment, extensions)| {
            commitment
                .scope_timeline_ids()
                .iter()
                .copied()
                .chain(
                    extensions
                        .iter()
                        .map(ErasureScopeExtensionV1::child_timeline),
                )
                .map(|timeline| {
                    EventStore::artifact_registrations_for_timeline(store, timeline, VIEW_LIST_MAX)
                        .ok()
                        .ok_or(ErasureHostErrorV1::AdapterFailure)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .map(|rows| {
            rows.into_iter()
                .flatten()
                .find(|row| {
                    row.artifact_class() == target.artifact_class
                        && ErasureReferenceV1::from_digest(*row.artifact_digest().as_bytes())
                            == target.artifact_digest
                })
                .map(|row| {
                    row.registration()
                        .fields()
                        .key_dependencies
                        .iter()
                        .map(|dependency| dependency.identity)
                        .collect()
                })
        })
}

/// The `artifact-store` or `managed-report` owner result of `command` (Q7).
///
/// It is the positive ELAD1, redacted with its views, only when the ARD1
/// row of the target is registered in the request's committed scope,
/// depends on at least one key, and the key registry has tombstoned every
/// key it depends on: the artifact is then unreadable. A row without any
/// key dependency leaves no destruction evidence, so it is, like a row
/// whose keys survive, the permanent negative `ArtifactDeletionFailed`. An
/// unreadable scope, registration list or registry is a host error.
fn disposition(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
    registered_dependencies(store, command.request, command.destruction.target)
        .and_then(|dependencies| {
            loaded_registry(store).map(|registry| {
                dependencies
                    .zip(registry)
                    .is_some_and(|(dependencies, registry)| {
                        !dependencies.is_empty()
                            && dependencies
                                .iter()
                                .all(|identity| registry.tombstone(*identity).is_some())
                    })
            })
        })
        .and_then(|redacted| {
            if redacted {
                disposition_record(command)
                    .map_err(map_erasure_error)
                    .and_then(|effect| committed(store, command, None, effect))
            } else {
                negative(store, command, ErasureErrorV1::ArtifactDeletionFailed)
            }
        })
}

/// The `client-cache-signal` effect of `command`: the ELCG1 of the
/// request's committed ERSC1 at the attempt's admitted position (Q8).
fn cache_effect(
    store: &dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    active: &ErasureRetryAdmissionV1,
) -> Result<LocalOwnerEffectV1, ErasureHostErrorV1> {
    committed_scope(store, command.request).and_then(|(commitment, _)| {
        cache_record(command, commitment.reference(), active.admitted_position())
            .map_err(map_erasure_error)
    })
}

/// Every effect the Local executor can commit for `command`, with its
/// outcome: its class's positive record, an existing tombstone of its key,
/// and each negative code. A command of another class simply has no ELO1
/// over the other classes' candidates.
fn candidate_effects(
    command: &ErasureOwnerCommandV1,
    (scope, generation): (ErasureReferenceV1, u64),
    registry: Option<&KeyRegistryStateV1>,
) -> Vec<CandidateEffectV1> {
    let tombstone = key_identity(registry, command.destruction.target.key_digest)
        .and_then(|identity| registry.and_then(|registry| registry.tombstone(identity)));
    let mut candidates = vec![
        (None, cache_record(command, scope, generation)),
        (None, disposition_record(command)),
        (None, purge_record(command)),
    ];
    candidates.extend(
        NEGATIVE_CODES
            .iter()
            .map(|code| (Some(*code), negative_effect(command, *code))),
    );
    candidates.extend(tombstone.map(|tombstone| {
        (
            None,
            Ok(LocalOwnerEffectV1::ExistingTombstone(Box::new(tombstone))),
        )
    }));
    candidates
}

/// Whether the store retains an ELO1 of `command`: the owner result of any
/// outcome the Local executor can commit for it.
fn has_owner_result(
    store: &dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    scope: (ErasureReferenceV1, u64),
    registry: Option<&KeyRegistryStateV1>,
) -> Result<bool, ErasureHostErrorV1> {
    candidate_effects(command, scope, registry)
        .into_iter()
        .map(|(error, effect)| {
            effect
                .and_then(|effect| {
                    PreparedLocalOwnerEffectV1::new(effect, owner_binding(command, error))
                })
                .and_then(|prepared| retained(store, prepared.owner_result().reference()))
        })
        .find(|probe| *probe != Ok(false))
        .unwrap_or(Ok(false))
        .map_err(map_erasure_error)
}

/// Whether the store retains the object at `reference`.
///
/// # Errors
/// The store's read error, other than the absence of the object.
fn retained(
    store: &dyn ErasureHostStore,
    reference: ErasureReferenceV1,
) -> Result<bool, ErasureErrorV1> {
    match store.read_object(reference) {
        Ok(_) => Ok(true),
        Err(ErasureErrorV1::ProvenanceMissing) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Whether the obligation at `obligation` of `attempt` has a retained ELO1.
fn obligation_has_owner_result(
    store: &dyn ErasureHostStore,
    request: ErasureReferenceV1,
    (attempt, obligation): (ErasureReferenceV1, ErasureReferenceV1),
    scope: (ErasureReferenceV1, u64),
    registry: Option<&KeyRegistryStateV1>,
) -> Result<bool, ErasureHostErrorV1> {
    store
        .read_object(obligation)
        .and_then(|bytes| ErasureObligationV1::from_canonical_cbor(&bytes))
        .map_err(map_erasure_error)
        .and_then(|obligation| {
            has_owner_result(
                store,
                &ErasureOwnerCommandV1 {
                    request,
                    destruction: ErasureDestructionCommandV1::from_obligation(&obligation, attempt),
                },
                scope,
                registry,
            )
        })
}

/// Whether every obligation of `active` other than `command`'s has a
/// retained ELO1 of this attempt, so the local replica runs after every
/// other owner of the request (F1).
///
/// # Errors
/// [`ErasureHostErrorV1::Conflict`] while another owner has no owner
/// result; otherwise the payload-free read error.
fn others_executed(
    store: &dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    active: &ErasureRetryAdmissionV1,
) -> Result<(), ErasureHostErrorV1> {
    let attempt = active.reference();
    committed_scope(store, command.request)
        .and_then(|(commitment, _)| loaded_registry(store).map(|registry| (commitment, registry)))
        .and_then(|(commitment, registry)| {
            let scope = (commitment.reference(), active.admitted_position());
            active
                .unresolved_obligations()
                .iter()
                .filter(|obligation| **obligation != command.destruction.obligation)
                .map(|obligation| {
                    obligation_has_owner_result(
                        store,
                        command.request,
                        (attempt, *obligation),
                        scope,
                        registry.as_ref(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .and_then(|executed| {
            executed
                .into_iter()
                .all(std::convert::identity)
                .then_some(())
                .ok_or(ErasureHostErrorV1::Conflict)
        })
}

/// The `local-replica` owner result of `command` (ADR-136 F1; Q3).
///
/// The purge runs here, outside every store fence and transaction, because
/// `VACUUM` cannot run inside one. ELRP1 and its ELO1 commit straight after
/// a positive purge, so the purge and its record are not atomic: a crash
/// between them re-runs the idempotent purge. `ReplicaTimeout` is the one
/// transient negative; every other purge failure is the permanent
/// `ReplicaNegativeAcknowledgement`.
fn purged_replica(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
    match store.purge_local_replica_residue() {
        Ok(()) => purge_record(command)
            .map_err(map_erasure_error)
            .and_then(|effect| committed(store, command, None, effect)),
        Err(ErasureErrorV1::ReplicaTimeout) => {
            negative(store, command, ErasureErrorV1::ReplicaTimeout)
        }
        Err(_) => negative(
            store,
            command,
            ErasureErrorV1::ReplicaNegativeAcknowledgement,
        ),
    }
}

/// The command the retained ELO1 `owner_result` answers, rebuilt from its
/// retained obligation and the attempt the ELO1 names.
///
/// # Errors
/// [`ErasureHostErrorV1::AuthorizationDenied`] when the ELO1 or its
/// obligation cannot be read.
fn bound_command(
    store: &dyn ErasureHostStore,
    owner_result: ErasureReferenceV1,
) -> Result<ErasureOwnerCommandV1, ErasureHostErrorV1> {
    ErasurePersistencePortV1::read_object(store, owner_result)
        .and_then(|bytes| LocalErasureOwnerResultV1::from_canonical_cbor(&bytes))
        .and_then(|elo1| {
            store
                .read_object(elo1.obligation)
                .and_then(|bytes| ErasureObligationV1::from_canonical_cbor(&bytes))
                .map(|obligation| ErasureOwnerCommandV1 {
                    request: elo1.request,
                    destruction: ErasureDestructionCommandV1::from_obligation(
                        &obligation,
                        elo1.attempt,
                    ),
                })
        })
        .ok()
        .ok_or(ErasureHostErrorV1::AuthorizationDenied)
}

/// Whether the Local executor's path for `work` can commit `effect` with
/// outcome `error`: its class's own positive record, or one of the
/// negative codes that path emits (M1 of the #1431 review). A tombstone a
/// key destruction commits is matched as the tombstone the registry holds.
fn emits(work: OwnerWorkV1, error: Option<ErasureErrorV1>, effect: &LocalOwnerEffectV1) -> bool {
    matches!(
        (work, error, effect),
        (
            OwnerWorkV1::Disposition,
            None,
            LocalOwnerEffectV1::ArtifactDisposition(_)
        ) | (
            OwnerWorkV1::Disposition,
            Some(ErasureErrorV1::ArtifactDeletionFailed),
            LocalOwnerEffectV1::Negative(_)
        ) | (
            OwnerWorkV1::CacheGeneration,
            None,
            LocalOwnerEffectV1::CacheGeneration(_)
        ) | (
            OwnerWorkV1::KeyDestruction,
            None,
            LocalOwnerEffectV1::ExistingTombstone(_)
        ) | (
            OwnerWorkV1::KeyDestruction,
            Some(ErasureErrorV1::KeyDestructionFailed),
            LocalOwnerEffectV1::Negative(_)
        ) | (
            OwnerWorkV1::ReplicaPurge,
            None,
            LocalOwnerEffectV1::ReplicaPurge(_)
        ) | (
            OwnerWorkV1::ReplicaPurge,
            Some(ErasureErrorV1::ReplicaTimeout | ErasureErrorV1::ReplicaNegativeAcknowledgement),
            LocalOwnerEffectV1::Negative(_)
        )
    ) || matches!(
        (work, error, effect),
        (OwnerWorkV1::Refused(code), Some(emitted), LocalOwnerEffectV1::Negative(_))
            if code == emitted
    )
}

/// Whether `owner_result` is the ELO1 of a committed outcome the Local
/// executor's path for the dispatched `command`'s class can produce.
///
/// # Errors
/// [`ErasureHostErrorV1::Conflict`] unless the active attempt dispatches
/// `command`; [`ErasureHostErrorV1::AuthorizationDenied`] when no committed
/// effect of `command` yields `owner_result`; otherwise the payload-free
/// read error.
fn committed_owner_result(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    owner_result: ErasureReferenceV1,
) -> Result<(), ErasureHostErrorV1> {
    owner_work(store, command)
        .and_then(|(work, active)| {
            committed_scope(store, command.request).and_then(|(commitment, _)| {
                loaded_registry(store).map(|registry| {
                    (
                        work,
                        (commitment.reference(), active.admitted_position()),
                        registry,
                    )
                })
            })
        })
        .and_then(|(work, scope, registry)| {
            candidate_effects(command, scope, registry.as_ref())
                .into_iter()
                .filter(|(error, effect)| {
                    effect
                        .as_ref()
                        .is_ok_and(|effect| emits(work, *error, effect))
                })
                .filter_map(|(error, effect)| {
                    effect
                        .and_then(|effect| {
                            PreparedLocalOwnerEffectV1::new(effect, owner_binding(command, error))
                        })
                        .ok()
                })
                .find(|prepared| prepared.owner_result().reference() == owner_result)
                .filter(|prepared| {
                    prepared.effect_object().is_none_or(|effect| {
                        store
                            .read_object(effect.reference())
                            .is_ok_and(|bytes| bytes == effect.canonical_cbor())
                    })
                })
                .map(drop)
                .ok_or(ErasureHostErrorV1::AuthorizationDenied)
        })
}
