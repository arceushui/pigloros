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
//! A host error means that no owner result could be made durable; it never
//! poisons the host.
//!
//! | ack class | effect |
//! |---|---|
//! | `key-registry` | the two key-destruction phases, the tombstone bound to ELO1 |
//! | `artifact-store`, `managed-report` | ELAD1 when every key the ARD1 row depends on is tombstoned (Q7), else ELNEG1 `ArtifactDeletionFailed` |
//! | `client-cache-signal` | ELCG1 at the attempt's admitted position (Q8) |
//! | `export-recipient`, `timeline-payload` | ELNEG1 `ArtifactDeletionFailed` |
//! | `local-backup-inventory` | ELNEG1 `BackupInventoryIncomplete` |
//! | `local-replica` | the F1 purge outside every fence, then ELRP1 or ELNEG1 (Q3) |
//!
//! The only transient code is the purge's `ReplicaTimeout`; the Local
//! executor never emits `KeyRegistryUnavailable` (Q19).

use pos_core::{
    deletion_receipt, local_erasure_key_digest_v1, local_erasure_owner_ref_v1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureHostErrorV1, ErasureInventoryCategoryV1,
    ErasureObligationInputV1, ErasureObligationV1, ErasureOwnerCommandV1, ErasureOwnerResultV1,
    ErasurePersistencePortV1, ErasureProtectedOperationV1, ErasureRecordedAttemptReadV1,
    ErasureRecordedProgressReadV1, ErasureRecordedProgressV1, ErasureRecordedScopeReadV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRetryAdmissionV1, ErasureScopeExtensionV1,
    EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, LocalErasureArtifactDispositionV1,
    LocalErasureCacheGenerationV1, LocalErasureNegativeResultV1, LocalErasureRedactionV1,
    LocalErasureReplicaPurgeV1, LocalOwnerEffectV1, LocalOwnerResultBindingV1,
    PreparedLocalOwnerEffectV1, TimelineId,
};

use super::{map_erasure_error, ErasureCommandSenderV1, ErasureHostStore, HostedCoordinatorPortV1};
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

impl ErasureCommandSenderV1<'_> {
    /// The dispatch outbox of `request`: one [`ErasureOwnerCommandV1`] for
    /// each obligation of its committed active attempt that has no
    /// acknowledgement in that attempt yet, in the attempt's obligation
    /// order.
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
        let limits = self.host.recovery_limits;
        let authority = self.host.authority.clone();
        self.host
            .ensure_generation_with_inventory(self.generation)
            .and_then(|installed| {
                authority
                    .ok_or(ErasureHostErrorV1::AuthorizationDenied)
                    .map(|authority| (installed, authority))
            })
            .and_then(|(installed, authority)| {
                let port = HostedCoordinatorPortV1::new(
                    self.host.store.host_store(),
                    authority.as_ref(),
                    limits,
                )
                .with_verified_inventory(installed);
                let persistence: &dyn ErasurePersistencePortV1 = &port;
                persistence
                    .recorded_progress(&port, &port, request)
                    .map_err(map_erasure_error)
            })
            .map(|progress| progress.map_or_else(Vec::new, |progress| outbox(request, &progress)))
    }

    /// Destroy the key of one `key-registry` command (ADR-136 §4a).
    ///
    /// The command runs under the protected-append fence of `host_timeline`,
    /// the store's Erasure Host Timeline, which every bundle lists as a host
    /// Timeline, so no erasure ever freezes it. Inside that one fence it
    /// commits two transactions: the pending destruction of `identity`, then
    /// its tombstone together with the positive ELO1 through
    /// `commit_local_owner_effect`. The destruction request's
    /// `authorization_digest` is the command identity `CA(request, target)`
    /// (owner decision Q5), and the tombstone's deletion receipt is the key
    /// registry's request-bound `deletion_receipt`, which the ELO1 binds as
    /// its effect.
    ///
    /// A crash between the transactions leaves the pending destruction; the
    /// next run of the same command finds it and completes it. A key the
    /// registry already tombstoned, under any authorization, yields a
    /// positive ELO1 bound to that tombstone's existing receipt, committed
    /// only while the registry still holds it, so a repeat is idempotent. A key without registered private material, or a
    /// pending destruction under another authorization, is the permanent
    /// negative `KeyDestructionFailed`.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::Conflict`] unless `command` is a dispatched
    /// `key-registry` command of the request's active attempt whose target
    /// is `identity`'s key; the payload-free fence error when
    /// `host_timeline` is unavailable; otherwise a host error when no owner
    /// result could be made durable.
    pub fn destroy_key_for_erasure(
        &mut self,
        command: &ErasureOwnerCommandV1,
        identity: KeyIdentityV1,
        host_timeline: TimelineId,
    ) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
        self.host
            .with_store_fence(
                self.generation,
                host_timeline,
                ErasureProtectedOperationV1::Append,
                |store| Ok(destroyed_key(store, command, identity)),
            )
            .and_then(|result| result.map_err(map_erasure_error))
    }

    /// Run the owner work of one dispatched command and return its owner
    /// result; `LocalErasureExecutorV1` is the only caller.
    ///
    /// A `key-registry` command whose target names no registered key is the
    /// permanent negative `KeyDestructionFailed`; every other key command
    /// runs [`Self::destroy_key_for_erasure`] under `host_timeline`.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::Conflict`] for a command that is not
    /// dispatched in the request's active attempt; otherwise a payload-free
    /// host error when no owner result could be made durable.
    pub(crate) fn execute_local_owner(
        &mut self,
        command: &ErasureOwnerCommandV1,
        host_timeline: TimelineId,
    ) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
        self.host
            .ensure_generation(self.generation)
            .and_then(|()| {
                owner_work(self.host.store.host_store(), command).map_err(map_erasure_error)
            })
            .and_then(|(work, active)| match work {
                OwnerWorkV1::KeyDestruction => {
                    self.registered_key_destruction(command, host_timeline)
                }
                OwnerWorkV1::ReplicaPurge => {
                    purged_replica(self.host.store.host_store(), command).map_err(map_erasure_error)
                }
                OwnerWorkV1::Disposition => {
                    disposition(self.host.store.host_store(), command).map_err(map_erasure_error)
                }
                OwnerWorkV1::CacheGeneration => {
                    cache_generation(self.host.store.host_store(), command, &active)
                        .map_err(map_erasure_error)
                }
                OwnerWorkV1::Refused(error) => {
                    negative(self.host.store.host_store(), command, error)
                        .map_err(map_erasure_error)
                }
            })
    }

    /// Destroy the registered key a `key-registry` command targets; a target
    /// that names no registered key is the permanent negative
    /// `KeyDestructionFailed`.
    fn registered_key_destruction(
        &mut self,
        command: &ErasureOwnerCommandV1,
        host_timeline: TimelineId,
    ) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
        let Some(identity) = key_identity(
            self.host.store.host_store(),
            command.destruction.target.key_digest,
        ) else {
            return negative(
                self.host.store.host_store(),
                command,
                ErasureErrorV1::KeyDestructionFailed,
            )
            .map_err(map_erasure_error);
        };
        self.destroy_key_for_erasure(command, identity, host_timeline)
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

/// The committed active attempt `command` was dispatched in.
///
/// # Errors
/// `PolicyConflict` unless the request has an active attempt that
/// `command` names, whose obligation and command pairs hold the command's,
/// and whose obligation address the command's category, target, owner and
/// command identity re-derive; otherwise the closed read error.
fn dispatched_admission(
    store: &dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let destruction = command.destruction;
    store
        .recorded_active_attempt(command.request)
        .and_then(|active| {
            ErasureObligationV1::new(ErasureObligationInputV1 {
                category: destruction.category,
                target: destruction.target,
                owner: destruction.owner,
                command_identity: destruction.command,
            })
            .map(|obligation| (active, obligation.reference()))
        })
        .and_then(|(active, obligation)| {
            active
                .filter(|active| {
                    active.request() == command.request
                        && active.reference() == destruction.provenance
                        && obligation == destruction.obligation
                        && destruction.command
                            == pos_core::destruction_command_reference(
                                command.request,
                                destruction.target,
                            )
                        && active
                            .unresolved_obligations()
                            .iter()
                            .zip(active.command_identities())
                            .any(|pair| pair == (&destruction.obligation, &destruction.command))
                })
                .ok_or(ErasureErrorV1::PolicyConflict)
        })
}

/// The owner work of a dispatched `command` and its active attempt.
///
/// # Errors
/// `PolicyConflict` for a command that is not dispatched or whose owner is
/// no acknowledgement class of this store; otherwise the closed read error.
fn owner_work(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
) -> Result<(OwnerWorkV1, ErasureRetryAdmissionV1), ErasureErrorV1> {
    let destruction = command.destruction;
    dispatched_admission(store, command).and_then(|active| {
        store
            .erasure_store_identity()
            .and_then(|identity| identity.ok_or(ErasureErrorV1::PolicyConflict))
            .and_then(|identity| {
                let store_identity = ErasureReferenceV1::from_digest(*identity.as_bytes());
                LOCAL_OWNER_WORK
                    .iter()
                    .find(|(category, ack_class, _)| {
                        *category == destruction.category
                            && local_erasure_owner_ref_v1(
                                store_identity,
                                u64::from(*category),
                                ack_class,
                            ) == Ok(destruction.owner)
                    })
                    .map(|(_, _, work)| (*work, active))
                    .ok_or(ErasureErrorV1::PolicyConflict)
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
) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
    PreparedLocalOwnerEffectV1::new(effect, owner_binding(command, error)).and_then(|prepared| {
        ErasureOwnerResultV1::bind(command, prepared.owner_result().canonical_cbor())
            .and_then(|result| store.commit_local_owner_effect(prepared).map(|_| result))
    })
}

/// Commit one canonical positive effect record of `command`.
fn committed_record(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    record: Result<Vec<u8>, ErasureErrorV1>,
    effect: fn(Vec<u8>) -> LocalOwnerEffectV1,
) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
    record.and_then(|bytes| committed(store, command, None, effect(bytes)))
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
) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
    negative_effect(command, error)
        .and_then(|effect| committed(store, command, Some(error), effect))
}

/// The registered key whose ADR-136 key digest is `key_digest`, destroyed
/// or not.
fn key_identity(
    store: &dyn ErasureHostStore,
    key_digest: ErasureReferenceV1,
) -> Option<KeyIdentityV1> {
    store
        .load_key_registry()
        .ok()
        .flatten()
        .and_then(|registry| {
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
/// `PolicyConflict` unless `command` is a dispatched `key-registry` command
/// whose target is `identity`'s key; otherwise the closed error of an owner
/// result that could not be made durable.
fn destroyed_key(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    identity: KeyIdentityV1,
) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
    owner_work(store, command)
        .and_then(|(work, _)| {
            (work == OwnerWorkV1::KeyDestruction
                && local_erasure_key_digest_v1(&identity)
                    == Ok(command.destruction.target.key_digest))
            .then_some(())
            .ok_or(ErasureErrorV1::PolicyConflict)
        })
        .and_then(|()| {
            let registry = store.load_key_registry().ok().flatten();
            let Some(tombstone) = registry
                .as_ref()
                .and_then(|registry| registry.tombstone(identity))
            else {
                return key_phases(
                    store,
                    command,
                    identity,
                    registry
                        .as_ref()
                        .and_then(|registry| registry.key_record(identity))
                        .and_then(|record| record.private_material_digest),
                );
            };
            committed(
                store,
                command,
                None,
                LocalOwnerEffectV1::ExistingTombstone(Box::new(tombstone)),
            )
        })
}

/// The two destruction transactions of a key the registry has not
/// tombstoned and whose registered private material is `material`: the
/// pending phase, then the tombstone with its ELO1. A key without private
/// material, or whose pending phase the registry refuses, is the permanent
/// negative `KeyDestructionFailed`.
fn key_phases(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    identity: KeyIdentityV1,
    material: Option<Hash>,
) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
    material
        .map(|material| {
            KeyDestructionRequestV1::new(
                identity,
                material,
                Hash::from_bytes(command.destruction.command.digest()),
            )
        })
        .filter(|request| store.begin_key_registry_destruction(*request).is_ok())
        .map_or_else(
            || {
                negative_effect(command, ErasureErrorV1::KeyDestructionFailed)
                    .map(|effect| (Some(ErasureErrorV1::KeyDestructionFailed), effect))
            },
            |request| {
                Ok((
                    None,
                    LocalOwnerEffectV1::KeyTombstone {
                        request: Box::new(request),
                        deletion_receipt: deletion_receipt(&request),
                    },
                ))
            },
        )
        .and_then(|(error, effect)| committed(store, command, error, effect))
}

/// The key identities the ARD1 row of `target` depends on, when a Timeline
/// of the request's committed scope registers that row.
fn registered_dependencies(
    store: &dyn ErasureHostStore,
    request: ErasureReferenceV1,
    target: pos_core::ErasureRequiredTargetV1,
) -> Option<Vec<KeyIdentityV1>> {
    store
        .recorded_scope(request)
        .ok()
        .flatten()
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
                .flat_map(|timeline| {
                    EventStore::artifact_registrations_for_timeline(store, timeline, VIEW_LIST_MAX)
                        .unwrap_or_default()
                })
                .find(|row| {
                    row.artifact_class() == target.artifact_class
                        && ErasureReferenceV1::from_digest(*row.artifact_digest().as_bytes())
                            == target.artifact_digest
                })
        })
        .map(|row| {
            row.registration()
                .fields()
                .key_dependencies
                .iter()
                .map(|dependency| dependency.identity)
                .collect()
        })
}

/// The `artifact-store` or `managed-report` owner result of `command` (Q7).
///
/// It is the positive ELAD1, redacted with its views, only when the ARD1
/// row of the target is registered in the request's committed scope,
/// depends on at least one key, and the key registry has tombstoned every
/// key it depends on: the artifact is then unreadable. Any other row, an
/// unreadable scope or registry included, is the permanent negative
/// `ArtifactDeletionFailed`.
fn disposition(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
    let target = command.destruction.target;
    let redacted = registered_dependencies(store, command.request, target)
        .zip(store.load_key_registry().ok().flatten())
        .is_some_and(|(dependencies, registry)| {
            !dependencies.is_empty()
                && dependencies
                    .iter()
                    .all(|identity| registry.tombstone(*identity).is_some())
        });
    if redacted {
        let record = LocalErasureArtifactDispositionV1 {
            request: command.request,
            artifact_class: target.artifact_class,
            artifact_digest: target.artifact_digest,
            redaction: LocalErasureRedactionV1::Redacted,
            replay_claim_to: ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        };
        committed_record(
            store,
            command,
            record.to_canonical_cbor(),
            LocalOwnerEffectV1::ArtifactDisposition,
        )
    } else {
        negative(store, command, ErasureErrorV1::ArtifactDeletionFailed)
    }
}

/// The `client-cache-signal` owner result of `command`: the ELCG1 of the
/// request's committed ERSC1 at the attempt's admitted position (Q8).
///
/// # Errors
/// `ProvenanceMissing` when the request has no committed scope; otherwise
/// the closed read or commit error.
fn cache_generation(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    active: &ErasureRetryAdmissionV1,
) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
    let record = store
        .recorded_scope(command.request)
        .and_then(|scope| scope.ok_or(ErasureErrorV1::ProvenanceMissing))
        .map(|(commitment, _)| LocalErasureCacheGenerationV1 {
            request: command.request,
            scope_commitment: commitment.reference(),
            generation: active.admitted_position(),
        })
        .and_then(|record| record.to_canonical_cbor());
    committed_record(store, command, record, LocalOwnerEffectV1::CacheGeneration)
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
) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
    match store.purge_local_replica_residue() {
        Ok(()) => {
            let record = LocalErasureReplicaPurgeV1 {
                request: command.request,
                command: command.destruction.command,
                replica_id: command.destruction.target.replica_id,
            };
            committed_record(
                store,
                command,
                record.to_canonical_cbor(),
                LocalOwnerEffectV1::ReplicaPurge,
            )
        }
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
