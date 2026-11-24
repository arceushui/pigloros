//! The retained-Memory `initialize` entry and its atomic commit (#560
//! A3c-2c-3).
//!
//! [`MemoryCommunityDomainV1::initialize`] composes the installed lifecycle
//! authority, the backend-neutral planner and this domain's atomic commit
//! in the ADR-129 A5.5/R6.9 order:
//!
//! 1. the caller form, its P6 initializer set and the decision-locator
//!    counts (shape errors, before any authority call);
//! 2. the FAE1, the administrative decision and the R6.3 anchor-T check
//!    (12);
//! 3. with the metadata-service `inspect` decision, the retry lookup by
//!    `(T, operation_id)` (A5.3(5)), `StaleGeneration` once `anchor_G` is
//!    consumed (R6.3(3)), and the evidence horizons: every CPN1, CIS1 and
//!    CSR1 under the generation horizon and every metadata record under the
//!    metadata horizon must outlive the call's decision bound
//!    (`EvidenceExpired`);
//! 4. for the new effect, the metadata-service `write` decision, one
//!    initializer `read` decision per distinct initializer (R6.1(5)) and
//!    one member `execute` decision per roster member (A5.2(3)), each 12;
//! 5. the effects: a burned native producer ordinal, the metadata and
//!    `ExecutionState` keys, the sealed CMB1s, the planner records, the
//!    protected graph, the extractor's batch, the CAV1 (whose trust rows
//!    give 10), CAU1, COA1 and CMI1, and every metadata record sealed;
//! 6. the final writer's decision-bound check under the release guard, then
//!    the commit: the G5 inventory generation and the CSI1 are
//!    compared-and-swapped, the ARD1 rows are published (G7), and the keys,
//!    sealed records, COA1s and retry index are retained together.
//!
//! The owner decisions on #560 of 2026-11-20 fix the metadata key (item 3),
//! the cohort key's request digest (item 4), the allocator (item 5) and the
//! receipt and retry index (item 6).

use pos_core::community_lifecycle::{
    community_catalogue_owner_v1, CommunityArtifactAdmissionV1, CommunityArtifactKindV1,
    CommunityArtifactOperationV1, CommunityArtifactPurposeV1, CommunityCopyHolderV1,
    CommunityCopyInventoryInputV1, CommunityCopyInventoryV1, CommunityCopyStateV1,
    CommunityGenerationAdmissionV1, CommunityGenerationIdsV1, CommunityInitializationRequestV1,
    CommunityInitializationSourceV1, CommunityKeyIntentInputV1, CommunityKeyIntentV1,
    CommunityLifecycleErrorV1 as Error, CommunityMemberBindingV1, CommunityMemberSlotsV1,
    CommunityMetadataAnchorV1, CommunityMetadataSchemaV1, CommunityMetadataScopeInputV1,
    CommunityMetadataScopeV1, CommunityRecordKindsV1, CommunityScopeMembersV1,
    CommunitySelectionInputV1, CommunitySelectionV1, CommunitySharedCountsV1,
    CommunityTimelineFloorV1, CommunityTimelineFloorsV1,
};
use pos_core::store::EventStore;
use pos_core::{
    ArtifactRegistrationPersistencePortV1, AuthorityGranteeV1, AuthorityTrustRootSealV1, CoreError,
    FactualPrefixReadPortV1, Hash, TimelineId,
};
use zeroize::Zeroizing;

use super::extractor::{
    prepare_community_artifact_batch_v1, CommunityArtifactBatchFormV1,
    CommunityArtifactBatchInputV1, CommunityArtifactBatchV1, CommunityArtifactRecordInputV1,
};
use super::initializer::CommunityInitializerOwnerV1;
use super::lifecycle_authority::{
    CommunityAuthorityAdmissionV1, CommunityAuthorityCallV1, CommunityLifecycleAuthorityV1,
    CommunityMemberActionV1,
};
use super::memory_domain::{CommunityDomainBindingV1, MemoryCommunityDomainV1};
use super::metadata_authority::{CommunityMetadataAuthorityV1, MetadataActionV1};
use super::native_graph::{
    CommunityInitializationGraphInputV1, CommunityInitializationGraphV1,
    CommunityInitializationMemberV1,
};
use super::pass_state::CommunityPassStateV1;
use super::planner::{
    CommunityInitializationAuthorityV1, CommunityInitializationBindingsV1,
    CommunityInitializationEvidenceInputV1, CommunityInitializationInstallationV1,
    CommunityInitializationPlannerV1, CommunityInitializationRecordsV1, CommunityInitializeFormV1,
};
use super::private_hash::scope_set_digest;
use super::protection::{CommunityArtifactProtectorV1, CommunityProtectionCohortV1};
use super::sealer::SealedMetadataV1;
use super::store_domain::CommunityStoreDomainV1;
use super::vault::{fresh_identity, VaultKeyV1};

/// Preferred CBOR encoding of the empty scope-member array.
const EMPTY_SCOPE_ROWS: [u8; 1] = [0x80];

/// The installed composition of one domain's `initialize` entry. None of it
/// comes from a caller.
#[derive(Clone, Copy)]
pub struct CommunityInitializationContextV1<'a> {
    /// The planner's installed inputs. Their `state_limit_bytes` are each
    /// roster row's CNT1 State limit, checked against the row's CNT1 digest
    /// by pos-runtime's `community_state_limits_v1` (owner decision on #560,
    /// note 22891).
    pub installation: CommunityInitializationInstallationV1<'a>,
    /// The domain's installed metadata policy and CSI1 identities.
    pub binding: CommunityDomainBindingV1<'a>,
    /// The installed catalogue initializer owner (R6.1(2)).
    pub initializer: &'a CommunityInitializerOwnerV1,
}

/// One caller's code-0 `initialize` (A5.3(0)): its one FAE1, the caller form
/// and the untrusted leaf-grant locators of its decisions (A5.1).
#[derive(Clone, Copy)]
pub struct CommunityInitializeCallV1<'a> {
    /// The call's one canonical FAE1 (R6.2(1)).
    pub credential: &'a [u8],
    /// The CGI1 caller form.
    pub form: CommunityInitializeFormV1,
    /// The leaf grant of the administrative decision.
    pub administrative_leaf: Hash,
    /// One leaf grant per distinct roster initializer, in the order each
    /// initializer first appears in the roster (R6.1(5)).
    pub initializer_leaves: &'a [Hash],
    /// One leaf grant per roster member's `execute` decision, in roster
    /// order (A5.2(3)).
    pub member_leaves: &'a [Hash],
}

/// The original outcome of one committed initialization (owner decision on
/// #560, 2026-11-20, item 6). A retry returns it unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityInitializationReceiptV1 {
    timeline: TimelineId,
    generation: [u8; 16],
    request_digest: Hash,
    generation_admission: Zeroizing<Vec<u8>>,
}

impl CommunityInitializationReceiptV1 {
    /// The initialized Timeline.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// The admitted generation, `anchor_G` for the first initialize.
    #[must_use]
    pub const fn generation(&self) -> [u8; 16] {
        self.generation
    }

    /// `H(CGI1)` of the committed request.
    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.request_digest
    }

    /// The canonical CGA1 original generation result.
    #[must_use]
    pub fn generation_admission(&self) -> &[u8] {
        &self.generation_admission
    }

    fn from_generation_admission(bytes: Zeroizing<Vec<u8>>) -> Result<Self, Error> {
        let fields = *CommunityGenerationAdmissionV1::from_canonical_cbor(&bytes)?.as_input();
        Ok(Self {
            timeline: fields.timeline,
            generation: fields.generation,
            request_digest: fields.generation_request_digest,
            generation_admission: bytes,
        })
    }
}

/// One committed initialization, retained by the domain.
pub(super) struct CommittedInitializationV1 {
    /// The bound content (A5.3(5)): the CDP1 and the initial source; the
    /// key already fixes T and the operation identity, and a code-0 prior is
    /// null.
    pub(super) profile_digest: Hash,
    pub(super) initial_source: CommunityInitializationSourceV1,
    /// The administrative decision's leaf grant, whose grantee is the
    /// original principal (A5.3(6)).
    pub(super) leaf_grant_id: Hash,
    /// The protection ID of the metadata key that sealed `records`.
    pub(super) metadata_key: [u8; 16],
    /// Every sealed metadata record; the last is the CGA1.
    pub(super) records: Vec<SealedMetadataV1>,
    /// One COA1 per published ARD1.
    pub(super) admissions: Vec<CommunityArtifactAdmissionV1>,
}

/// Everything one initialization commits, staged before the writer.
pub(super) struct StagedInitializationV1 {
    key: (TimelineId, [u8; 16]),
    committed: CommittedInitializationV1,
    keys: [VaultKeyV1; 2],
    batch: CommunityArtifactBatchV1,
    selection: SealedMetadataV1,
    receipt: CommunityInitializationReceiptV1,
    /// The CSI1 the operation read: the swap's expected value.
    read_selection: Hash,
    /// The inventory generation CAU1 read (G5): the swap's expected value.
    inventory_generation: u64,
    /// The roster members, whose quarantine reserve the context holds
    /// (ADR-129 revision 13, R13.1(5)).
    members: u64,
    /// T's pass state: the seeded counters and the initial graph.
    pass_state: CommunityPassStateV1,
}

/// The read-only inputs of the staging steps.
#[derive(Clone, Copy)]
struct StageInputsV1<'s, 'p, 'a> {
    operation: &'s OperationV1<'p, 'a>,
    lifecycle: &'s CommunityLifecycleAuthorityV1,
    decisions: &'s DecisionsV1,
    authenticated: &'s CommunityAuthorityCallV1,
}

/// The sealed CMB1s, planned records and protected graph of one
/// initialization, with the extractor's batch.
struct MintedV1 {
    sealed: Vec<SealedMetadataV1>,
    bindings: CommunityInitializationBindingsV1,
    records: CommunityInitializationRecordsV1,
    protector: CommunityArtifactProtectorV1,
    graph: CommunityInitializationGraphV1,
    batch: CommunityArtifactBatchV1,
    /// The actual recorded-set counts of T's history, which seed the
    /// counters (R10.3(6)).
    history: CommunitySharedCountsV1,
    /// The roster length.
    members: u64,
}

/// The CAU1 of one initialization with its COA1s and CMI1s.
struct EvidencedV1 {
    evidence: CommunityInitializationAuthorityV1,
    admissions: Vec<CommunityArtifactAdmissionV1>,
    materializations: Vec<Zeroizing<Vec<u8>>>,
}

/// The outcome of every step before the final writer.
pub(super) enum PreparedV1 {
    /// A retry's original receipt.
    Original(CommunityInitializationReceiptV1),
    /// A new initialization and the call whose bound the writer checks.
    Staged(Box<StagedInitializationV1>, CommunityAuthorityCallV1),
}

/// The decisions one new initialization needs (A5.2, R6.1(5)).
struct DecisionsV1 {
    administrative: CommunityAuthorityAdmissionV1,
    data: Vec<CommunityAuthorityAdmissionV1>,
    metadata_request_digest: Hash,
}

/// One planned new initialization: its installed context, planner and
/// call, the generation it derived and the premises it read.
struct OperationV1<'p, 'a> {
    seal: &'static AuthorityTrustRootSealV1,
    context: CommunityInitializationContextV1<'a>,
    planner: &'p CommunityInitializationPlannerV1<'a>,
    call: CommunityInitializeCallV1<'a>,
    generation: [u8; 16],
    anchor_generation: [u8; 16],
    selection: Zeroizing<Vec<u8>>,
    selection_address: Hash,
}

impl OperationV1<'_, '_> {
    const fn timeline(&self) -> TimelineId {
        self.call.form.timeline
    }

    const fn operation(&self) -> CommunityArtifactOperationV1 {
        CommunityArtifactOperationV1::Initialization(self.call.form.operation_id)
    }

    const fn metadata_horizon(&self) -> u64 {
        self.context
            .binding
            .metadata_policy
            .as_input()
            .metadata_not_after_micros
    }

    const fn generation_horizon(&self) -> u64 {
        self.context
            .installation
            .profile
            .as_input()
            .retention
            .generation_not_after_micros
    }
}

impl MemoryCommunityDomainV1 {
    /// Initialize the anchor Timeline's first generation (code 0), or
    /// return the original outcome of a retry.
    ///
    /// Only the trusted composition root, which holds the
    /// [`AuthorityTrustRootSealV1`], initializes:
    ///
    /// ```compile_fail,E0061
    /// use pos_store::community::{
    ///     CommunityInitializationContextV1, CommunityInitializeCallV1,
    ///     CommunityLifecycleAuthorityV1, CommunityMetadataAuthorityV1, MemoryCommunityDomainV1,
    /// };
    /// fn forge(
    ///     domain: &mut MemoryCommunityDomainV1,
    ///     context: CommunityInitializationContextV1<'_>,
    ///     lifecycle: &mut CommunityLifecycleAuthorityV1,
    ///     metadata: &mut CommunityMetadataAuthorityV1,
    ///     call: CommunityInitializeCallV1<'_>,
    /// ) {
    ///     let _ = domain.initialize(context, lifecycle, metadata, call);
    /// }
    /// ```
    ///
    /// # Errors
    /// In the A5.5 order: `InvalidBinding` for a refused caller form, a
    /// locator count other than the roster's or its distinct initializers',
    /// or an installation of another domain; `EvidenceUnavailable` for every
    /// authority failure, an unbootstrapped domain, a Timeline other than
    /// `anchor_T` and a writer at or after the decision bound; `Conflict`
    /// for a retry with other bound content or by another principal;
    /// `StaleGeneration` once `anchor_G` is consumed; `EvidenceExpired` when
    /// the decision bound is after the generation or the metadata horizon,
    /// whichever ends first; `AdmissionDenied`
    /// for a refused trust row; and the planner, graph, extractor and codec
    /// refusals.
    pub fn initialize(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        context: CommunityInitializationContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: CommunityInitializeCallV1<'_>,
    ) -> Result<CommunityInitializationReceiptV1, Error> {
        match self.prepare(seal, context, lifecycle, metadata, call)? {
            PreparedV1::Original(receipt) => Ok(receipt),
            PreparedV1::Staged(staged, authenticated) => {
                lifecycle.check_writer_bound(authenticated, self)?;
                self.commit(*staged)
            }
        }
    }

    /// Every step before the final writer: the original outcome of a
    /// retry, or the staged commit with the call whose bound the writer
    /// checks.
    pub(super) fn prepare(
        &mut self,
        seal: &'static AuthorityTrustRootSealV1,
        context: CommunityInitializationContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: CommunityInitializeCallV1<'_>,
    ) -> Result<PreparedV1, Error> {
        let planner = CommunityInitializationPlannerV1::new(seal, context.installation, call.form)?;
        self.check_shape(context, call)?;
        let authenticated = lifecycle.authenticate(call.credential, planner.request(), self)?;
        let administrative =
            lifecycle.authorize_administrative(&authenticated, self, call.administrative_leaf)?;
        let (anchor, selection, selection_address) = self.premises(context, call.form.timeline)?;
        self.admit(
            context.binding.metadata_policy,
            metadata,
            MetadataActionV1::Inspect,
        )?;
        if let Some(original) = self
            .initializations
            .get(&(call.form.timeline, call.form.operation_id))
        {
            return self
                .retry(original, context, call.form, &administrative)
                .map(PreparedV1::Original);
        }
        let anchor_generation = anchor.as_input().anchor_generation;
        let generation = CommunitySelectionV1::from_canonical_cbor(&selection)
            .and_then(|current| planner.generation(&anchor, &current))?;
        let operation = OperationV1 {
            seal,
            context,
            planner: &planner,
            call,
            generation,
            anchor_generation,
            selection,
            selection_address,
        };
        if authenticated.decision_bound().as_micros()
            > operation
                .generation_horizon()
                .min(operation.metadata_horizon())
        {
            return Err(Error::EvidenceExpired);
        }
        let decisions = self.decisions(
            &operation,
            lifecycle,
            metadata,
            administrative,
            &authenticated,
        )?;
        self.stage(StageInputsV1 {
            operation: &operation,
            lifecycle,
            decisions: &decisions,
            authenticated: &authenticated,
        })
        .map(|staged| PreparedV1::Staged(Box::new(staged), authenticated))
    }

    /// The step-1 shape of the call against the installed context.
    fn check_shape(
        &self,
        context: CommunityInitializationContextV1<'_>,
        call: CommunityInitializeCallV1<'_>,
    ) -> Result<(), Error> {
        let installation = context.installation;
        let roster = installation.profile.as_input().roster;
        if installation.store_incarnation == self.store_incarnation
            && installation.native_profile_digest == context.binding.native_profile_digest
            && call.member_leaves.len() == roster.len()
            && call.initializer_leaves.len() == distinct_initializers(installation).len()
        {
            Ok(())
        } else {
            Err(Error::InvalidBinding)
        }
    }

    /// The validated CMA1, which must name `timeline` as `anchor_T`
    /// (R6.3(1)), and the current CSI1 with its CNE1 address.
    fn premises(
        &self,
        context: CommunityInitializationContextV1<'_>,
        timeline: TimelineId,
    ) -> Result<(CommunityMetadataAnchorV1, Zeroizing<Vec<u8>>, Hash), Error> {
        let record = self.bootstrap.as_ref().ok_or(Error::EvidenceUnavailable)?;
        let anchor = CommunityMetadataAnchorV1::from_canonical_cbor(
            &record.anchor,
            context.binding.metadata_policy,
        )
        .ok()
        .filter(|anchor| anchor.as_input().anchor_timeline == timeline)
        .ok_or(Error::EvidenceUnavailable)?;
        let (key, sealed) = self.selection.as_ref().map_or(
            (record.protection_id, &record.selection),
            |(key, sealed)| (*key, sealed),
        );
        self.keys
            .get(&key)
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|key| key.open(sealed))
            .map(|selection| (anchor, selection, sealed.address))
    }

    /// The A5.3(5) retry outcome, after the retry's own administrative
    /// decision: the original receipt when the bound content is equal and
    /// the decision's principal is the original leaf grant's grantee, else
    /// `Conflict`. The retained CGA1 and every retained COA1's ARD1 must
    /// still resolve.
    fn retry(
        &self,
        original: &CommittedInitializationV1,
        context: CommunityInitializationContextV1<'_>,
        form: CommunityInitializeFormV1,
        administrative: &CommunityAuthorityAdmissionV1,
    ) -> Result<CommunityInitializationReceiptV1, Error> {
        let grantee = CommunityStoreDomainV1::load_authority(self, original.leaf_grant_id)
            .and_then(|persisted| {
                persisted
                    .chain()
                    .grants()
                    .last()
                    .map(|leaf| leaf.grantee().clone())
                    .ok_or(Error::EvidenceUnavailable)
            })?;
        if original.profile_digest != context.installation.profile.digest()
            || original.initial_source != form.initial_source
            || grantee
                != AuthorityGranteeV1::Principal(administrative.decision().principal().clone())
        {
            return Err(Error::Conflict);
        }
        self.keys
            .get(&original.metadata_key)
            .zip(original.records.last())
            .ok_or(Error::EvidenceUnavailable)
            .and_then(|(key, sealed)| key.open(sealed))
            .and_then(|opened| {
                // A retained record that no longer decodes as the CGA1 is
                // retained evidence that does not resolve, not a caller
                // encoding error.
                CommunityInitializationReceiptV1::from_generation_admission(opened)
                    .map_err(|_| Error::EvidenceUnavailable)
            })
            .and_then(|receipt| {
                community_catalogue_owner_v1(receipt.timeline, receipt.generation).and_then(
                    |owner| {
                        original
                            .admissions
                            .iter()
                            .all(|admission| {
                                matches!(
                                    ArtifactRegistrationPersistencePortV1::read_artifact_registration(
                                        &self.store,
                                        &owner,
                                        admission.as_input().registration_address,
                                    ),
                                    Ok(Some(_))
                                )
                            })
                            .then_some(receipt)
                            .ok_or(Error::EvidenceUnavailable)
                    },
                )
            })
    }

    /// The step-5 decisions of a new initialization: metadata `write`, one
    /// initializer `read` per distinct initializer and one member `execute`
    /// per roster member, each from its caller-named leaf.
    fn decisions(
        &self,
        operation: &OperationV1<'_, '_>,
        lifecycle: &CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        administrative: CommunityAuthorityAdmissionV1,
        authenticated: &CommunityAuthorityCallV1,
    ) -> Result<DecisionsV1, Error> {
        let context = operation.context;
        let write = self.admit(
            context.binding.metadata_policy,
            metadata,
            MetadataActionV1::Write,
        )?;
        let mut data = distinct_initializers(context.installation)
            .into_iter()
            .zip(operation.call.initializer_leaves)
            .map(|(initializer, leaf)| {
                lifecycle.authorize_initializer(
                    authenticated,
                    context.initializer,
                    initializer,
                    self,
                    *leaf,
                )
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let roster = context.installation.profile.as_input().roster;
        operation
            .planner
            .bindings(operation.generation)
            .and_then(|bindings| {
                bindings
                    .member_bindings()
                    .zip(roster)
                    .zip(operation.call.member_leaves)
                    .map(|((bytes, row), leaf)| {
                        CommunityMemberBindingV1::from_canonical_cbor(bytes, row.implementation())
                            .and_then(|member| {
                                lifecycle.authorize_member(
                                    authenticated,
                                    &member,
                                    CommunityMemberActionV1::Execute,
                                    self,
                                    *leaf,
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, Error>>()
            })
            .map(|members| {
                data.extend(members);
                DecisionsV1 {
                    administrative,
                    data,
                    metadata_request_digest: write.request_digest(),
                }
            })
    }

    /// Allocate and burn the next native producer ordinal (ADR-129 §4).
    fn allocate_producer_ordinal(&mut self) -> Result<u64, Error> {
        self.native_producer_ordinal
            .checked_add(1)
            .inspect(|ordinal| self.native_producer_ordinal = *ordinal)
            .ok_or(Error::CapacityExhausted)
    }

    /// Stage every record of the new initialization before the writer:
    /// burn a producer ordinal, provision the metadata key (item 3), mint
    /// and protect the records, read the CAV1 and derive CAU1, COA1 and
    /// CMI1, then seal every metadata record and the successor CSI1.
    fn stage(
        &mut self,
        inputs: StageInputsV1<'_, '_, '_>,
    ) -> Result<StagedInitializationV1, Error> {
        self.allocate_producer_ordinal().and_then(|ordinal| {
            metadata_intent(inputs.operation, inputs.decisions)
                .and_then(VaultKeyV1::provision)
                .and_then(|mut key| {
                    metadata_scope(self.store_incarnation, inputs.operation, &key).and_then(
                        |scope| {
                            self.mint(inputs, ordinal, &mut key, &scope)
                                .and_then(|minted| {
                                    self.evidence(inputs, &minted, &key)
                                        .map(|evidenced| (minted, evidenced))
                                })
                                .and_then(|(minted, evidenced)| {
                                    self.finish(inputs, ordinal, key, &scope, minted, evidenced)
                                })
                        },
                    )
                })
        })
    }

    /// Seal each member's CMB1 under the metadata key, then plan the CGI1,
    /// CSB1, CBQ1 and CPV1 over their envelope addresses and protect the
    /// initial graph under one `ExecutionState` cohort (item 4).
    fn mint(
        &self,
        inputs: StageInputsV1<'_, '_, '_>,
        ordinal: u64,
        key: &mut VaultKeyV1,
        scope: &CommunityMetadataScopeV1<'_>,
    ) -> Result<MintedV1, Error> {
        let operation = inputs.operation;
        let roster = operation
            .context
            .installation
            .profile
            .as_input()
            .roster
            .len() as u64;
        operation
            .planner
            .bindings(operation.generation)
            .and_then(|bindings| {
                bindings
                    .member_bindings()
                    .map(|bytes| key.seal(scope, CommunityMetadataSchemaV1::Cmb1, bytes))
                    .collect::<Result<Vec<_>, Error>>()
                    .and_then(|sealed| {
                        let addresses: Vec<Hash> =
                            sealed.iter().map(|record| record.address).collect();
                        self.history_counts(operation.timeline())
                            .and_then(|history| {
                                self.check_initialize_budget(operation.timeline(), roster)
                                    .map(|()| history)
                            })
                            .and_then(|history| {
                                operation
                                    .planner
                                    .records(
                                        operation.generation,
                                        &inputs.decisions.administrative,
                                        &addresses,
                                        history,
                                    )
                                    .map(|records| (records, history))
                            })
                            .and_then(|(records, history)| {
                                cohort(operation, records.scope_binding_digest(), inputs.decisions)
                                    .and_then(|cohort| {
                                        CommunityArtifactProtectorV1::provision(
                                            operation.seal,
                                            cohort,
                                        )
                                    })
                                    .and_then(|mut protector| {
                                        self.graph(
                                            operation,
                                            &records,
                                            &bindings,
                                            &addresses,
                                            ordinal,
                                            &mut protector,
                                        )
                                        .and_then(
                                            |graph| {
                                                batch(
                                                    operation, &records, &bindings, &graph,
                                                    &protector,
                                                )
                                                .map(|batch| MintedV1 {
                                                    sealed,
                                                    bindings,
                                                    records,
                                                    protector,
                                                    graph,
                                                    batch,
                                                    history,
                                                    members: roster,
                                                })
                                            },
                                        )
                                    })
                            })
                    })
            })
    }

    /// T's recorded-set counts, the history seed of its counters (R10.3(6)).
    ///
    /// The store counts a Timeline's own set only, not a Fork child's
    /// inherited prefix, which the seed of a Fork child must include. Until
    /// the Fork slice reads that prefix, a Fork child is refused rather than
    /// undercounted. Like the graph's logical-head read, every store refusal
    /// (an absent or erasure-fenced Timeline, a storage failure) is one
    /// outcome: unavailable evidence.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a Fork child, and `EvidenceUnavailable`
    /// when the store cannot read the Timeline or its counts.
    fn history_counts(&self, timeline: TimelineId) -> Result<CommunitySharedCountsV1, Error> {
        self.store
            .get_timeline(timeline)
            .and_then(|found| found.ok_or(CoreError::TimelineNotFound(timeline)))
            .and_then(|found| {
                self.store
                    .factual_set_counts(timeline)
                    .map(|counts| (found.meta.fork_point.is_some(), counts))
            })
            .or(Err(Error::EvidenceUnavailable))
            .and_then(|(fork_child, counts)| {
                if fork_child {
                    Err(Error::InvalidBinding)
                } else {
                    Ok(CommunitySharedCountsV1 {
                        nodes: counts.nodes as u64,
                        edges: counts.edges as u64,
                        declared_inputs: counts.inputs as u64,
                        encoded_record_bytes: 0,
                    })
                }
            })
    }

    /// The CAV1 read now with every decision and both keys, the CAU1, one
    /// COA1 per protected record and one CMI1 per COA1.
    fn evidence(
        &self,
        inputs: StageInputsV1<'_, '_, '_>,
        minted: &MintedV1,
        key: &VaultKeyV1,
    ) -> Result<EvidencedV1, Error> {
        let operation = inputs.operation;
        let planner = operation.planner;
        let generation = operation.generation;
        let mut admitted: Vec<&CommunityAuthorityAdmissionV1> =
            vec![&inputs.decisions.administrative];
        admitted.extend(&inputs.decisions.data);
        let keys: [&CommunityKeyIntentV1; 2] = [key.intent(), minted.protector.key_intent()];
        planner
            .current_view(self, inputs.lifecycle, generation, &admitted, &keys)
            .and_then(|view| {
                planner.authority_evidence(
                    inputs.lifecycle,
                    generation,
                    CommunityInitializationEvidenceInputV1 {
                        call: inputs.authenticated,
                        records: &minted.records,
                        view: &view,
                        graph: &minted.graph,
                    },
                )
            })
            .and_then(|evidence| {
                planner
                    .admissions(&minted.graph, &evidence)
                    .and_then(|admissions| {
                        planner
                            .materializations(generation, &minted.graph, &admissions)
                            .map(|materializations| EvidencedV1 {
                                evidence,
                                admissions,
                                materializations,
                            })
                    })
            })
    }

    /// Seal every remaining metadata record and the successor CSI1 under
    /// the metadata key, close both keys and stage the commit.
    fn finish(
        &self,
        inputs: StageInputsV1<'_, '_, '_>,
        ordinal: u64,
        mut key: VaultKeyV1,
        scope: &CommunityMetadataScopeV1<'_>,
        minted: MintedV1,
        evidenced: EvidencedV1,
    ) -> Result<StagedInitializationV1, Error> {
        let operation = inputs.operation;
        let MintedV1 {
            mut sealed,
            bindings,
            records,
            protector,
            graph,
            batch,
            history,
            members,
        } = minted;
        let (mut cohort_key, cohort_copy) = protector.into_parts();
        key_copy(operation, &key)
            .and_then(|copy| {
                let copies = [copy.to_canonical_cbor(), cohort_copy.to_canonical_cbor()];
                plaintexts(
                    &bindings,
                    &records,
                    evidenced.evidence.evidence(),
                    &evidenced.materializations,
                    &graph,
                    &copies,
                )
                .into_iter()
                .map(|(schema, plaintext)| key.seal(scope, schema, plaintext))
                .collect::<Result<Vec<_>, Error>>()
            })
            .and_then(|rest| {
                sealed.extend(rest);
                successor(
                    self.store_incarnation,
                    operation,
                    ordinal,
                    graph.selected_head_digest(),
                )
                .and_then(|successor| key.seal(scope, CommunityMetadataSchemaV1::Csi1, &successor))
            })
            .and_then(|selection| {
                CommunityInitializationReceiptV1::from_generation_admission(Zeroizing::new(
                    graph.generation_admission().to_vec(),
                ))
                .map(|receipt| (selection, receipt))
            })
            .map(|(selection, receipt)| {
                key.close();
                cohort_key.close();
                StagedInitializationV1 {
                    pass_state: CommunityPassStateV1::initialized(history, &graph),
                    key: (operation.timeline(), operation.call.form.operation_id),
                    committed: CommittedInitializationV1 {
                        profile_digest: operation.context.installation.profile.digest(),
                        initial_source: operation.call.form.initial_source,
                        leaf_grant_id: inputs.decisions.administrative.leaf_grant_id(),
                        metadata_key: key.intent().as_input().protection_operation_id,
                        records: sealed,
                        admissions: evidenced.admissions,
                    },
                    inventory_generation: evidenced.evidence.inventory_generation(),
                    keys: [key, cohort_key],
                    batch,
                    selection,
                    receipt,
                    read_selection: operation.selection_address,
                    members,
                }
            })
    }

    /// The protected initial graph, minted with the burned `ordinal` on the
    /// Timeline's actual Event logical head.
    fn graph(
        &self,
        operation: &OperationV1<'_, '_>,
        records: &CommunityInitializationRecordsV1,
        bindings: &CommunityInitializationBindingsV1,
        addresses: &[Hash],
        ordinal: u64,
        protector: &mut CommunityArtifactProtectorV1,
    ) -> Result<CommunityInitializationGraphV1, Error> {
        let context = operation.context;
        let profile = context.installation.profile;
        self.store
            .logical_head(operation.timeline())
            // Fail closed: an absent `anchor_T` (`TimelineNotFound`), an
            // erasure-fenced one and a storage-integrity failure are each
            // unavailable evidence (12). They share that one outcome, so no
            // separate arm per `CoreError` would differ.
            .map_err(|_| Error::EvidenceUnavailable)
            .and_then(|event_logical_head| {
                CommunityInitializationRequestV1::from_canonical_cbor(records.request()).and_then(
                    |request| {
                        bindings
                            .member_bindings()
                            .zip(profile.as_input().roster)
                            .map(|(bytes, row)| {
                                CommunityMemberBindingV1::from_canonical_cbor(
                                    bytes,
                                    row.implementation(),
                                )
                            })
                            .collect::<Result<Vec<_>, Error>>()
                            .and_then(|members| {
                                let entries: Vec<CommunityInitializationMemberV1<'_>> = members
                                    .iter()
                                    .zip(addresses)
                                    .map(|(binding, address)| CommunityInitializationMemberV1 {
                                        binding,
                                        binding_envelope_address: *address,
                                    })
                                    .collect();
                                CommunityInitializationGraphV1::assemble(
                                    operation.seal,
                                    CommunityInitializationGraphInputV1 {
                                        store_incarnation: self.store_incarnation,
                                        producer_ordinal: ordinal,
                                        request: &request,
                                        profile,
                                        members: &entries,
                                        owner_binding_digest: bindings.owner_binding_digest(),
                                        host_provenance_digest: records.provenance_digest(),
                                        event_logical_head,
                                    },
                                    context.initializer,
                                    protector,
                                )
                            })
                    },
                )
            })
    }

    /// The writer's compares before anything is published.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when the inventory generation CAU1 read
    /// or the CSI1 the operation read moved, and `Conflict` when the
    /// Timeline already has pass state: a Timeline initializes once (a
    /// second code-0 initialize gives `StaleGeneration` before staging), and
    /// its pass state is never reset.
    fn check_writer(&self, staged: &StagedInitializationV1) -> Result<(), Error> {
        let current = self
            .selection
            .as_ref()
            .map(|(_, sealed)| sealed.address)
            .or_else(|| {
                self.bootstrap
                    .as_ref()
                    .map(|record| record.selection.address)
            });
        if self.inventory_generation != staged.inventory_generation
            || current != Some(staged.read_selection)
        {
            return Err(Error::EvidenceUnavailable);
        }
        if self.pass_states.contains_key(&staged.key.0) {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// The atomic commit (ADR-129 §3, §4; G5, G7).
    ///
    /// The writer compares the inventory generation CAU1 read and the CSI1
    /// the operation read with the current ones, publishes the ARD1 rows,
    /// and only then retains the keys, the successor CSI1, the sealed
    /// records, the COA1s and the retry index, and advances the inventory
    /// generation once.
    ///
    /// # Errors
    /// Returns the [`Self::check_writer`] refusals and the ARD1 publication
    /// refusal; each leaves the domain unchanged.
    pub(super) fn commit(
        &mut self,
        staged: StagedInitializationV1,
    ) -> Result<CommunityInitializationReceiptV1, Error> {
        self.check_writer(&staged)?;
        self.store.commit_community_artifact_batch(&staged.batch)?;
        let [metadata_key, cohort_key] = staged.keys;
        let metadata_id = metadata_key.intent().as_input().protection_operation_id;
        self.keys.insert(metadata_id, metadata_key);
        self.keys.insert(
            cohort_key.intent().as_input().protection_operation_id,
            cohort_key,
        );
        self.selection = Some((metadata_id, staged.selection));
        self.inventory_generation += 1;
        self.count_erasure_context(staged.key.0, staged.members);
        self.pass_states.insert(staged.key.0, staged.pass_state);
        self.initializations.insert(staged.key, staged.committed);
        Ok(staged.receipt)
    }
}

/// Every metadata record the initialization seals after its CMB1s, in
/// order: COB1, CGI1, CSB1, CBQ1, CPV1, CAU1, each CMI1 and CMS1, CST1,
/// CSH1, CGR1, both keys' CCI1s and, last, the CGA1.
fn plaintexts<'r>(
    bindings: &'r CommunityInitializationBindingsV1,
    records: &'r CommunityInitializationRecordsV1,
    evidence: &'r [u8],
    materializations: &'r [Zeroizing<Vec<u8>>],
    graph: &'r CommunityInitializationGraphV1,
    copies: &'r [Zeroizing<Vec<u8>>; 2],
) -> Vec<(CommunityMetadataSchemaV1, &'r [u8])> {
    let mut plaintexts: Vec<(CommunityMetadataSchemaV1, &[u8])> = vec![
        (CommunityMetadataSchemaV1::Cob1, bindings.owner_binding()),
        (CommunityMetadataSchemaV1::Cgi1, records.request()),
        (CommunityMetadataSchemaV1::Csb1, records.scope_binding()),
        (CommunityMetadataSchemaV1::Cbq1, records.budget_quote()),
        (CommunityMetadataSchemaV1::Cpv1, records.provenance()),
        (CommunityMetadataSchemaV1::Cau1, evidence),
    ];
    plaintexts.extend(
        materializations
            .iter()
            .map(|record| (CommunityMetadataSchemaV1::Cmi1, record.as_slice())),
    );
    plaintexts.extend(
        graph
            .member_progress()
            .map(|record| (CommunityMetadataSchemaV1::Cms1, record)),
    );
    plaintexts.extend([
        (CommunityMetadataSchemaV1::Cst1, graph.host_progress()),
        (CommunityMetadataSchemaV1::Csh1, graph.selected_head()),
        (CommunityMetadataSchemaV1::Cgr1, graph.graph_root()),
        (CommunityMetadataSchemaV1::Cci1, copies[0].as_slice()),
        (CommunityMetadataSchemaV1::Cci1, copies[1].as_slice()),
        (
            CommunityMetadataSchemaV1::Cga1,
            graph.generation_admission(),
        ),
    ]);
    plaintexts
}

/// The distinct initializer digests of the roster, in first-appearance
/// order (R6.1(5)).
fn distinct_initializers(installation: CommunityInitializationInstallationV1<'_>) -> Vec<Hash> {
    let mut digests: Vec<Hash> = Vec::new();
    for row in installation.profile.as_input().roster {
        let digest = Hash::from_bytes(row.initializer().digest);
        if !digests.contains(&digest) {
            digests.push(digest);
        }
    }
    digests
}

/// The initialization's metadata CKP1 (owner decision on #560, 2026-11-20,
/// item 3): parent `Initialization(operation_id)`, `LifecycleControl`, the
/// anchor coordinates, the empty scope, the metadata horizon and the
/// metadata `write` decision's request digest.
fn metadata_intent(
    operation: &OperationV1<'_, '_>,
    decisions: &DecisionsV1,
) -> Result<CommunityKeyIntentInputV1, Error> {
    fresh_identity().map(|protection_operation_id| CommunityKeyIntentInputV1 {
        protection_operation_id,
        parent_operation: operation.operation(),
        timeline: operation.timeline(),
        generation: operation.anchor_generation,
        purpose: CommunityArtifactPurposeV1::LifecycleControl,
        scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
        evidence_not_after_micros: operation.metadata_horizon(),
        allowed_record_kinds: CommunityRecordKindsV1::empty()
            .with(CommunityArtifactKindV1::LifecycleControl),
        member_slots: CommunityMemberSlotsV1::empty(),
        material_fingerprint: Hash::zero(),
        authority_request_digest: decisions.metadata_request_digest,
    })
}

/// The CSM1 cover of every metadata record the operation seals: the anchor
/// coordinates, the metadata key's protection ID and the empty scope.
fn metadata_scope(
    store_incarnation: [u8; 16],
    operation: &OperationV1<'_, '_>,
    key: &VaultKeyV1,
) -> Result<CommunityMetadataScopeV1<'static>, Error> {
    CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
        store_incarnation,
        metadata_anchor_timeline: operation.timeline(),
        metadata_anchor_generation: operation.anchor_generation,
        protection_operation_id: key.intent().as_input().protection_operation_id,
        scope_members: CommunityScopeMembersV1::from_members(&[]),
        metadata_not_after_micros: operation.metadata_horizon(),
    })
}

/// The CCI1 key-vault copy of the metadata key's material.
fn key_copy(
    operation: &OperationV1<'_, '_>,
    key: &VaultKeyV1,
) -> Result<CommunityCopyInventoryV1, Error> {
    fresh_identity().and_then(|copy_id| {
        CommunityCopyInventoryV1::new(CommunityCopyInventoryInputV1 {
            copy_id,
            revision: 1,
            predecessor: None,
            parent_operation: operation.operation(),
            timeline: operation.timeline(),
            generation: operation.anchor_generation,
            holder: CommunityCopyHolderV1::KeyVault,
            holder_digest: key.intent().digest(),
            purpose: CommunityArtifactPurposeV1::LifecycleControl,
            scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
            object_commitment: None,
            state: CommunityCopyStateV1::Owned,
            deadline_micros: operation.metadata_horizon(),
        })
    })
}

/// The one `ExecutionState` cohort of the initialization, over every roster
/// slot, whose scope cover is the CSB1 and whose request digest is the
/// administrative decision's (owner decision on #560, 2026-11-20, item 4).
fn cohort(
    operation: &OperationV1<'_, '_>,
    scope_cover_digest: Hash,
    decisions: &DecisionsV1,
) -> Result<CommunityProtectionCohortV1, Error> {
    let slots: Vec<u16> = (0_u16..)
        .take(
            operation
                .context
                .installation
                .profile
                .as_input()
                .roster
                .len(),
        )
        .collect();
    CommunityMemberSlotsV1::new(&slots).map(|member_slots| CommunityProtectionCohortV1 {
        parent_operation: operation.operation(),
        timeline: operation.timeline(),
        generation: operation.generation,
        purpose: CommunityArtifactPurposeV1::ExecutionState,
        scope_set_digest: scope_set_digest(&EMPTY_SCOPE_ROWS),
        scope_cover_digest,
        evidence_not_after_micros: operation.generation_horizon(),
        allowed_record_kinds: CommunityRecordKindsV1::empty()
            .with(CommunityArtifactKindV1::StateContent)
            .with(CommunityArtifactKindV1::StateRevisionOrHead)
            .with(CommunityArtifactKindV1::ExecutionProvenance)
            .with(CommunityArtifactKindV1::ClassificationProof),
        member_slots,
        authority_request_digest: decisions.administrative.decision().request_digest(),
    })
}

/// The extractor's verified batch of the graph: a code-0 initialize reads
/// no selected head and expects none.
fn batch(
    operation: &OperationV1<'_, '_>,
    records: &CommunityInitializationRecordsV1,
    bindings: &CommunityInitializationBindingsV1,
    graph: &CommunityInitializationGraphV1,
    protector: &CommunityArtifactProtectorV1,
) -> Result<CommunityArtifactBatchV1, Error> {
    let inputs: Vec<CommunityArtifactRecordInputV1<'_>> = graph
        .records()
        .iter()
        .map(|record| CommunityArtifactRecordInputV1 {
            object: record.protected().object(),
            registration: record.protected().registration(),
        })
        .collect();
    CommunityInitializationRequestV1::from_canonical_cbor(records.request()).and_then(|request| {
        prepare_community_artifact_batch_v1(
            operation.seal,
            CommunityArtifactBatchFormV1::Closure(CommunityArtifactBatchInputV1 {
                store_incarnation: operation.context.installation.store_incarnation,
                profile_digest: operation.context.installation.profile.digest(),
                operation_id: operation.call.form.operation_id,
                authorization_ref: request.as_input().authorization_ref,
                owner_binding_digest: bindings.owner_binding_digest(),
                records: &inputs,
                graph_root: graph.graph_root(),
                selected_head: graph.selected_head(),
                current_head: None,
                expected_prior_head: None,
            }),
            &[protector],
        )
    })
}

/// The successor CSI1: the read rows plus the new Timeline's row, whose
/// active generation is `G` and whose selection is `H(CSH1)`, and the
/// burned producer ordinal (owner decision on #560, 2026-11-20, item 5).
fn successor(
    store_incarnation: [u8; 16],
    operation: &OperationV1<'_, '_>,
    ordinal: u64,
    selected_head: Hash,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let binding = operation.context.binding;
    CommunitySelectionV1::from_canonical_cbor(&operation.selection).and_then(|current| {
        current
            .as_input()
            .timeline_floors
            .iter()
            .collect::<Result<Vec<_>, Error>>()
            .and_then(|mut floors| {
                floors.push(CommunityTimelineFloorV1 {
                    timeline: operation.timeline(),
                    highest_pass_ordinal: 0,
                    active_generation: Some(operation.generation),
                    closed_generations: CommunityGenerationIdsV1::from_ids(&[]),
                    selected_head: Some(selected_head),
                    closed: false,
                });
                floors.sort_by_key(|row| row.timeline.inner().to_bytes());
                CommunitySelectionV1::new(CommunitySelectionInputV1 {
                    store_incarnation,
                    installed_catalogue_digest: binding.installed_catalogue_digest,
                    native_profile_digest: binding.native_profile_digest,
                    highest_native_producer_ordinal: ordinal,
                    timeline_floors: CommunityTimelineFloorsV1::from_floors(&floors),
                    metadata_not_after_micros: operation.metadata_horizon(),
                })
                .map(|selection| selection.to_canonical_cbor())
            })
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
