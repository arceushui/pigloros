//! The backend-neutral initialize planner (#560 A3c-2c-2).
//!
//! It mints the host-derived records of one code-0 initialization from the
//! installed composition inputs and the owner's own evaluated decision,
//! under the owner decisions on #560, note 22722 (G2–G4 and "Installed
//! inputs"), in the ADR-129 annex §2 digest order:
//!
//! 1. before any authority call, the caller form and its R6.1(7) P6
//!    initializer-set reference (A5.5 step 1, I31);
//! 2. the R6.3 anchor-T check and anchor-G derivation from the validated
//!    CMA1 and CSI1;
//! 3. COB1 and the host-derived CMB1s of the roster (G2);
//! 4. once the CMB1s are sealed, the CGI1 with its A5.3(0) host-derived
//!    fields, the CSB1 (G4), the CBQ1 (G3) and the CPV1.
//!
//! It reads no domain and commits nothing: every backend's initialize entry
//! uses the same planner, so they mint byte-identical records (R6.5).

use pos_core::community_lifecycle::{
    community_initializer_set_ref_v1, CommunityArtifactOperationV1, CommunityBudgetQuoteV1,
    CommunityContentReferenceV1, CommunityDigestListV1, CommunityDueMemberBudgetV1,
    CommunityDurableProfileV1, CommunityInitializationRequestInputV1,
    CommunityInitializationRequestV1, CommunityInitializationSourceV1, CommunityInputIndexV1,
    CommunityLifecycleErrorV1 as Error, CommunityMemberBindingInputV1, CommunityMemberBindingV1,
    CommunityMetadataAnchorV1, CommunityNativeNodeInputV1, CommunityNativeNodeKindV1,
    CommunityNativeNodeV1, CommunityOriginalProvenanceInputV1, CommunityOriginalProvenanceV1,
    CommunityOwnerBindingInputV1, CommunityOwnerBindingV1, CommunityScopeBindingInputV1,
    CommunityScopeBindingV1, CommunityScopeCoverageRowV1, CommunityScopeCoverageRowsV1,
    CommunityScopeMembersV1, CommunitySelectionV1, CommunityTypedInputRefV1,
    CommunityTypedInputRefsV1, COMMUNITY_SHARED_RECORD_LIMITS_V1,
};
use pos_core::RecordedDependencyClassV1;
use pos_core::{AuthorityTrustRootSealV1, Hash, TimelineId};
use zeroize::Zeroizing;

use super::lifecycle_authority::{
    CommunityAdministrativeActionV1, CommunityAdministrativeOperationV1,
    CommunityAdministrativeRequestV1, CommunityAuthorityAdmissionV1,
};
use super::native_graph::member_binding_ref;
use super::private_hash::scope_set_digest;

/// The fixed CIS1 encoding maximum, a CBQ1 byte term.
const CIS1_BYTES: u64 = 1024;

/// The fixed CSR1 encoding maximum, a CBQ1 byte term.
const CSR1_BYTES: u64 = 512;

/// Preferred CBOR encoding of the empty scope-member array: the
/// initializer's proven empty scope (R6.1(6)).
const EMPTY_SCOPE_ROWS: [u8; 1] = [0x80];

/// Installed composition inputs of the planner (note 22722, "Installed
/// inputs"). None of them comes from a caller.
#[derive(Clone, Copy)]
pub struct CommunityInitializationInstallationV1<'a> {
    /// The protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// The installed CDP1.
    pub profile: &'a CommunityDurableProfileV1<'a>,
    /// The qualified native profile identity.
    pub native_profile_digest: Hash,
    /// The installed owner catalogue, which COB1 binds.
    pub installed_owner_catalogue_digest: Hash,
    /// The host installation identity, which COB1 binds.
    pub installation_id: [u8; 16],
    /// Each roster row's CNT1 effective State limit in bytes, in roster
    /// order: the CSC1 term of the CBQ1 byte maximum. The composition root
    /// takes it from the row's actual CNT1, and the initialize entry
    /// (2c-3, pos-runtime) checks it against the row's CNT1 digest; this
    /// planner cannot see a CNT1.
    pub state_limit_bytes: &'a [u64],
}

/// The caller form of a code-0 `initialize` (A5.3(0)): the CGI1 fields
/// without its host-derived G, refs and horizon, and with a null prior.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityInitializeFormV1 {
    /// CGI1 target Timeline.
    pub timeline: TimelineId,
    /// CGI1 `operation_id`, stable across retries.
    pub operation_id: [u8; 16],
    /// CGI1 `initial_source`; it must be the R6.1(7) initializer set.
    pub initial_source: CommunityInitializationSourceV1,
}

/// One planned code-0 initialization.
pub struct CommunityInitializationPlannerV1<'a> {
    installation: CommunityInitializationInstallationV1<'a>,
    form: CommunityInitializeFormV1,
    request: CommunityAdministrativeRequestV1,
}

/// COB1 and the roster's host-derived CMB1s for one generation (G2).
pub struct CommunityInitializationBindingsV1 {
    owner_binding: Zeroizing<Vec<u8>>,
    owner_binding_digest: Hash,
    members: Vec<(Zeroizing<Vec<u8>>, Hash)>,
}

impl CommunityInitializationBindingsV1 {
    /// The canonical COB1.
    #[must_use]
    pub fn owner_binding(&self) -> &[u8] {
        &self.owner_binding
    }

    /// The ADR-128 `OwnerBinding` commitment of the COB1.
    #[must_use]
    pub const fn owner_binding_digest(&self) -> Hash {
        self.owner_binding_digest
    }

    /// Each member's canonical CMB1, in roster order.
    #[must_use]
    pub fn member_bindings(&self) -> impl ExactSizeIterator<Item = &[u8]> + '_ {
        self.members.iter().map(|(bytes, _)| bytes.as_slice())
    }

    /// Each member's CMB1 digest, in roster order.
    #[must_use]
    pub fn member_binding_digests(&self) -> impl ExactSizeIterator<Item = Hash> + '_ {
        self.members.iter().map(|(_, digest)| *digest)
    }
}

/// The CGI1, CSB1, CBQ1 and CPV1 of one planned initialization.
pub struct CommunityInitializationRecordsV1 {
    request: Zeroizing<Vec<u8>>,
    request_digest: Hash,
    scope_binding: Zeroizing<Vec<u8>>,
    scope_binding_digest: Hash,
    budget_quote: Zeroizing<Vec<u8>>,
    budget_quote_digest: Hash,
    provenance: Zeroizing<Vec<u8>>,
    provenance_digest: Hash,
}

impl CommunityInitializationRecordsV1 {
    /// The canonical CGI1.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// `H(CGI1)`, the CSB1/CPV1/CAU1 `input_identity`.
    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.request_digest
    }

    /// The canonical CSB1.
    #[must_use]
    pub fn scope_binding(&self) -> &[u8] {
        &self.scope_binding
    }

    /// The ADR-128 `ScopeCover` commitment of the CSB1.
    #[must_use]
    pub const fn scope_binding_digest(&self) -> Hash {
        self.scope_binding_digest
    }

    /// The canonical CBQ1.
    #[must_use]
    pub fn budget_quote(&self) -> &[u8] {
        &self.budget_quote
    }

    /// `H(CBQ1)`, the CPV1 `budget_identity`.
    #[must_use]
    pub const fn budget_quote_digest(&self) -> Hash {
        self.budget_quote_digest
    }

    /// The canonical CPV1.
    #[must_use]
    pub fn provenance(&self) -> &[u8] {
        &self.provenance
    }

    /// The ADR-128 `OwnerProvenance` commitment of the CPV1.
    #[must_use]
    pub const fn provenance_digest(&self) -> Hash {
        self.provenance_digest
    }
}

impl<'a> CommunityInitializationPlannerV1<'a> {
    /// Accept a code-0 caller form (A5.5 step 1), before any authority call.
    ///
    /// Only the trusted composition root, which holds the
    /// [`AuthorityTrustRootSealV1`], plans an initialization:
    ///
    /// ```compile_fail,E0061
    /// use pos_store::community::{
    ///     CommunityInitializationInstallationV1, CommunityInitializationPlannerV1,
    ///     CommunityInitializeFormV1,
    /// };
    /// fn forge(
    ///     installation: CommunityInitializationInstallationV1<'_>,
    ///     form: CommunityInitializeFormV1,
    /// ) {
    ///     let _ = CommunityInitializationPlannerV1::new(installation, form);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero Timeline or operation identity, a
    /// source other than an initializer set, an initializer-set reference
    /// that differs from the R6.1(7) derivation over the installed roster
    /// (P6, I31), and a State-limit count other than the roster's.
    pub fn new(
        _seal: &'static AuthorityTrustRootSealV1,
        installation: CommunityInitializationInstallationV1<'a>,
        form: CommunityInitializeFormV1,
    ) -> Result<Self, Error> {
        CommunityAdministrativeRequestV1::derive(&CommunityAdministrativeOperationV1::Initialize {
            timeline: form.timeline,
            operation_id: form.operation_id,
            initial_source: form.initial_source,
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        })
        .and_then(|request| {
            if form.initial_source
                == CommunityInitializationSourceV1::Initializer(community_initializer_set_ref_v1(
                    installation.profile,
                ))
                && installation.state_limit_bytes.len()
                    == installation.profile.as_input().roster.len()
            {
                Ok(Self {
                    installation,
                    form,
                    request,
                })
            } else {
                Err(Error::InvalidBinding)
            }
        })
    }

    /// The derived administrative request the call authenticates for.
    #[must_use]
    pub const fn request(&self) -> CommunityAdministrativeRequestV1 {
        self.request
    }

    /// The R6.3 anchor-T check and anchor-G derivation.
    ///
    /// `anchor` and `selection` are the domain's validated CMA1 and current
    /// CSI1. A code-0 initialize is admissible only on `anchor_T` (D7). Its
    /// G is `anchor_G` while CSI1 has no `anchor_T` row. The caller has
    /// already looked up a retry by `(anchor_T, operation_id)` before
    /// allocating (R6.3(4)).
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when the caller's Timeline is not
    /// `anchor_T`, or the anchor or selection belongs to another store
    /// incarnation; and `StaleGeneration` (an A5.5 step-4 result) once a
    /// committed CGI1 has consumed `anchor_G` (D8; owner decision on #560,
    /// 2026-11-19).
    pub fn generation(
        &self,
        anchor: &CommunityMetadataAnchorV1,
        selection: &CommunitySelectionV1<'_>,
    ) -> Result<[u8; 16], Error> {
        let anchor = anchor.as_input();
        let selection = selection.as_input();
        let incarnation = self.installation.store_incarnation;
        if anchor.store_incarnation != incarnation
            || selection.store_incarnation != incarnation
            || anchor.anchor_timeline != self.form.timeline
        {
            return Err(Error::EvidenceUnavailable);
        }
        selection
            .timeline_floors
            .iter()
            .try_fold(false, |seen, row| {
                row.map(|row| seen || row.timeline == anchor.anchor_timeline)
            })
            .and_then(|seen| {
                if seen {
                    Err(Error::StaleGeneration)
                } else {
                    Ok(anchor.anchor_generation)
                }
            })
    }

    /// COB1 and the roster's host-derived CMB1s for `generation` (G2).
    ///
    /// COB1 binds the installed inputs, the CDP1 and its authority
    /// catalogue; every CMB1 is its roster row plus that COB1. Every horizon
    /// is the CDP1 `generation_not_after`.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero generation or installed input.
    pub fn bindings(
        &self,
        generation: [u8; 16],
    ) -> Result<CommunityInitializationBindingsV1, Error> {
        let installation = self.installation;
        let profile = installation.profile.as_input();
        CommunityOwnerBindingV1::new(CommunityOwnerBindingInputV1 {
            store_incarnation: installation.store_incarnation,
            timeline: self.form.timeline,
            generation,
            native_profile_digest: installation.native_profile_digest,
            installed_owner_catalogue_digest: installation.installed_owner_catalogue_digest,
            authority_catalogue_digest: profile.authority_catalogue_digest,
            durable_profile_digest: installation.profile.digest(),
            installation_id: installation.installation_id,
            evidence_not_after_micros: profile.retention.generation_not_after_micros,
        })
        .and_then(|owner| {
            let owner_binding_digest = owner.digest();
            profile
                .roster
                .iter()
                .map(|row| {
                    let [pmf1_digest, state_schema_digest, negotiated_tuple_digest] = row.digests();
                    CommunityMemberBindingV1::new(CommunityMemberBindingInputV1 {
                        stable_entry: row.stable_entry(),
                        implementation: row.implementation(),
                        pmf1_digest,
                        state_schema_digest,
                        negotiated_tuple_digest,
                        initial_state_content_digest: Hash::from_bytes(row.initializer().digest),
                        protected_owner_binding_digest: owner_binding_digest,
                    })
                    .map(|member| (member.to_canonical_cbor(), member.digest()))
                })
                .collect::<Result<Vec<_>, Error>>()
                .map(|members| CommunityInitializationBindingsV1 {
                    owner_binding: owner.to_canonical_cbor(),
                    owner_binding_digest,
                    members,
                })
        })
    }

    /// The CGI1, CSB1, CBQ1 and CPV1 of `generation`, once each member's
    /// CMB1 is sealed at `envelope_addresses` (one per roster slot).
    ///
    /// The CGI1 takes its `principal_ref` and `authorization_ref` from
    /// `admission`, the owner's own `Active` decision for this exact
    /// administrative request (A5.3(2)), and its horizon from the CDP1. The
    /// CSB1 (G4) has one empty-scope coverage row per member's variant-3
    /// CMB1 ref, no scope members and the CDP1 `source_catalogue_digest` as
    /// its policy revision. The CPV1 names the same refs as its sources, the
    /// CDP1 `execution_profile_digest` as its rule bundle and `H(CBQ1)` as
    /// its budget identity (G3). The CBQ1 due rows, the CGI1 member list and
    /// the CPV1 refs are all in roster order.
    ///
    /// Before minting the CGI1, the CBQ1 maxima must fit the CDP1 shared
    /// per-record limits (owner decision on #560, 2026-11-19).
    ///
    /// # Errors
    /// Returns `InvalidBinding` for an admission of another request, an
    /// address count other than the roster's, a zero or repeated address and
    /// every [`Self::bindings`] refusal; and `BoundsExceeded` for a quote
    /// over the shared limits.
    pub fn records(
        &self,
        generation: [u8; 16],
        admission: &CommunityAuthorityAdmissionV1,
        envelope_addresses: &[Hash],
    ) -> Result<CommunityInitializationRecordsV1, Error> {
        let decided = admission.request();
        let expected = self.request;
        if decided.resource() != expected.resource()
            || decided.action() != CommunityAdministrativeActionV1::Initialize.as_str()
            || decided.environment_constraints() != [expected.operation_constraint()]
            || envelope_addresses.len() != self.installation.profile.as_input().roster.len()
            || envelope_addresses
                .iter()
                .enumerate()
                .any(|(index, address)| envelope_addresses[..index].contains(address))
        {
            return Err(Error::InvalidBinding);
        }
        self.bindings(generation).and_then(|bindings| {
            let digests: Vec<Hash> = bindings.member_binding_digests().collect();
            let refs: Vec<CommunityTypedInputRefV1<'_>> = digests
                .iter()
                .zip(envelope_addresses)
                .zip(0_u16..)
                .map(|((digest, address), slot)| {
                    member_binding_ref(
                        self.form.timeline,
                        generation,
                        self.form.operation_id,
                        slot,
                        *address,
                        *digest,
                    )
                })
                .collect();
            self.quote(generation, &digests, &refs).and_then(|quote| {
                self.request_record(generation, admission, &digests)
                    .and_then(|request| self.evidence(generation, request, &refs, &quote))
            })
        })
    }

    /// The CBQ1 initialization quote, in roster order, within the CDP1
    /// shared per-record limits (G3).
    ///
    /// Its byte maximum sums, per member, the installed CNT1 State limit for
    /// the CSC1, the fixed CIS1 and CSR1 maxima, and the actual sizes of the
    /// member's two one-input CPN1s (owner decision on #560, 2026-11-19).
    fn quote(
        &self,
        generation: [u8; 16],
        digests: &[Hash],
        refs: &[CommunityTypedInputRefV1<'_>],
    ) -> Result<CommunityBudgetQuoteV1, Error> {
        let profile = self.installation.profile;
        let due = digests
            .iter()
            .zip(profile.as_input().roster)
            .map(|(digest, row)| CommunityDueMemberBudgetV1 {
                member_binding_digest: *digest,
                negotiated_tuple_digest: row.digests()[2],
            })
            .collect();
        refs.iter()
            .zip(self.installation.state_limit_bytes)
            .zip(0_u32..)
            .try_fold(0_u64, |total, ((reference, limit), slot)| {
                self.node_bytes(generation, slot, *reference).map(|nodes| {
                    total
                        .saturating_add(*limit)
                        .saturating_add(CIS1_BYTES + CSR1_BYTES)
                        .saturating_add(nodes)
                })
            })
            .and_then(|bytes| {
                CommunityBudgetQuoteV1::initialization(
                    self.form.timeline,
                    generation,
                    profile.digest(),
                    due,
                    bytes,
                )
            })
            .and_then(|quote| {
                quote
                    .require_within(COMMUNITY_SHARED_RECORD_LIMITS_V1)
                    .map(|()| quote)
            })
    }

    /// The encoded size of slot `slot`'s `InitialState` CPN1 (input: its CMB1
    /// ref) plus its `StateRevision` CPN1 (input: that node).
    ///
    /// The commit allocates the producer ordinal later, so both are encoded
    /// with the largest one; every digest is fixed-width, so the stand-in
    /// digests do not change the size.
    fn node_bytes(
        &self,
        generation: [u8; 16],
        slot: u32,
        member: CommunityTypedInputRefV1<'_>,
    ) -> Result<u64, Error> {
        let stand_in = Hash::from_bytes([1; 32]);
        let node = |node_ordinal: u32,
                    kind: CommunityNativeNodeKindV1,
                    magic: [u8; 4],
                    input: CommunityTypedInputRefV1<'_>| {
            let inputs = [input];
            CommunityNativeNodeV1::new(CommunityNativeNodeInputV1 {
                store_incarnation: self.installation.store_incarnation,
                timeline: self.form.timeline,
                generation,
                producer_ordinal: u64::MAX,
                node_ordinal,
                kind,
                content: CommunityContentReferenceV1 {
                    record_magic: magic,
                    logical_digest: stand_in,
                },
                dependency_class: RecordedDependencyClassV1::EndogenousRecomputed,
                input_index: CommunityInputIndexV1::Direct(
                    CommunityTypedInputRefsV1::from_references(&inputs),
                ),
                scope_binding_digest: stand_in,
                authorization_digest: stand_in,
                provenance_digest: stand_in,
                evidence_not_after_micros: self
                    .installation
                    .profile
                    .as_input()
                    .retention
                    .generation_not_after_micros,
            })
            .map(|node| (node.to_canonical_cbor().len() as u64, node.reference()))
        };
        node(
            2 * slot,
            CommunityNativeNodeKindV1::InitialState,
            *b"CIS1",
            member,
        )
        .and_then(|(initial, reference)| {
            node(
                2 * slot + 1,
                CommunityNativeNodeKindV1::StateRevision,
                *b"CSR1",
                CommunityTypedInputRefV1::Native(reference),
            )
            .map(|(revision, _)| initial + revision)
        })
    }

    /// The code-0 CGI1 with its host-derived fields (A5.3(0)).
    fn request_record(
        &self,
        generation: [u8; 16],
        admission: &CommunityAuthorityAdmissionV1,
        digests: &[Hash],
    ) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
        let profile = self.installation.profile;
        CommunityInitializationRequestV1::new(CommunityInitializationRequestInputV1 {
            operation_id: self.form.operation_id,
            timeline: self.form.timeline,
            generation,
            expected_prior_generation: None,
            expected_prior_head_digest: None,
            profile_digest: profile.digest(),
            member_binding_digests: CommunityDigestListV1::from_digests(digests),
            initial_source: self.form.initial_source,
            principal_ref: admission.principal_ref(),
            authorization_ref: admission.authorization_ref(),
            evidence_not_after_micros: profile.as_input().retention.generation_not_after_micros,
        })
        .map(|request| (request.to_canonical_cbor(), request.digest()))
    }

    /// The CSB1 and CPV1 over the members' CMB1 refs, with the CBQ1.
    fn evidence(
        &self,
        generation: [u8; 16],
        (request, request_digest): (Zeroizing<Vec<u8>>, Hash),
        refs: &[CommunityTypedInputRefV1<'_>],
        quote: &CommunityBudgetQuoteV1,
    ) -> Result<CommunityInitializationRecordsV1, Error> {
        let installation = self.installation;
        let profile = installation.profile.as_input();
        let timeline = self.form.timeline;
        let operation = CommunityArtifactOperationV1::Initialization(self.form.operation_id);
        let horizon = profile.retention.generation_not_after_micros;
        let empty_scope = scope_set_digest(&EMPTY_SCOPE_ROWS);
        let mut coverage: Vec<CommunityScopeCoverageRowV1> = refs
            .iter()
            .map(|reference| CommunityScopeCoverageRowV1 {
                typed_input_ref_digest: reference.digest(),
                scope_set_digest: empty_scope,
            })
            .collect();
        coverage.sort_by_key(|row| row.typed_input_ref_digest);
        let budget_quote_digest = quote.digest();
        CommunityScopeBindingV1::new(CommunityScopeBindingInputV1 {
            store_incarnation: installation.store_incarnation,
            timeline,
            generation,
            operation,
            input_identity: request_digest,
            coverage_rows: CommunityScopeCoverageRowsV1::from_rows(&coverage),
            scope_members: CommunityScopeMembersV1::from_members(&[]),
            policy_revision: profile.source_catalogue_digest,
            evidence_not_after_micros: horizon,
        })
        .and_then(|scope| {
            let scope_binding_digest = scope.digest();
            CommunityOriginalProvenanceV1::new(CommunityOriginalProvenanceInputV1 {
                store_incarnation: installation.store_incarnation,
                timeline,
                generation,
                operation,
                input_identity: request_digest,
                scope_binding_digest,
                source_root_refs: CommunityTypedInputRefsV1::from_references(refs),
                rule_bundle_digest: profile.execution_profile_digest,
                budget_identity: budget_quote_digest,
                evidence_not_after_micros: horizon,
            })
            .map(|provenance| CommunityInitializationRecordsV1 {
                request,
                request_digest,
                scope_binding: scope.to_canonical_cbor(),
                scope_binding_digest,
                budget_quote: quote.to_canonical_cbor(),
                budget_quote_digest,
                provenance_digest: provenance.digest(),
                provenance: provenance.to_canonical_cbor(),
            })
        })
    }
}
