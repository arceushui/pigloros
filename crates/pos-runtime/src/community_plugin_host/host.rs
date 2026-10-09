//! The host pass seam (ADR-061 revision 7 decision 10).
//!
//! [`CommunityPluginHostV1`] owns the members of the host and sequences one pass: one trusted
//! UTC second, the gate of every member, the offer of each authorization to its slot, the
//! registry's anchored stage call, admission, classification, and the close of the pass. It is
//! generic over [`CommunityPluginMemberV1`], which `pos-plugin-supervisor` implements. The pass
//! never writes registry trust state; only [`CommunityPluginHostV1::refresh_policy()`] does.

use pos_core::{
    trusted_clock::TrustedWallSourceV1, Event, PipelineAdmissionPortV1, PipelineCommitReceiptV1,
    PluginId, Seq, TimelineId, TimelineMeta,
};
use pos_crypto::plugin_trust::verify_plugin_trust_v1;
use pos_plugin_release::{BundleAddressV1, ReleaseSourceV1};
use pos_store::plugin_trust_registry::{
    PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1, PolicyAdvanceOutcomeV1,
    TrustedUtcSecondV1,
};

use super::error::{CommunityPluginHostErrorV1, TrustDenialBasisV1};
use super::failure::{classify_pass_failure, PassFailureV1};
use super::gate::{
    gate_community_release_v1, slices, CommunityPassAuthorizationV1, CommunityPassV1,
    CommunityPluginExpectationV1, CommunityPluginTrustMaterialV1, PluginTrustMaterialSourceV1,
};
use crate::{PluginRegistry, RuntimeError, ScheduledPassAdmissionV1};

mod outcome;

pub use outcome::{CommunityPassOutcomeV1, GateSummaryV1, MemberPassV1, PassResultV1};

/// `ArtifactTrustDenied{TrustStateUnavailable}`, the refusal of every member when the pass has
/// no trusted second.
const TRUST_STATE_UNAVAILABLE: CommunityPluginHostErrorV1 =
    CommunityPluginHostErrorV1::ArtifactTrustDenied {
        basis: TrustDenialBasisV1::TrustStateUnavailable,
    };

/// One member of the host: a community Plugin whose Driver is registered and whose release the
/// composition can re-read (ADR-061 revision 7 decision 10).
///
/// `pos-plugin-supervisor` implements it for `CommunityMemberV1`, which wraps the Driver's
/// handle. The slot methods are those of the handle; the host reads `pass_failure()` and
/// `pass_invocation_id()` into the member's entry before it closes the pass.
pub trait CommunityPluginMemberV1 {
    /// The member's Plugin.
    fn plugin(&self) -> PluginId;

    /// What the composition expects at the member's address: the PMF1 Plugin ID text and, when
    /// a Driver was built, the `(complete-PMF1 digest, release digest)` pair it was built for.
    fn expectation(&self) -> &CommunityPluginExpectationV1;

    /// The source of the release closure.
    fn release_source(&self) -> &dyn ReleaseSourceV1;

    /// The address of the active release's closure in [`Self::release_source()`].
    fn release_address(&self) -> &BundleAddressV1;

    /// The source of the operator-pinned anchors and signed records.
    fn trust_material(&self) -> &dyn PluginTrustMaterialSourceV1;

    /// Offer this pass's authorization to the member's slot.
    ///
    /// # Errors
    /// Returns `InvalidInvocation` when the slot is occupied.
    fn offer_authorization(
        &self,
        authorization: CommunityPassAuthorizationV1,
    ) -> Result<(), CommunityPluginHostErrorV1>;

    /// Record a failure the host raised for the member outside its `step`.
    fn record_refusal(&self, error: CommunityPluginHostErrorV1);

    /// End the pass for the member: drop an unconsumed authorization.
    fn close_pass(&self);

    /// The failure this pass produced for the member.
    fn pass_failure(&self) -> Option<CommunityPluginHostErrorV1>;

    /// The invocation ID the member's Driver built in this pass.
    fn pass_invocation_id(&self) -> Option<[u8; 16]>;

    /// Mirror the member's availability into the registry.
    ///
    /// # Errors
    /// Returns the registry's composition error for an unregistered or unpinned Plugin.
    fn sync_registry(&self, registry: &mut PluginRegistry) -> Result<(), RuntimeError>;
}

/// Which anchored stage call of the registry a pass uses.
#[derive(Debug)]
pub enum CommunityStageV1<'a> {
    /// `step_all_anchored`.
    Anchored,
    /// `step_all_anchored_with_events`, with the host-filtered committed prefix.
    WithEvents(&'a [Event]),
}

/// What the registry's stage and admit calls take, and the Tick of the pass.
pub struct CommunityPassRequestV1<'a> {
    /// The Tick of the pass, from the owner of the Tick Boundary.
    pub tick: u64,
    /// The Timeline to step.
    pub timeline: TimelineId,
    /// The Timeline's Fork ancestry from `pos_core::fork_ancestry()`.
    pub ancestry: &'a [TimelineMeta],
    /// The observation anchor of the pass.
    pub observed_through: Seq,
    /// Which anchored stage call to use.
    pub stage: CommunityStageV1<'a>,
    /// The host-owned inputs that bind the staged pass to its admission basis.
    pub admission: ScheduledPassAdmissionV1,
    /// The admission port the batch commits through.
    pub port: &'a mut dyn PipelineAdmissionPortV1,
}

/// The verdict on one member: the gate's summary, or the error that refused it.
type MemberVerdict = Result<GateSummaryV1, CommunityPluginHostErrorV1>;

/// A member's summary and its one-shot authorization.
type Cleared = (GateSummaryV1, CommunityPassAuthorizationV1);

/// The result of gating one member.
type GateAttempt = Result<Cleared, CommunityPluginHostErrorV1>;

/// Closes the pass on every exit, including a panic that unwinds out of a member.
///
/// The members' own state ignores mutex poison, so closing during unwinding is safe. The guard
/// holds no `&mut PluginRegistry`, so the registry sync does not run on unwind.
struct PassGuard<'a, M: CommunityPluginMemberV1> {
    members: &'a [M],
    pass: Option<CommunityPassV1>,
}

impl<'a, M: CommunityPluginMemberV1> PassGuard<'a, M> {
    fn open(members: &'a [M], utc: Option<TrustedUtcSecondV1>, tick: u64) -> Self {
        Self {
            members,
            pass: utc.map(|utc| CommunityPassV1::open(utc, tick)),
        }
    }

    const fn pass(&self) -> Option<&CommunityPassV1> {
        self.pass.as_ref()
    }
}

impl<M: CommunityPluginMemberV1> Drop for PassGuard<'_, M> {
    fn drop(&mut self) {
        self.members.iter().for_each(M::close_pass);
        if let Some(pass) = &self.pass {
            pass.close();
        }
    }
}

/// The members of one host and the pass sequence over them.
pub struct CommunityPluginHostV1<M> {
    members: Vec<M>,
}

impl<M: CommunityPluginMemberV1> CommunityPluginHostV1<M> {
    /// A host over `members`, in host schedule order.
    #[must_use]
    pub const fn new(members: Vec<M>) -> Self {
        Self { members }
    }

    /// Run one pass: sample, gate, stage, admit, classify, close and sync.
    ///
    /// One trusted UTC second is sampled for the whole pass. A failed sample refuses every
    /// member; a gate refusal or a failed offer refuses the whole pass before anything is
    /// staged. The pass is closed on every exit, a panic that unwinds out of a member included;
    /// the registry is synced with every member after each pass that returns.
    pub fn run_pass(
        &mut self,
        registry: &mut PluginRegistry,
        trust: &impl PluginTrustPolicyRegistryV1,
        wall: &mut impl TrustedWallSourceV1,
        request: CommunityPassRequestV1<'_>,
    ) -> CommunityPassOutcomeV1 {
        let tick = request.tick;
        let utc = TrustedUtcSecondV1::from_source(wall).ok();
        let guard = PassGuard::open(&self.members, utc, tick);
        let (verdicts, result) = guard.pass().map_or_else(
            || (refuse_all(&self.members), PassResultV1::Refused),
            |pass| self.run_open(registry, trust, pass, request),
        );
        let mut entries = report(&self.members, verdicts);
        drop(guard);
        sync_all(&self.members, registry, &mut entries);
        CommunityPassOutcomeV1 {
            tick,
            utc: utc.map(TrustedUtcSecondV1::as_i64),
            gates: entries,
            result,
        }
    }

    /// Adopt newer policy: close the pass of every member, then record `material` through the
    /// registry's `advance_policy` at a fresh trusted UTC second and `tick`.
    ///
    /// An authorization that sits in a member slot is dropped by the close, so it is never
    /// usable after the refresh; one held outside a slot stays usable until its pass is closed
    /// by its creator.
    ///
    /// # Errors
    /// Returns `TrustedTimeUnavailable` when the clock fails, `Trust(..)` when the PTR1 or PRV1
    /// records do not verify, and otherwise the registry's own error.
    pub fn refresh_policy(
        &mut self,
        trust: &mut impl PluginTrustPolicyRegistryV1,
        material: &CommunityPluginTrustMaterialV1,
        wall: &mut impl TrustedWallSourceV1,
        tick: u64,
    ) -> Result<PolicyAdvanceOutcomeV1, PluginTrustPolicyRegistryErrorV1> {
        self.members.iter().for_each(M::close_pass);
        TrustedUtcSecondV1::from_source(wall).and_then(|utc| advance(trust, material, utc, tick))
    }

    /// Steps 2 to 5 of a pass whose sample succeeded.
    fn run_open(
        &self,
        registry: &mut PluginRegistry,
        trust: &impl PluginTrustPolicyRegistryV1,
        pass: &CommunityPassV1,
        request: CommunityPassRequestV1<'_>,
    ) -> (Vec<MemberVerdict>, PassResultV1) {
        let cleared = match self.gate_all(trust, pass) {
            Ok(cleared) => cleared,
            Err(verdicts) => return (verdicts, PassResultV1::Refused),
        };
        let verdicts = offer_all(&self.members, cleared);
        let result = if verdicts.iter().all(Result::is_ok) {
            settle(stage_and_admit(registry, request))
        } else {
            PassResultV1::Refused
        };
        (verdicts, result)
    }

    /// Gate every member, in host schedule order. When any is refused, every refused member's
    /// refusal is recorded and the verdicts of all members are returned as the error.
    fn gate_all(
        &self,
        trust: &impl PluginTrustPolicyRegistryV1,
        pass: &CommunityPassV1,
    ) -> Result<Vec<Cleared>, Vec<MemberVerdict>> {
        let roster = &self.members;
        let attempts: Vec<GateAttempt> = roster
            .iter()
            .map(|member| gate_member(trust, member, pass))
            .collect();
        if attempts.iter().all(Result::is_ok) {
            return Ok(attempts.into_iter().flatten().collect());
        }
        let verdicts = roster
            .iter()
            .zip(attempts)
            .map(|(member, attempt)| refuse(member, attempt))
            .collect();
        Err(verdicts)
    }
}

/// Verify the PTR1 and PRV1 records of `material` at `utc` and `tick`, then record the policy.
fn advance(
    trust: &mut impl PluginTrustPolicyRegistryV1,
    material: &CommunityPluginTrustMaterialV1,
    utc: TrustedUtcSecondV1,
    tick: u64,
) -> Result<PolicyAdvanceOutcomeV1, PluginTrustPolicyRegistryErrorV1> {
    let verified = verify_plugin_trust_v1(
        material.root_anchor(),
        &slices(material.roots()),
        &slices(material.revocations()),
        utc.as_i64(),
        tick,
    );
    verified
        .map_err(PluginTrustPolicyRegistryErrorV1::Trust)
        .and_then(|evidence| {
            trust.advance_policy(
                material.policy_anchor(),
                material.tps1_bytes(),
                &evidence,
                utc,
                tick,
            )
        })
}

/// Gate one member against the registry with its own source, address and material.
fn gate_member<M: CommunityPluginMemberV1>(
    trust: &impl PluginTrustPolicyRegistryV1,
    member: &M,
    pass: &CommunityPassV1,
) -> GateAttempt {
    let attempt = gate_community_release_v1(
        trust,
        member.expectation(),
        member.release_source(),
        member.release_address(),
        member.trust_material(),
        pass,
    );
    attempt.map(|(gated, authorization)| (GateSummaryV1::of(&gated), authorization))
}

/// The verdict of a gated member, recording the refusal of one that was refused. An
/// authorization of a member that passed is dropped: the pass is refused as a whole.
fn refuse<M: CommunityPluginMemberV1>(member: &M, attempt: GateAttempt) -> MemberVerdict {
    note(member, attempt.map(|(summary, _authorization)| summary))
}

/// `verdict`, after recording the refusal it carries, if any, for `member`.
fn note<M: CommunityPluginMemberV1>(member: &M, verdict: MemberVerdict) -> MemberVerdict {
    if let Err(error) = &verdict {
        member.record_refusal(*error);
    }
    verdict
}

/// Refuse every member for want of a trusted second.
fn refuse_all<M: CommunityPluginMemberV1>(roster: &[M]) -> Vec<MemberVerdict> {
    roster
        .iter()
        .map(|member| {
            member.record_refusal(TRUST_STATE_UNAVAILABLE);
            Err(TRUST_STATE_UNAVAILABLE)
        })
        .collect()
}

/// Offer each authorization to its member's slot, in order. The first member whose slot is
/// occupied has its refusal recorded and its verdict replaced by the error; later members are
/// not offered.
fn offer_all<M: CommunityPluginMemberV1>(
    roster: &[M],
    cleared: Vec<Cleared>,
) -> Vec<MemberVerdict> {
    let mut refused = false;
    let mut verdicts = Vec::with_capacity(cleared.len());
    for (member, (summary, authorization)) in roster.iter().zip(cleared) {
        let offered = if refused {
            Ok(())
        } else {
            member.offer_authorization(authorization)
        };
        refused = refused || offered.is_err();
        verdicts.push(note(member, offered.map(|()| summary)));
    }
    verdicts
}

/// Stage the pass with the requested anchored call, then admit the whole batch.
fn stage_and_admit(
    registry: &mut PluginRegistry,
    request: CommunityPassRequestV1<'_>,
) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
    let CommunityPassRequestV1 {
        timeline,
        ancestry,
        observed_through,
        stage,
        admission,
        port,
        ..
    } = request;
    let stepped = match stage {
        CommunityStageV1::Anchored => {
            registry.step_all_anchored(timeline, ancestry, observed_through)
        }
        CommunityStageV1::WithEvents(events) => {
            registry.step_all_anchored_with_events(timeline, ancestry, observed_through, events)
        }
    };
    stepped.and_then(|_drafts| registry.admit_scheduled_pass(port, &admission))
}

/// The pass result of an admission outcome: `InDoubt` is reported as such, never as a failure.
fn settle(outcome: Result<Option<PipelineCommitReceiptV1>, RuntimeError>) -> PassResultV1 {
    outcome.map_or_else(failed, committed)
}

/// A committed pass, with its commit receipt when it had any Event.
fn committed(receipt: Option<PipelineCommitReceiptV1>) -> PassResultV1 {
    PassResultV1::Committed(receipt.map(Box::new))
}

/// A failed pass, or an in-doubt one: `InDoubt` is never reported as a failure.
fn failed(error: RuntimeError) -> PassResultV1 {
    match classify_pass_failure(&error) {
        PassFailureV1::InDoubt => PassResultV1::InDoubt,
        PassFailureV1::Host(host) => PassResultV1::Failed {
            host: Some(host),
            error: Box::new(error),
        },
        PassFailureV1::Unrelated => PassResultV1::Failed {
            host: None,
            error: Box::new(error),
        },
    }
}

/// The members' entries, reading what this pass produced before the pass is closed.
fn report<M: CommunityPluginMemberV1>(
    roster: &[M],
    verdicts: Vec<MemberVerdict>,
) -> Vec<MemberPassV1> {
    roster
        .iter()
        .zip(verdicts)
        .map(|(member, verdict)| MemberPassV1 {
            plugin: member.plugin(),
            expected_plugin_id: member.expectation().plugin_id.clone(),
            gate: verdict,
            invocation_id: member.pass_invocation_id(),
            launch_failure: member.pass_failure(),
            sync: Ok(()),
        })
        .collect()
}

/// Mirror every member's availability into the registry and note a failure in its entry.
fn sync_all<M: CommunityPluginMemberV1>(
    roster: &[M],
    registry: &mut PluginRegistry,
    entries: &mut [MemberPassV1],
) {
    for (member, entry) in roster.iter().zip(entries) {
        entry.sync = member.sync_registry(registry);
    }
}
