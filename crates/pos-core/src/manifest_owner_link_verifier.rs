//! ADR-089 Revision 4 installed historical owner-link verifier.
//!
//! A caller presents one exact WCR1 or LCQ1 identity for a Timeline, head and
//! scope. The verifier reads one consistent owner snapshot and proves that
//! WCR1, WCB1, LCQ1, LCC1 and LCS2 select the same cut, that the sealed
//! kind-8 and kind-14 rows select the immutable MCA1/MSR1/MSB1 admission whose
//! committed result is an ancestor of the seal's pre-state, that WCS1 names a
//! producer subset of MSB1 with equal EOP1, that WCB1's complete Required WDB1
//! closure holds every admitted EOP1/OPC1 leaf, zero-output Plugins included,
//! and that the kind-1 static pins match MCA1. Every signature is re-verified
//! through the installed hooks, and the retained WKE1 coordinator key
//! evidence of LCQ1 and every MSR1 is resolved natively against the installed
//! key registry, so a coordinator key rotated or tombstoned after signing
//! still verifies (ADR-065 §2). Only then does it recheck the inventory
//! generation, retention lease, key owner and erasure fences, and release an
//! identity-only capability through the trusted-clock handoff.
//!
//! ADR-081 Revision 2 closures carry unavailable reference leaves, so the
//! capability never grants an Exact claim.

use std::collections::{BTreeMap, BTreeSet};

use crate::local_cut_commit::{LocalCutCommitV1, LocalCutReceiptV1};
use crate::local_cut_owner::{
    local_cut_owner_intent_digest_v1, validate_local_cut_owner_result_v1, LocalCutOwnerCommitV1,
    LocalCutOwnerErrorV1, LocalCutOwnerRequestV1, LocalCutOwnerStateV1, LocalCutOwnerVerifierV1,
    LocalCutRecordingContextRowV1,
};
use crate::local_cut_seal::{LocalCutManifestBindingRowV1, LocalCutSealInputV2, LocalCutSealV2};
use crate::local_cut_world_closure::{
    derive_local_cut_world_closure_v1, validate_local_cut_owner_recordings_v1,
    LocalCutWorldClosureSourceV1, LocalCutWorldRecordingV1,
};
use crate::manifest_owner_admission::{
    opc1_native_digest, validate_manifest_owner_admission_snapshot_v1,
    ManifestOwnerAdmissionSnapshotV1, ManifestOwnerAdmissionVerifierV1,
    ManifestOwnerPolicyCopiesV1,
};
use crate::manifest_owner_members::recorded_lease;
use crate::output_policy::OutputPolicyV1;
use crate::trusted_clock::{
    handoff_checked, sealed, ApplicableExpiriesV1, AuthorizedArtifactUseV1, GuardMonotonicSourceV1,
    HandoffTokenV1, ProtectedHandoffTargetV1, ReleaseGuardV1, StagedProtectedOutputV1,
    TrustedWallSourceV1,
};
use crate::world_dependency_directory::WorldDependencyBranchV1;
use crate::world_key_evidence::{
    resolve_coordinator_key_evidence_v1, CoordinatorKeyEvidenceErrorV1, WorldKeyEvidenceInputV1,
    WorldKeyEvidenceV1,
};
use crate::{
    ArtifactRegistrationV1, ErasureContainmentGateV1, ErasureProtectedOperationV1,
    ErasureReferenceV1, Hash, KeyRegistryPortV1, KeyRoleV1, ManifestAdmissionCatalogRowV1,
    OwnerIdV1, PluginId, TimelineId, WallTime, WorldRecordingReceiptV1,
};

/// Closed public reasons why an owner link was not verified.
///
/// No variant carries private bytes, stable slots or record digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManifestOwnerLinkVerificationErrorV1 {
    /// The owner snapshot, admission row, ancestry or admission signature is
    /// unavailable or does not belong to the sealed cut.
    #[error("manifest owner admission evidence is unavailable")]
    CompositionUnavailable,
    /// A kind-8 or kind-14 row, MSR1, MSB1 or WCS1 differs from the sealed
    /// owner selection.
    #[error("manifest slot binding differs from the sealed owner selection")]
    SlotBindingMismatch,
    /// An EOP1, WCS1 producer or kind-1 static pin differs from MCA1.
    #[error("admitted output policy differs from the owner catalog")]
    PolicyMismatch,
    /// A Required EOP1/OPC1 copy or WDB1 closure node is missing or altered,
    /// or an Exact claim was requested from a structural closure.
    #[error("required output-policy closure is unavailable")]
    ClosureUnavailable,
    /// The identity, Timeline, head, scope or LCQ1 signature does not select
    /// one authenticated visible cut.
    #[error("identity does not select this authenticated cut")]
    WrongCut,
    /// LCC1 does not name the exact LCS2 seal; only LCS2 cuts are verified.
    #[error("local-cut seal version is not supported")]
    UnsupportedSealVersion,
    /// A current consent, lease, erasure, inventory, key or release fence
    /// refused protected use.
    #[error("protected use is denied")]
    ProtectedUseDenied,
}

/// One exact authenticated cut identity presented for a Timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestOwnerLinkCutIdentityV1 {
    /// Exact WCR1 content address of the Timeline's recording.
    WorldRecordingReceipt(Hash),
    /// Exact LCQ1 content address of the cut's signed receipt.
    LocalCutReceipt(Hash),
}

impl ManifestOwnerLinkCutIdentityV1 {
    /// Whether this identity names the cut that one WCR1 records.
    ///
    /// A WCR1 identity matches only that exact receipt. An LCQ1 identity
    /// matches every WCR1 of its cut, so the caller selects the Timeline.
    #[must_use]
    pub fn selects(self, receipt: &WorldRecordingReceiptV1) -> bool {
        match self {
            Self::WorldRecordingReceipt(digest) => receipt.digest() == digest,
            Self::LocalCutReceipt(digest) => {
                receipt.as_input().actual_commit_receipt_digest == digest
            }
        }
    }
}

/// Exact head that the selected WCB1 must record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestOwnerLinkHeadV1 {
    /// Recorded logical head.
    pub logical_head: u64,
    /// Recorded stitched head hash.
    pub stitched_head_hash: Hash,
}

/// One untrusted owner-link verification request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestOwnerLinkRequestV1 {
    /// Actual local owner whose retained evidence is read.
    pub owner: OwnerIdV1,
    /// Exact WCR1 or LCQ1 identity of the requested cut.
    pub identity: ManifestOwnerLinkCutIdentityV1,
    /// Requested owned Timeline.
    pub timeline_id: TimelineId,
    /// Head the selected WCB1 must record.
    pub expected_head: ManifestOwnerLinkHeadV1,
    /// ADR-081 Timeline/RLS1 scope the selected WCB1 must record.
    pub expected_scope: Hash,
}

/// One consistent owner snapshot behind a requested cut.
///
/// A store returns it from one read transaction or one shared borrow. It is
/// untrusted input to [`verify_manifest_owner_link_v1`], never authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerLinkSnapshotV1 {
    /// Current local-cut owner state.
    pub owner_state: LocalCutOwnerStateV1,
    /// Retained request rows of the selected cut: LCS2 and its kind-1,
    /// kind-4, kind-5, kind-8 and kind-14 rows.
    pub request: LocalCutOwnerRequestV1,
    /// Retained LCS2, LCC1, LCQ1 and every WCB1/WCR1 of the selected cut.
    pub result: LocalCutOwnerCommitV1,
    /// Earlier visible cuts of the same configuration generation, newest
    /// first, as gathered by [`collect_manifest_owner_link_ancestors_v1`].
    pub ancestors: Vec<ManifestOwnerLinkAncestorV1>,
    /// Admission snapshot of each kind-14 row found at the sealed generation,
    /// in row order.
    pub admissions: Vec<ManifestOwnerAdmissionSnapshotV1>,
    /// Retained WDB1 nodes reachable from the requested Timeline's WCB1
    /// dependency root, keyed by digest, as gathered by
    /// [`collect_manifest_owner_link_branches_v1`].
    pub dependency_branches: BTreeMap<Hash, WorldDependencyBranchV1>,
    /// Retained exact WKE1 bytes of the LCQ1 and every MSR1 coordinator key
    /// evidence address, keyed by that address, as gathered by
    /// [`collect_manifest_owner_link_key_evidence_v1`].
    pub key_evidence: BTreeMap<Hash, Vec<u8>>,
}

/// One earlier visible cut: its LCS2 seal, LCC1 commit and LCQ1 receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestOwnerLinkAncestorV1 {
    /// Retained LCS2 seal.
    pub seal: LocalCutSealV2,
    /// Retained LCC1 commit record.
    pub commit: LocalCutCommitV1,
    /// Retained LCQ1 receipt.
    pub receipt: LocalCutReceiptV1,
}

impl ManifestOwnerLinkAncestorV1 {
    /// Copy the seal, commit and receipt of one retained cut result.
    #[must_use]
    pub const fn of_result(result: &LocalCutOwnerCommitV1) -> Self {
        Self {
            seal: result.seal,
            commit: result.commit,
            receipt: result.receipt,
        }
    }
}

/// An owner pre-state: the previous visible LCQ1 and the inventory generation.
type PreStateV1 = (Option<Hash>, Hash);

/// The pre-state a seal names.
const fn seal_pre_state(seal: &LocalCutSealInputV2) -> PreStateV1 {
    (
        seal.previous_visible_receipt_hash,
        seal.expected_inventory_generation,
    )
}

/// The pre-state an admission produced: its MSR1 previous LCQ1 and its
/// committed inventory generation.
const fn admitted_pre_state(admission: &ManifestOwnerAdmissionSnapshotV1) -> PreStateV1 {
    let receipt = admission.timeline.receipt.as_input();
    (
        receipt.previous_visible_lcq1_hash,
        admission.resulting_inventory_generation,
    )
}

/// Gather the earlier cuts that the ancestry walk needs, newest first.
///
/// `earlier` yields the owner's visible cuts before `seal`, newest first, and
/// is read lazily. Gathering stops before reading another cut once the
/// pre-state reaches the requested Timeline's `admission`, and it stops
/// without keeping the cut at the first cut of another configuration
/// generation or the first cut that is not exactly the pre-state. A
/// consistent history therefore reads only the cuts since the admission, and
/// an admission that is never reached reads no further than its generation.
/// Both stores share this walk.
///
/// # Errors
/// Returns the first error that `earlier` yields while it is read.
pub fn collect_manifest_owner_link_ancestors_v1<E>(
    seal: &LocalCutSealInputV2,
    admission: &ManifestOwnerAdmissionSnapshotV1,
    earlier: impl IntoIterator<Item = Result<ManifestOwnerLinkAncestorV1, E>>,
) -> Result<Vec<ManifestOwnerLinkAncestorV1>, E> {
    let admitted = admitted_pre_state(admission);
    let mut earlier = earlier.into_iter();
    let mut pre_state = seal_pre_state(seal);
    let mut ancestors = Vec::new();
    while pre_state != admitted {
        let Some(next) = earlier.next() else {
            break;
        };
        let ancestor = next?;
        let earlier_seal = ancestor.seal.as_input();
        let generation = earlier_seal.configuration_generation;
        if generation != seal.configuration_generation || !precedes(&ancestor, pre_state) {
            break;
        }
        pre_state = seal_pre_state(earlier_seal);
        ancestors.push(ancestor);
    }
    Ok(ancestors)
}

/// Gather the retained WDB1 nodes reachable from one dependency root.
///
/// `node` reads one retained node of the root's scope by digest. A digest
/// that names a WAL1 leaf, a missing node or a node whose content does not
/// hash to its key is left out, so the walk stays within the content-addressed
/// directory; the verifier then requires every derived node.
///
/// A packed directory within the admission's read limits has at most
/// `max_node_visits` branch nodes, since those limits count every leaf and
/// every branch. The walk reads at most that many nodes and then fails.
///
/// # Errors
/// Returns the first error that `node` returns, and `BoundExceeded` when more
/// than `max_node_visits` retained nodes are reachable.
pub fn collect_manifest_owner_link_branches_v1(
    root: Hash,
    max_node_visits: u64,
    mut node: impl FnMut(Hash) -> Result<Option<WorldDependencyBranchV1>, LocalCutOwnerErrorV1>,
) -> Result<BTreeMap<Hash, WorldDependencyBranchV1>, LocalCutOwnerErrorV1> {
    let mut nodes = BTreeMap::new();
    let mut pending = vec![root];
    let mut visits = 0_u64;
    while let Some(digest) = pending.pop() {
        let found = node(digest)?.filter(|branch| branch.digest() == digest);
        if let Some(branch) = found {
            visits += 1;
            if visits > max_node_visits {
                return Err(LocalCutOwnerErrorV1::BoundExceeded);
            }
            pending.extend(branch.children().iter().map(|child| child.node_hash()));
            nodes.insert(digest, branch);
        }
    }
    Ok(nodes)
}

/// Gather the retained WKE1 bytes that one cut's receipts name.
///
/// `evidence` reads one retained `world_key_evidence` row by its address. The
/// LCQ1 address and each admission's MSR1 address are read once each; an
/// address without a retained row is left out, so the verifier rejects it.
///
/// # Errors
/// Returns the first error that `evidence` returns.
pub fn collect_manifest_owner_link_key_evidence_v1(
    receipt: &LocalCutReceiptV1,
    admissions: &[ManifestOwnerAdmissionSnapshotV1],
    mut evidence: impl FnMut(Hash) -> Result<Option<Vec<u8>>, LocalCutOwnerErrorV1>,
) -> Result<BTreeMap<Hash, Vec<u8>>, LocalCutOwnerErrorV1> {
    let addresses: BTreeSet<Hash> = coordinator_evidence_hashes(receipt, admissions).collect();
    let mut retained = BTreeMap::new();
    for evidence_hash in addresses {
        if let Some(bytes) = evidence(evidence_hash)? {
            retained.insert(evidence_hash, bytes);
        }
    }
    Ok(retained)
}

/// The LCQ1 coordinator key-evidence address, then each MSR1's, in row order.
fn coordinator_evidence_hashes<'s>(
    receipt: &LocalCutReceiptV1,
    admissions: &'s [ManifestOwnerAdmissionSnapshotV1],
) -> impl Iterator<Item = Hash> + use<'s> {
    let lcq1 = receipt.as_input().coordinator_key_evidence_hash;
    let msr1 = admissions
        .iter()
        .map(|admission| admission.timeline.receipt.as_input().coordinator_key_evidence_hash);
    std::iter::once(lcq1).chain(msr1)
}

/// Same-store read port for the installed owner-link verifier.
pub trait ManifestOwnerLinkReadPortV1 {
    /// Read the visible cut that `identity` selects for `timeline_id`.
    ///
    /// The lookup scans the Timeline's retained WCR1 rows in cut order; the
    /// first one that [`ManifestOwnerLinkCutIdentityV1::selects`] chooses
    /// names the cut. Its retained records, earlier cuts of the same
    /// configuration generation, its kind-14 admission snapshots and its
    /// WDB1 nodes are returned from one consistent snapshot.
    ///
    /// # Errors
    /// Returns `CorruptState` for an invalid retained record and
    /// `StorageFailure` when the backend cannot provide a snapshot.
    fn read_manifest_owner_link_snapshot_v1(
        &self,
        owner_id: [u8; 32],
        identity: ManifestOwnerLinkCutIdentityV1,
        timeline_id: TimelineId,
    ) -> Result<Option<ManifestOwnerLinkSnapshotV1>, LocalCutOwnerErrorV1>;
}

/// The released capability with its trusted-clock overrun signal.
pub type ManifestOwnerLinkReleaseV1 = AuthorizedArtifactUseV1<VerifiedManifestOwnerLinkV1>;

/// Installed signature hooks that re-verify LCQ1 and MSR1 key roles.
#[derive(Clone, Copy)]
pub struct ManifestOwnerLinkAuthorityV1<'a> {
    /// Installed coordinator verifier for LCQ1 receipts.
    pub local_cut: &'a dyn LocalCutOwnerVerifierV1,
    /// Installed admission verifier for MSR1 receipts.
    pub admission: &'a dyn ManifestOwnerAdmissionVerifierV1,
}

/// Fresh-use fences supplied by the protected-use caller.
pub struct ManifestOwnerLinkUseFenceV1<'a, 'g> {
    /// Held ADR-078 release guard.
    pub guard: ReleaseGuardV1<'g>,
    /// Lease and consent expiries checked under `guard`.
    pub expiries: &'a ApplicableExpiriesV1,
    /// ADR-060 containment gate whose fence serializes the whole read.
    pub erasure_gate: &'a ErasureContainmentGateV1,
    /// Installed key registry that holds each key dependency's owner.
    pub keys: &'a dyn KeyRegistryPortV1,
    /// Trusted wall source for the final release check.
    pub wall: &'a mut dyn TrustedWallSourceV1,
    /// Monotonic source for the final release check.
    pub mono: &'a mut dyn GuardMonotonicSourceV1,
}

/// Exact content addresses proved by one verified owner link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestOwnerLinkDigestsV1 {
    /// LCS2 seal.
    pub lcs2: Hash,
    /// LCC1 commit record.
    pub lcc1: Hash,
    /// LCQ1 signed receipt.
    pub lcq1: Hash,
    /// The Timeline's WCB1 binding.
    pub wcb1: Hash,
    /// The Timeline's WCR1 recording receipt.
    pub wcr1: Hash,
    /// MCA1 catalog at the sealed configuration generation.
    pub mca1: Hash,
    /// MSR1 admission receipt selected by kind-14.
    pub msr1: Hash,
    /// MSB1 slot binding selected by kind-14.
    pub msb1: Hash,
    /// WCS1 consumer set selected by kind-8 and kind-14.
    pub wcs1: Hash,
}

/// An identity-only, host-issued historical owner-link capability.
///
/// The fields are private, the value is not serializable, and only the
/// installed verifier mints it, through the trusted-clock handoff. It proves
/// historical identity and grants no Exact claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedManifestOwnerLinkV1 {
    owner_id: [u8; 32],
    cut_id: u64,
    timeline_id: TimelineId,
    configuration_generation: u64,
    head: ManifestOwnerLinkHeadV1,
    scope: Hash,
    digests: ManifestOwnerLinkDigestsV1,
    inventory_generation: ErasureReferenceV1,
}

impl VerifiedManifestOwnerLinkV1 {
    /// Return the exact owner identity.
    #[must_use]
    pub const fn owner_id(&self) -> [u8; 32] {
        self.owner_id
    }

    /// Return the verified cut identity.
    #[must_use]
    pub const fn cut_id(&self) -> u64 {
        self.cut_id
    }

    /// Return the verified Timeline.
    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    /// Return the cut's sealed configuration generation.
    #[must_use]
    pub const fn configuration_generation(&self) -> u64 {
        self.configuration_generation
    }

    /// Return the verified WCB1 head.
    #[must_use]
    pub const fn head(&self) -> ManifestOwnerLinkHeadV1 {
        self.head
    }

    /// Return the verified ADR-081 scope.
    #[must_use]
    pub const fn scope(&self) -> Hash {
        self.scope
    }

    /// Return the exact record content addresses of the verified chain.
    #[must_use]
    pub const fn digests(&self) -> ManifestOwnerLinkDigestsV1 {
        self.digests
    }

    /// Return the erasure inventory generation the release was fenced on.
    #[must_use]
    pub const fn inventory_generation(&self) -> ErasureReferenceV1 {
        self.inventory_generation
    }

    /// Require an Exact claim before protected materialization.
    ///
    /// # Errors
    /// Always returns `ClosureUnavailable`: an ADR-081 Revision 2 closure
    /// holds unavailable reference leaves, so no owner link supports Exact.
    pub const fn require_exact_claim(&self) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
        Err(ManifestOwnerLinkVerificationErrorV1::ClosureUnavailable)
    }
}

/// Construct a verified owner link for an explicitly enabled downstream seam
/// test.
///
/// This helper is unavailable from the normal dependency graph. Production
/// code receives [`VerifiedManifestOwnerLinkV1`] only from
/// [`verify_manifest_owner_link_v1`].
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn test_verified_manifest_owner_link(
    request: &ManifestOwnerLinkRequestV1,
    cut_id: u64,
    configuration_generation: u64,
    digests: &ManifestOwnerLinkDigestsV1,
    inventory_generation: ErasureReferenceV1,
) -> VerifiedManifestOwnerLinkV1 {
    VerifiedManifestOwnerLinkV1 {
        owner_id: owner_reference(&request.owner),
        cut_id,
        timeline_id: request.timeline_id,
        configuration_generation,
        head: request.expected_head,
        scope: request.expected_scope,
        digests: *digests,
        inventory_generation,
    }
}

/// Verify one historical owner link and release it under every fresh fence.
///
/// The whole read runs inside the erasure gate's fence for `request`'s
/// Timeline. The verifier requires the gate's installed inventory, reads one
/// owner snapshot, proves the complete cut and admission chain, and
/// re-verifies the LCQ1 and every MSR1 through `authority`. It resolves the
/// retained WKE1 bytes of each receipt's coordinator key evidence against
/// `keys` with [`resolve_coordinator_key_evidence_v1`], so a coordinator key
/// rotated or tombstoned since signing still verifies while its registry row
/// keeps the exact material and public key. It then requires
/// the owner's current inventory generation to equal the gate's, `expiries`
/// to cover the selected scope's RLS1 retention deadline, every key
/// dependency of the scope to name the owner's active live key, and the gate
/// to keep its inventory through the read. The capability is released only
/// through [`handoff_checked`]; on success and on every failure the snapshot
/// is dropped before anything is released. Dropping releases the memory; it
/// does not zeroize it.
///
/// # Errors
/// Returns one closed [`ManifestOwnerLinkVerificationErrorV1`]; an
/// unavailable snapshot is `CompositionUnavailable` and an unknown identity
/// is `WrongCut`. Coordinator key evidence that is not retained, does not
/// decode to the receipt's address or is not the verify-only signing form is
/// `CompositionUnavailable`; evidence that the registry does not hold is
/// `ProtectedUseDenied`.
pub fn verify_manifest_owner_link_v1<S: ManifestOwnerLinkReadPortV1 + ?Sized>(
    store: &S,
    request: &ManifestOwnerLinkRequestV1,
    authority: ManifestOwnerLinkAuthorityV1<'_>,
    fence: ManifestOwnerLinkUseFenceV1<'_, '_>,
) -> Result<ManifestOwnerLinkReleaseV1, ManifestOwnerLinkVerificationErrorV1> {
    let gate = fence.erasure_gate;
    let operation = ErasureProtectedOperationV1::Read;
    let verify = || verify_and_release(store, request, authority, fence);
    let fenced = gate.with_fence_value(request.timeline_id, operation, verify);
    fenced.unwrap_or(Err(
        ManifestOwnerLinkVerificationErrorV1::ProtectedUseDenied,
    ))
}

/// The Timeline's admission and the kind-8 row at the same row position.
type SelectedAdmissionV1<'s> = (
    &'s ManifestOwnerAdmissionSnapshotV1,
    &'s LocalCutRecordingContextRowV1,
);

/// The cut recording and admission that one verified snapshot selects.
struct SelectedLinkV1<'s> {
    recording: &'s LocalCutWorldRecordingV1,
    admission: &'s ManifestOwnerAdmissionSnapshotV1,
}

/// The staged capability; only the trusted-clock handoff can release it.
struct StagedManifestOwnerLinkV1 {
    link: VerifiedManifestOwnerLinkV1,
}

impl sealed::Sealed for StagedManifestOwnerLinkV1 {}

impl ProtectedHandoffTargetV1 for StagedManifestOwnerLinkV1 {
    type Committed = VerifiedManifestOwnerLinkV1;

    fn commit(self, _token: HandoffTokenV1) -> VerifiedManifestOwnerLinkV1 {
        self.link
    }
}

fn verify_and_release<S: ManifestOwnerLinkReadPortV1 + ?Sized>(
    store: &S,
    request: &ManifestOwnerLinkRequestV1,
    authority: ManifestOwnerLinkAuthorityV1<'_>,
    fence: ManifestOwnerLinkUseFenceV1<'_, '_>,
) -> Result<ManifestOwnerLinkReleaseV1, ManifestOwnerLinkVerificationErrorV1> {
    let ManifestOwnerLinkUseFenceV1 {
        guard,
        expiries,
        erasure_gate,
        keys,
        wall,
        mono,
    } = fence;
    let denied = ManifestOwnerLinkVerificationErrorV1::ProtectedUseDenied;
    let generation = erasure_gate.inventory_generation().map_err(|_| denied)?;
    let snapshot = read_snapshot(store, request)?;
    let selected = verify_snapshot(request, &snapshot, authority, keys)?;
    let admission = selected.admission;
    let fresh = is_fresh_use(request, &snapshot, admission, generation, expiries)
        && keys_are_live(request, admission, keys);
    // The fence serializes inventory installation, so only a gate that closed
    // during the read can change this answer.
    if !fresh || erasure_gate.inventory_generation() != Ok(generation) {
        return Err(denied);
    }
    let link = mint(request, &snapshot, &selected, generation);
    // Drop the private materialization before anything is released.
    drop(snapshot);
    let staged = StagedProtectedOutputV1::stage(StagedManifestOwnerLinkV1 { link });
    handoff_checked(guard, expiries, staged, wall, mono).map_err(|_| denied)
}

fn owner_reference(owner: &OwnerIdV1) -> [u8; 32] {
    *ArtifactRegistrationV1::owner_reference(owner).as_bytes()
}

fn read_snapshot<S: ManifestOwnerLinkReadPortV1 + ?Sized>(
    store: &S,
    request: &ManifestOwnerLinkRequestV1,
) -> Result<ManifestOwnerLinkSnapshotV1, ManifestOwnerLinkVerificationErrorV1> {
    store
        .read_manifest_owner_link_snapshot_v1(
            owner_reference(&request.owner),
            request.identity,
            request.timeline_id,
        )
        .map_err(|_| ManifestOwnerLinkVerificationErrorV1::CompositionUnavailable)?
        .ok_or(ManifestOwnerLinkVerificationErrorV1::WrongCut)
}

/// Prove the cut, admission and closure chain, then re-verify signatures and
/// resolve the coordinator key evidence they name.
///
/// Structural checks run first so that a signature hook only ever sees one
/// consistent chain.
fn verify_snapshot<'s>(
    request: &ManifestOwnerLinkRequestV1,
    snapshot: &'s ManifestOwnerLinkSnapshotV1,
    authority: ManifestOwnerLinkAuthorityV1<'_>,
    keys: &dyn KeyRegistryPortV1,
) -> Result<SelectedLinkV1<'s>, ManifestOwnerLinkVerificationErrorV1> {
    let recording = select_recording(request, snapshot)?;
    verify_cut_chain(snapshot)?;
    verify_head_and_scope(request, recording)?;
    let (admission, context) = selected_admission(request, snapshot)?;
    verify_admitted_policy(admission)?;
    verify_admission_links(snapshot)?;
    if !admission_is_ancestor(snapshot, admission) {
        return Err(ManifestOwnerLinkVerificationErrorV1::CompositionUnavailable);
    }
    verify_dependency_closure(snapshot, recording, admission, context)?;
    verify_static_pins(snapshot, admission)?;
    authenticate_receipts(snapshot, authority)
        .and_then(|()| verify_coordinator_key_evidence(snapshot, keys))?;
    Ok(SelectedLinkV1 {
        recording,
        admission,
    })
}

/// Select the Timeline's WCR1 named by the identity in a cut still visible
/// under this owner.
fn select_recording<'s>(
    request: &ManifestOwnerLinkRequestV1,
    snapshot: &'s ManifestOwnerLinkSnapshotV1,
) -> Result<&'s LocalCutWorldRecordingV1, ManifestOwnerLinkVerificationErrorV1> {
    let seal = snapshot.result.seal.as_input();
    let visible = seal.owner_id == owner_reference(&request.owner)
        && seal.cut_id <= snapshot.owner_state.last_visible_cut_id;
    let recording = snapshot.result.recordings.iter().find(|recording| {
        recording.binding.as_input().timeline_id == request.timeline_id
            && request.identity.selects(&recording.receipt)
    });
    recording
        .filter(|_| visible)
        .ok_or(ManifestOwnerLinkVerificationErrorV1::WrongCut)
}

/// Prove WCR1 -> WCB1/LCQ1 -> LCC1 -> LCS2 and the kind-5/kind-14 rows.
fn verify_cut_chain(
    snapshot: &ManifestOwnerLinkSnapshotV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let result = &snapshot.result;
    let commit = result.commit.as_input();
    // The retained seal is typed as LCS2, so an LCS1 cut cannot reach this
    // check. An LCC1 that names any other digest is therefore either an
    // unsupported seal format or a substituted seal; both are deliberately
    // reported as `UnsupportedSealVersion`.
    if commit.seal_hash != result.seal.digest() {
        return Err(ManifestOwnerLinkVerificationErrorV1::UnsupportedSealVersion);
    }
    let seal = result.seal.as_input();
    let linked = validate_local_cut_owner_result_v1(seal.owner_id, seal.cut_id, result).is_ok()
        && local_cut_owner_intent_digest_v1(&snapshot.request).is_ok()
        && validate_local_cut_owner_recordings_v1(&snapshot.request, result).is_ok();
    let retained = (snapshot.request.seal, snapshot.request.result_heads_table);
    if !linked || retained != (result.seal, commit.result_heads_table) {
        return Err(ManifestOwnerLinkVerificationErrorV1::WrongCut);
    }
    Ok(())
}

fn verify_head_and_scope(
    request: &ManifestOwnerLinkRequestV1,
    recording: &LocalCutWorldRecordingV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let binding = recording.binding.as_input();
    let recorded = (
        binding.logical_head,
        binding.stitched_head_hash,
        recording.scope,
    );
    let head = request.expected_head;
    let expected = (
        head.logical_head,
        head.stitched_head_hash,
        request.expected_scope,
    );
    if recorded == expected {
        Ok(())
    } else {
        Err(ManifestOwnerLinkVerificationErrorV1::WrongCut)
    }
}

/// Pair the Timeline's admission with the kind-8 row at its row position.
fn selected_admission<'s>(
    request: &ManifestOwnerLinkRequestV1,
    snapshot: &'s ManifestOwnerLinkSnapshotV1,
) -> Result<SelectedAdmissionV1<'s>, ManifestOwnerLinkVerificationErrorV1> {
    snapshot
        .admissions
        .iter()
        .zip(&snapshot.request.recording_context_rows)
        .find(|(admission, _)| admission.timeline.timeline_id == request.timeline_id)
        .ok_or(ManifestOwnerLinkVerificationErrorV1::CompositionUnavailable)
}

/// Compare MSB1 with MCA1, the retained EOP1/OPC1 bytes of every admitted
/// Plugin with MCA1, and each WCS1 producer with its MSB1 EOP1 leaf.
fn verify_admitted_policy(
    admission: &ManifestOwnerAdmissionSnapshotV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    verify_admitted_copies(admission)?;
    let producers = admission.timeline.wcs1.producers();
    let producers_admitted = producers.iter().all(|producer| {
        bound_eop1_digest(admission, producer.plugin_id()) == Some(producer.output_policy_hash())
    });
    if producers_admitted {
        Ok(())
    } else {
        Err(ManifestOwnerLinkVerificationErrorV1::PolicyMismatch)
    }
}

/// Compare MSB1 with MCA1 and every admitted Plugin's retained EOP1/OPC1
/// bytes, zero-output Plugins included, with its MCA1 row.
fn verify_admitted_copies(
    admission: &ManifestOwnerAdmissionSnapshotV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let catalog = &admission.catalog.as_input().rows;
    let copies = &admission.timeline.policy_copies;
    let admitted = catalog
        .iter()
        .map(|row| (&row.stable_slot, row.plugin_id, row.closure_hash));
    let bound = admission.timeline.binding.as_input().rows.iter();
    let bound = bound.map(|row| (&row.stable_slot, row.plugin_id, row.closure_hash));
    if bound.ne(admitted) {
        return Err(ManifestOwnerLinkVerificationErrorV1::SlotBindingMismatch);
    }
    if copies.len() != catalog.len() {
        return Err(ManifestOwnerLinkVerificationErrorV1::ClosureUnavailable);
    }
    for row in catalog {
        let copy = copies
            .iter()
            .find(|copy| copy.plugin_id == row.plugin_id)
            .ok_or(ManifestOwnerLinkVerificationErrorV1::ClosureUnavailable)?;
        verify_policy_copy(row, copy)?;
    }
    Ok(())
}

/// The native digest of the EOP1 leaf whose WAL1 hash a Plugin's MSB1 row names.
fn bound_eop1_digest(
    admission: &ManifestOwnerAdmissionSnapshotV1,
    plugin_id: PluginId,
) -> Option<Hash> {
    let timeline = &admission.timeline;
    let rows = &timeline.binding.as_input().rows;
    let row = rows.iter().find(|row| row.plugin_id == plugin_id);
    let leaf = row.and_then(|row| {
        let mut leaves = timeline.policy_copies.iter().map(|copy| &copy.eop1_leaf);
        leaves.find(|leaf| leaf.digest() == row.eop1_wal1_hash)
    });
    leaf.map(|leaf| leaf.as_input().native_digest)
}

/// Recheck one admitted Plugin's exact native EOP1 and OPC1 bytes.
///
/// An OPC1 digest equal to the MCA1 closure hash fixes the admitted bytes,
/// whose envelope already bound this EOP1 at admission.
fn verify_policy_copy(
    row: &ManifestAdmissionCatalogRowV1,
    copy: &ManifestOwnerPolicyCopiesV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let admitted = (
        row.eop1_native_digest,
        row.plugin_id,
        &row.plugin_version,
        row.implementation_hash,
    );
    let decoded = OutputPolicyV1::from_canonical_cbor(&copy.eop1_bytes);
    let policy_matches = decoded.is_ok_and(|policy| {
        let fields = policy.fields();
        let pinned = (
            policy.digest(),
            fields.plugin_id,
            &fields.plugin_version,
            fields.implementation_hash,
        );
        pinned == admitted
    });
    if !policy_matches {
        return Err(ManifestOwnerLinkVerificationErrorV1::PolicyMismatch);
    }
    if opc1_native_digest(&copy.opc1_bytes) == row.closure_hash {
        Ok(())
    } else {
        Err(ManifestOwnerLinkVerificationErrorV1::ClosureUnavailable)
    }
}

/// Bind every kind-14 row to its admission at the sealed owner generation and
/// every kind-8 row to its kind-14 row.
fn verify_admission_links(
    snapshot: &ManifestOwnerLinkSnapshotV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let seal = snapshot.result.seal.as_input();
    let rows = snapshot.request.manifest_binding_table.rows();
    if rows.len() != snapshot.admissions.len() {
        return Err(ManifestOwnerLinkVerificationErrorV1::CompositionUnavailable);
    }
    for (row, admission) in rows.iter().zip(&snapshot.admissions) {
        verify_admission_row(seal, row, admission)?;
    }
    let contexts = snapshot
        .request
        .recording_context_rows
        .iter()
        .map(|context| (context.timeline_id, context.wcs_hash));
    let bound = rows.iter().map(|row| (row.timeline_id, row.wcs_hash));
    if contexts.ne(bound) {
        return Err(ManifestOwnerLinkVerificationErrorV1::SlotBindingMismatch);
    }
    Ok(())
}

/// Bind one kind-14 row to the admission of the same owner, sealed
/// configuration generation and Timeline, with exactly the row's MSR1.
///
/// The existing snapshot validation re-derives the admission's member leaves
/// from their native bytes and binds its MSR1 to its scope, WCS1, MSB1 and
/// MCA1 and to the stored pre-CAS pair (previous LCQ1 and expected inventory
/// generation). An admission whose MSR1 is the sealed row's MSR1 therefore
/// also has the row's scope, WCS1 and MSB1, so the MSR1 digest alone selects it.
fn verify_admission_row(
    seal: &LocalCutSealInputV2,
    row: &LocalCutManifestBindingRowV1,
    admission: &ManifestOwnerAdmissionSnapshotV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let catalog = admission.catalog.as_input();
    let admitted = (
        catalog.owner_id,
        catalog.configuration_generation,
        admission.timeline.timeline_id,
    );
    let sealed = (
        seal.owner_id,
        seal.configuration_generation,
        row.timeline_id,
    );
    if admitted != sealed || validate_manifest_owner_admission_snapshot_v1(admission).is_err() {
        Err(ManifestOwnerLinkVerificationErrorV1::CompositionUnavailable)
    } else if admission.timeline.receipt.digest() != row.msr_hash {
        Err(ManifestOwnerLinkVerificationErrorV1::SlotBindingMismatch)
    } else {
        Ok(())
    }
}

/// Whether the admission's committed result is an ancestor of the seal's
/// pre-state.
///
/// The walk starts at the seal's previous LCQ1 and expected inventory. Each
/// earlier cut of the same configuration generation must be exactly that
/// pre-state, and then yields its own seal's pre-state, until one equals the
/// admission's MSR1 previous LCQ1 and committed inventory generation. Every
/// admission commits a fresh inventory generation, so a cut sealed before it
/// can never stand for its result. This checks the admission's post-CAS
/// result; its pre-CAS pair is bound to the same row by
/// [`verify_admission_row`].
fn admission_is_ancestor(
    snapshot: &ManifestOwnerLinkSnapshotV1,
    admission: &ManifestOwnerAdmissionSnapshotV1,
) -> bool {
    let admitted = admitted_pre_state(admission);
    let mut pre_state = seal_pre_state(snapshot.result.seal.as_input());
    for ancestor in &snapshot.ancestors {
        if pre_state == admitted {
            return true;
        }
        if !precedes(ancestor, pre_state) {
            return false;
        }
        pre_state = seal_pre_state(ancestor.seal.as_input());
    }
    pre_state == admitted
}

/// Whether one earlier cut's LCQ1 names its LCC1, its LCC1 names its LCS2,
/// and its LCQ1 and committed inventory are exactly the pre-state.
fn precedes(ancestor: &ManifestOwnerLinkAncestorV1, pre_state: PreStateV1) -> bool {
    let commit = ancestor.commit.as_input();
    let linked = (
        ancestor.receipt.as_input().commit_record_hash,
        commit.seal_hash,
    );
    let committed = (
        Some(ancestor.receipt.digest()),
        commit.result_inventory_generation,
    );
    linked == (ancestor.commit.digest(), ancestor.seal.digest()) && committed == pre_state
}

/// Re-derive the Timeline's WCB1 and complete WDB1 directory from the
/// admission and require them, and every retained directory node, exactly.
fn verify_dependency_closure(
    snapshot: &ManifestOwnerLinkSnapshotV1,
    recording: &LocalCutWorldRecordingV1,
    admission: &ManifestOwnerAdmissionSnapshotV1,
    context: &LocalCutRecordingContextRowV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let unavailable = ManifestOwnerLinkVerificationErrorV1::ClosureUnavailable;
    let closure = derive_local_cut_world_closure_v1(&LocalCutWorldClosureSourceV1 {
        operation_id: snapshot.request.operation_id,
        seal: &snapshot.result.seal,
        admission,
        retention_lease_hash: context.retention_lease_hash,
        predecessor_binding_hash: context.predecessor_wcb_hash,
        genesis_hash: recording.binding.as_input().stitched_head_hash,
    })
    .map_err(|_| unavailable)?;
    // The retained nodes were gathered from the committed root, so a node
    // outside the derived directory is never read: "extra" means extra
    // relative to the derived directory, which the binding equality below
    // pins to the committed root.
    let retained = closure
        .directory()
        .branches()
        .iter()
        .all(|branch| snapshot.dependency_branches.get(&branch.digest()) == Some(branch));
    if retained && *closure.binding() == recording.binding {
        Ok(())
    } else {
        Err(unavailable)
    }
}

/// Compare every kind-1 static pin with MCA1 at the sealed generation.
///
/// A reducer-only Plugin may have no kind-1 row; each row must still name an
/// owned Timeline and an admitted Plugin, version, implementation and EOP1.
fn verify_static_pins(
    snapshot: &ManifestOwnerLinkSnapshotV1,
    admission: &ManifestOwnerAdmissionSnapshotV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let catalog = &admission.catalog.as_input().rows;
    let bound = snapshot.request.manifest_binding_table.rows();
    let pinned = snapshot.request.composition_rows.iter().all(|row| {
        let pin = (
            row.plugin_id,
            row.plugin_version.as_str(),
            row.implementation_hash,
            row.eop1_native_digest,
        );
        let owned = bound
            .iter()
            .any(|binding| binding.timeline_id == row.timeline_id);
        owned && catalog.iter().any(|admitted| static_pin(admitted) == pin)
    });
    if pinned {
        Ok(())
    } else {
        Err(ManifestOwnerLinkVerificationErrorV1::PolicyMismatch)
    }
}

/// The static pin that a kind-1 row must repeat from its MCA1 row.
const fn static_pin(row: &ManifestAdmissionCatalogRowV1) -> (PluginId, &str, Hash, Hash) {
    (
        row.plugin_id,
        row.plugin_version.as_str(),
        row.implementation_hash,
        row.eop1_native_digest,
    )
}

/// Re-verify LCQ1 and every MSR1 through the installed key-role hooks.
fn authenticate_receipts(
    snapshot: &ManifestOwnerLinkSnapshotV1,
    authority: ManifestOwnerLinkAuthorityV1<'_>,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let result = &snapshot.result;
    authority
        .local_cut
        .verify_local_cut_receipt(&result.receipt, &result.commit, &snapshot.admissions)
        .map_err(|_| ManifestOwnerLinkVerificationErrorV1::WrongCut)?;
    let admitted = snapshot.admissions.iter().all(|admission| {
        authority
            .admission
            .verify_coordinator_receipt(&admission.timeline.receipt)
            .is_ok()
    });
    if admitted {
        Ok(())
    } else {
        Err(ManifestOwnerLinkVerificationErrorV1::CompositionUnavailable)
    }
}

/// Resolve the retained WKE1 of the LCQ1 and every MSR1 against `keys`.
fn verify_coordinator_key_evidence(
    snapshot: &ManifestOwnerLinkSnapshotV1,
    keys: &dyn KeyRegistryPortV1,
) -> Result<(), ManifestOwnerLinkVerificationErrorV1> {
    let mut addresses = coordinator_evidence_hashes(&snapshot.result.receipt, &snapshot.admissions);
    addresses.try_for_each(|evidence_hash| {
        let bytes = snapshot
            .key_evidence
            .get(&evidence_hash)
            .ok_or(ManifestOwnerLinkVerificationErrorV1::CompositionUnavailable)?;
        resolve_coordinator_key_evidence_v1(bytes, evidence_hash, keys)
            .map(drop)
            .map_err(key_evidence_error)
    })
}

/// Unusable retained evidence leaves the admission unavailable; evidence that
/// the installed registry does not hold denies protected use.
const fn key_evidence_error(
    error: CoordinatorKeyEvidenceErrorV1,
) -> ManifestOwnerLinkVerificationErrorV1 {
    match error {
        CoordinatorKeyEvidenceErrorV1::InvalidEvidence
        | CoordinatorKeyEvidenceErrorV1::WrongKeyUse => {
            ManifestOwnerLinkVerificationErrorV1::CompositionUnavailable
        }
        CoordinatorKeyEvidenceErrorV1::UnregisteredKey => {
            ManifestOwnerLinkVerificationErrorV1::ProtectedUseDenied
        }
    }
}

/// Whether the owner's current inventory equals the gate's and `expiries`
/// cover the selected scope's recorded RLS1 retention deadline.
fn is_fresh_use(
    request: &ManifestOwnerLinkRequestV1,
    snapshot: &ManifestOwnerLinkSnapshotV1,
    admission: &ManifestOwnerAdmissionSnapshotV1,
    generation: ErasureReferenceV1,
    expiries: &ApplicableExpiriesV1,
) -> bool {
    let state = &snapshot.owner_state;
    let fenced = (
        owner_reference(&request.owner),
        Hash::from_bytes(generation.digest()),
    );
    let current = (state.owner_id, state.inventory_generation) == fenced;
    let deadline = recorded_lease(&admission.timeline.members)
        .map(|lease| WallTime::from_micros(lease.retention_deadline_micros));
    current && deadline.is_some_and(|deadline| expiries.earliest_expiry() <= deadline)
}

/// Whether every key dependency of the selected scope names the owner's
/// active, undestroyed key of its role.
///
/// Only the active epoch resolves. A leaf names its key only by identity
/// digest, and the registry port cannot enumerate an owner's sparse role
/// epochs, so an older epoch has no bounded lookup here; coordinator receipts
/// instead resolve their retained WKE1 bytes directly.
fn keys_are_live(
    request: &ManifestOwnerLinkRequestV1,
    admission: &ManifestOwnerAdmissionSnapshotV1,
    keys: &dyn KeyRegistryPortV1,
) -> bool {
    let owner_id = owner_reference(&request.owner);
    let timeline = &admission.timeline;
    timeline
        .members
        .leaves
        .iter()
        .map(|member| &member.leaf)
        .chain(
            timeline
                .policy_copies
                .iter()
                .flat_map(|copy| [&copy.eop1_leaf, &copy.opc1_leaf]),
        )
        .flat_map(|leaf| &leaf.as_input().key_dependencies)
        .all(|dependency| {
            let active = active_key_identity(keys, &request.owner, dependency.role);
            dependency.owner == owner_id && active == Some(dependency.identity_digest)
        })
}

/// The stable WKE1 identity digest of the owner's active live key of `role`.
fn active_key_identity(
    keys: &dyn KeyRegistryPortV1,
    owner: &OwnerIdV1,
    role: KeyRoleV1,
) -> Option<Hash> {
    keys.active_key(owner, role)
        .and_then(|record| {
            record
                .private_material_digest
                .map(|private_material_digest| WorldKeyEvidenceInputV1 {
                    identity: record.identity,
                    private_material_digest,
                    private_material_required: true,
                    public_verification_key: record.public_verification_key,
                })
        })
        .and_then(|input| WorldKeyEvidenceV1::new(input).ok())
        .map(|evidence| evidence.identity_digest())
}

fn mint(
    request: &ManifestOwnerLinkRequestV1,
    snapshot: &ManifestOwnerLinkSnapshotV1,
    selected: &SelectedLinkV1<'_>,
    inventory_generation: ErasureReferenceV1,
) -> VerifiedManifestOwnerLinkV1 {
    let result = &snapshot.result;
    let seal = result.seal.as_input();
    let timeline = &selected.admission.timeline;
    VerifiedManifestOwnerLinkV1 {
        owner_id: seal.owner_id,
        cut_id: seal.cut_id,
        timeline_id: request.timeline_id,
        configuration_generation: seal.configuration_generation,
        head: request.expected_head,
        scope: selected.recording.scope,
        digests: ManifestOwnerLinkDigestsV1 {
            lcs2: result.seal.digest(),
            lcc1: result.commit.digest(),
            lcq1: result.receipt.digest(),
            wcb1: selected.recording.binding.digest(),
            wcr1: selected.recording.receipt.digest(),
            mca1: selected.admission.catalog.digest(),
            msr1: timeline.receipt.digest(),
            msb1: timeline.binding.digest(),
            wcs1: timeline.wcs1.digest(),
        },
        inventory_generation,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_test_support_link_exposes_its_bindings_and_never_grants_exact() {
        let request = ManifestOwnerLinkRequestV1 {
            owner: OwnerIdV1::from_static("open-source-app"),
            identity: ManifestOwnerLinkCutIdentityV1::LocalCutReceipt(Hash::from_bytes([1; 32])),
            timeline_id: TimelineId::new(),
            expected_head: ManifestOwnerLinkHeadV1 {
                logical_head: 0,
                stitched_head_hash: Hash::from_bytes([2; 32]),
            },
            expected_scope: Hash::from_bytes([3; 32]),
        };
        let digests = ManifestOwnerLinkDigestsV1 {
            lcs2: Hash::from_bytes([4; 32]),
            lcc1: Hash::from_bytes([5; 32]),
            lcq1: Hash::from_bytes([6; 32]),
            wcb1: Hash::from_bytes([7; 32]),
            wcr1: Hash::from_bytes([8; 32]),
            mca1: Hash::from_bytes([9; 32]),
            msr1: Hash::from_bytes([10; 32]),
            msb1: Hash::from_bytes([11; 32]),
            wcs1: Hash::from_bytes([12; 32]),
        };
        let generation = ErasureReferenceV1::from_digest([13; 32]);
        let link = test_verified_manifest_owner_link(&request, 7, 2, &digests, generation);
        assert_eq!(link.owner_id(), owner_reference(&request.owner));
        assert_eq!(link.cut_id(), 7);
        assert_eq!(link.timeline_id(), request.timeline_id);
        assert_eq!(link.configuration_generation(), 2);
        assert_eq!(link.head(), request.expected_head);
        assert_eq!(link.scope(), request.expected_scope);
        assert_eq!(link.digests(), digests);
        assert_eq!(link.inventory_generation(), generation);
        assert_eq!(
            link.require_exact_claim(),
            Err(ManifestOwnerLinkVerificationErrorV1::ClosureUnavailable)
        );
    }
}
