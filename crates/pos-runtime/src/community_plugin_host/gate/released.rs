//! The two values a successful gate yields (ADR-061 revision 7 decision 2).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pos_crypto::plugin_execution::PluginExecutionProjectionV1;
use pos_crypto::plugin_manifest::component_digest_v1;
use pos_plugin_release::ContentValidationV1;

use super::pass::CommunityPassV1;

/// The pair of digests that identifies one release: the complete canonical PMF1 and the PMF1
/// release digest.
///
/// A named pair keeps the two 32-byte values from being swapped positionally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseIdentityV1 {
    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    pub pmf1_digest: [u8; 32],
    /// The PMF1 release digest.
    pub release_digest: [u8; 32],
}

/// A release the execution-time trust gate accepted.
///
/// It has no public constructor (a `test-support` constructor exists for tests) and read
/// accessors only. It proves the gate at its own UTC second and Tick only; negotiation and
/// Driver construction confer no authority to execute at any other Tick. It is the only input a
/// Driver can be built from. It owns the Component bytes (up to 33 MiB), so it is not `Clone`
/// and its `Debug` output shows lengths and digests only.
#[derive(Eq, PartialEq)]
pub struct GatedCommunityReleaseV1 {
    execution: PluginExecutionProjectionV1,
    component: Vec<u8>,
    component_digest: [u8; 32],
    tps1_digest: [u8; 32],
    utc_second: i64,
    tick: u64,
}

impl GatedCommunityReleaseV1 {
    /// The gated release; the Component digest is computed here from the bytes held.
    pub(super) fn new(
        execution: PluginExecutionProjectionV1,
        component: Vec<u8>,
        tps1_digest: [u8; 32],
        utc_second: i64,
        tick: u64,
    ) -> Self {
        Self {
            component_digest: component_digest_v1(&component),
            execution,
            component,
            tps1_digest,
            utc_second,
            tick,
        }
    }

    /// A gated release for tests: the TPS1 digest is `[0x33; 32]` and the UTC second and Tick
    /// are zero. Nothing was gated.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test(execution: PluginExecutionProjectionV1, component: Vec<u8>) -> Self {
        Self::new(execution, component, [0x33; 32], 0, 0)
    }

    /// The exact PMF1 Plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        self.execution.plugin_id()
    }

    /// The complete-PMF1 and release digests as one pair.
    #[must_use]
    pub const fn identity(&self) -> ReleaseIdentityV1 {
        ReleaseIdentityV1 {
            pmf1_digest: self.execution.pmf1_digest(),
            release_digest: self.execution.release_digest(),
        }
    }

    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.execution.pmf1_digest()
    }

    /// The PMF1 release digest.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.execution.release_digest()
    }

    /// The execution requirements projected from the same PMF1 bytes.
    #[must_use]
    pub const fn execution(&self) -> &PluginExecutionProjectionV1 {
        &self.execution
    }

    /// The verified bytes of the closure's `component` layer, as re-read for this gate call.
    #[must_use]
    pub fn component(&self) -> &[u8] {
        &self.component
    }

    /// `component_digest_v1` of [`Self::component()`], computed from the bytes held.
    #[must_use]
    pub const fn component_digest(&self) -> [u8; 32] {
        self.component_digest
    }

    /// The digest of the authenticated TPS1 the registry retained.
    #[must_use]
    pub const fn tps1_digest(&self) -> [u8; 32] {
        self.tps1_digest
    }

    /// The trusted UTC second the release was gated at.
    #[must_use]
    pub const fn utc_second(&self) -> i64 {
        self.utc_second
    }

    /// The Tick the release was gated at.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// What was checked about the release content.
    ///
    /// The registry stores no install receipt, so until #574 the fact is the constant
    /// `NotPerformed`.
    #[must_use]
    pub const fn content_validation(&self) -> ContentValidationV1 {
        ContentValidationV1::NotPerformed
    }
}

impl std::fmt::Debug for GatedCommunityReleaseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatedCommunityReleaseV1")
            .field("plugin_id", &self.plugin_id())
            .field("identity", &self.identity())
            .field("component_len", &self.component.len())
            .field("component_digest", &self.component_digest)
            .field("tps1_digest", &self.tps1_digest)
            .field("utc_second", &self.utc_second)
            .field("tick", &self.tick)
            .finish()
    }
}

/// The one-shot proof that a release was gated for a pass.
///
/// It is opaque, neither `Clone` nor `Copy`, and consumed by value by exactly one worker launch.
/// It binds the Plugin ID, the complete-PMF1 and release digests, the Component digest, the
/// Tick, the authenticated TPS1 digest, and the pass-open flag of its pass, which only the
/// pass's creator clears. There is no separate pass identity.
#[derive(Debug)]
pub struct CommunityPassAuthorizationV1 {
    plugin_id: String,
    identity: ReleaseIdentityV1,
    component_digest: [u8; 32],
    tick: u64,
    tps1_digest: [u8; 32],
    pass_open: Arc<AtomicBool>,
}

impl CommunityPassAuthorizationV1 {
    /// The authorization of `gated` in `pass`.
    pub(super) fn issue(gated: &GatedCommunityReleaseV1, pass: &CommunityPassV1) -> Self {
        Self::assemble(
            pass,
            gated.plugin_id(),
            gated.identity(),
            gated.component_digest(),
            gated.tick(),
            gated.tps1_digest(),
        )
    }

    /// An authorization of `pass` with arbitrary field values, for tests that exercise a
    /// launch without calling the gate.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test(
        pass: &CommunityPassV1,
        plugin_id: &str,
        identity: ReleaseIdentityV1,
        component_digest: [u8; 32],
        tick: u64,
        tps1_digest: [u8; 32],
    ) -> Self {
        Self::assemble(
            pass,
            plugin_id,
            identity,
            component_digest,
            tick,
            tps1_digest,
        )
    }

    fn assemble(
        pass: &CommunityPassV1,
        plugin_id: &str,
        identity: ReleaseIdentityV1,
        component_digest: [u8; 32],
        tick: u64,
        tps1_digest: [u8; 32],
    ) -> Self {
        Self {
            plugin_id: plugin_id.to_owned(),
            identity,
            component_digest,
            tick,
            tps1_digest,
            pass_open: pass.open_flag(),
        }
    }

    /// The exact PMF1 Plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// The complete-PMF1 and release digests as one pair.
    #[must_use]
    pub const fn identity(&self) -> ReleaseIdentityV1 {
        self.identity
    }

    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.identity.pmf1_digest
    }

    /// The PMF1 release digest.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.identity.release_digest
    }

    /// The Component digest of the bytes the gate re-read.
    #[must_use]
    pub const fn component_digest(&self) -> [u8; 32] {
        self.component_digest
    }

    /// The Tick of the pass.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// The digest of the authenticated TPS1 the registry retained.
    #[must_use]
    pub const fn tps1_digest(&self) -> [u8; 32] {
        self.tps1_digest
    }

    /// Whether the pass this authorization belongs to is still open.
    #[must_use]
    pub fn is_pass_open(&self) -> bool {
        self.pass_open.load(Ordering::Acquire)
    }
}
