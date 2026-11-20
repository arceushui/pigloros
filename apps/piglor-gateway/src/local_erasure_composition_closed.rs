//! The serve composition of the erasure authority on a build without Linux
//! systemd credentials: only the closed composition (ADR-136 §4a; owner
//! decision D9 of 2026-11-18 on #1413). `serve --require-local-erasure`
//! refuses to start.

use std::path::Path;

use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use thiserror::Error;

use crate::Gateway;

/// The fixed path of the deployment trust state store.
pub const DEPLOYMENT_TRUST_STATE_PATH: &str = "/var/lib/pigloros/trust-state.db";

/// Why `serve --require-local-erasure` refuses to start.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum LocalErasureServeErrorV1 {
    /// This build has no Linux systemd credentials.
    #[error("local erasure requires Linux systemd credentials")]
    Unsupported,
}

/// The inputs of `serve --require-local-erasure`.
#[derive(Clone, Copy, Debug)]
pub struct LocalErasureServeInputsV1<'a> {
    /// The Gateway's `SQLite` store.
    pub sqlite_path: &'a str,
    /// The serve unit's credential directory.
    pub credential_directory: &'a Path,
    /// The deployment trust state store.
    pub trust_state: &'a Path,
    /// Whether the directory also holds the Fork-admission credentials.
    pub with_fork_authority: bool,
}

/// The closed erasure authority of one serve.
pub struct LocalErasureServeV1 {
    composition: ErasureCoordinatorCompositionV1,
}

impl LocalErasureServeV1 {
    /// The closed erasure authority.
    #[must_use]
    pub fn closed() -> Self {
        Self {
            composition: ErasureCoordinatorCompositionV1::closed(),
        }
    }

    /// The closed authority, or a refusal when `inputs` ask for the Local
    /// one.
    ///
    /// # Errors
    /// Returns [`LocalErasureServeErrorV1::Unsupported`] for any `inputs`.
    pub fn for_serve(
        inputs: Option<LocalErasureServeInputsV1<'_>>,
    ) -> Result<Self, LocalErasureServeErrorV1> {
        inputs.map_or_else(
            || Ok(Self::closed()),
            |_| Err(LocalErasureServeErrorV1::Unsupported),
        )
    }

    /// The composition the erasure host opens with.
    #[must_use]
    pub const fn composition(&self) -> &ErasureCoordinatorCompositionV1 {
        &self.composition
    }

    /// A closed composition starts nothing; it takes `self` like the Linux
    /// composition does.
    #[must_use]
    pub fn start(self, _host: &mut ErasureExecutionHostV1) -> LocalErasureStartV1 {
        let Self { composition: _ } = self;
        LocalErasureStartV1 { sweep: None }
    }
}

/// No startup sweep runs off Linux: the uninhabited stand-in of the Linux
/// sweep outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureSweepV1 {}

/// A started closed composition.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalErasureStartV1 {
    sweep: Option<LocalErasureSweepV1>,
}

impl LocalErasureStartV1 {
    /// No sweep ran: always `None`.
    #[must_use]
    pub const fn sweep(&self) -> Option<LocalErasureSweepV1> {
        self.sweep
    }
}

/// The admission hook of a driver; none exists off Linux, so it is
/// uninhabited.
#[derive(Clone, Copy, Debug)]
pub enum LocalErasureTriggerV1 {}

impl LocalErasureTriggerV1 {
    /// Never called: no trigger exists.
    pub const fn admitted(&self) {
        match *self {}
    }
}

/// The inert driver of a closed composition.
pub struct LocalErasureDriverTaskV1 {
    trigger: Option<LocalErasureTriggerV1>,
}

impl LocalErasureDriverTaskV1 {
    /// No driver runs.
    #[must_use]
    pub const fn spawn(_gateway: &Gateway, _started: LocalErasureStartV1) -> Self {
        Self { trigger: None }
    }

    /// No admission hook: always `None`.
    #[must_use]
    pub const fn trigger(&self) -> Option<LocalErasureTriggerV1> {
        self.trigger
    }

    /// Nothing to stop; ready at once.
    pub fn stop(self) -> std::future::Ready<()> {
        let Self { trigger: _ } = self;
        std::future::ready(())
    }
}
