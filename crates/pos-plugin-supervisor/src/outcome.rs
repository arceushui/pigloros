//! The stable per-Plugin outcome record of one host pass (ADR-061 revision 7 decision 13, #585).
//!
//! [`CommunityPluginSubjectOutcomeV1`] is the record the #194 subject adapter reads. It is
//! assembled, never stored, from the member's entry of the pass
//! ([`MemberPassV1`](pos_runtime::community_plugin_host::MemberPassV1)) and, when the member's
//! Driver launched, the invocation receipt of that pass. The record carries no claim about
//! signature validity: the gate's verdict is the `Refused` result, and `content_validation` is
//! the fact that the release content was not validated (decision 12).

use pos_plugin_release::ContentValidationV1;
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, CommunityPluginModeV1, HostFailureClassV1, MemberPassV1, MeteringV1,
};

use crate::adapter::{CommunityInvocationReceiptV1, ReceiptDispositionV1};

/// How one Plugin's pass ended, as a closed set with the exact closed strings of ADR-061
/// revision 7 decisions 3 and 5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityPluginSubjectResultV1 {
    /// The invocation is staged in the pending pass (receipt disposition `Staged`).
    Staged {
        /// The V1 output digest the guest returned.
        output_digest: Option<[u8; 32]>,
        /// The deterministic metering the worker reported.
        metering: Option<MeteringV1>,
    },
    /// The whole batch committed (receipt disposition `Committed`).
    Committed {
        /// The V1 output digest the guest returned.
        output_digest: Option<[u8; 32]>,
        /// The deterministic metering the worker reported.
        metering: Option<MeteringV1>,
    },
    /// A host refusal before any guest code ran: a gate error, or a failure of the class
    /// `PreExecutionRejection`.
    Refused {
        /// The closed error name.
        error: &'static str,
        /// The trust or revocation basis name, when the error has one.
        basis: Option<&'static str>,
        /// The `HostFailureClassV1` variant name.
        class: &'static str,
    },
    /// A failure of the class `Authoritative` or `Operational`.
    Failed {
        /// The closed error name.
        error: &'static str,
        /// The `HostFailureClassV1` variant name.
        class: &'static str,
    },
    /// The gate was `Ok` but nothing launched: a sibling member refused the whole pass, or the
    /// member was quarantined.
    NotRun,
    /// A receipt with disposition `Discarded` and no failure: an aborted pass.
    Discarded,
}

/// The stable outcome record of one Plugin in one pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPluginSubjectOutcomeV1 {
    /// The PMF1 Plugin ID text the composition expected for the member.
    pub plugin_id: String,
    /// BLAKE3-256 of the complete canonical PMF1 bytes: `Some` exactly when the gate was `Ok`.
    pub pmf1_digest: Option<[u8; 32]>,
    /// The PMF1 release digest: `Some` exactly when the gate was `Ok`.
    pub release_digest: Option<[u8; 32]>,
    /// The authenticated TPS1 digest: `Some` exactly when the gate was `Ok`.
    pub tps1_digest: Option<[u8; 32]>,
    /// The execution profile digest of the receipt's negotiated record: `Some` exactly when a
    /// receipt exists and its record carries a digest.
    pub execution_profile_digest: Option<[u8; 32]>,
    /// The Tick of the pass.
    pub tick: u64,
    /// The Execution Mode: the receipt's negotiated mode when a receipt exists, else the
    /// caller's.
    pub mode: CommunityPluginModeV1,
    /// What was checked about the release content: until #574 the constant `NotPerformed`.
    pub content_validation: ContentValidationV1,
    /// How the pass ended for the Plugin.
    pub result: CommunityPluginSubjectResultV1,
}

impl CommunityPluginSubjectOutcomeV1 {
    /// Assemble the record of `entry`, total over every entry and receipt.
    ///
    /// `tick` and `mode` come from the caller, because a refused gate supplies neither; when
    /// `receipt` exists its negotiated mode wins over `mode`.
    ///
    /// `receipt` is the one the caller found with `CommunityPluginHandleV1::receipt_for()` for
    /// `entry.invocation_id`; the caller passes `None` when that ID is `None`, because
    /// `assemble` compares no IDs.
    ///
    /// The result precedence is:
    /// - a gate error is `Refused`;
    /// - else a receipt governs: its failure is `Refused` for the class `PreExecutionRejection`
    ///   and `Failed` otherwise, and with no failure its disposition gives `Staged`,
    ///   `Committed` or `Discarded`;
    /// - else the pass's `launch_failure` is `Refused` or `Failed` by class;
    /// - else `NotRun`.
    #[must_use]
    pub fn assemble(
        entry: &MemberPassV1,
        tick: u64,
        mode: CommunityPluginModeV1,
        receipt: Option<&CommunityInvocationReceiptV1>,
    ) -> Self {
        let gated = entry.gate.as_ref().ok();
        Self {
            plugin_id: entry.expected_plugin_id.clone(),
            pmf1_digest: gated.map(|summary| summary.pmf1_digest),
            release_digest: gated.map(|summary| summary.release_digest),
            tps1_digest: gated.map(|summary| summary.tps1_digest),
            execution_profile_digest: receipt
                .and_then(|receipt| receipt.negotiated.execution_profile_digest()),
            tick,
            mode: receipt.map_or(mode, |receipt| receipt.negotiated.mode()),
            content_validation: ContentValidationV1::NotPerformed,
            result: result_of(entry, receipt),
        }
    }
}

/// The result by precedence: gate error, receipt, launch failure, not run.
fn result_of(
    entry: &MemberPassV1,
    receipt: Option<&CommunityInvocationReceiptV1>,
) -> CommunityPluginSubjectResultV1 {
    entry
        .gate
        .as_ref()
        .err()
        .map(|error| refused(*error))
        .or_else(|| receipt.map(receipt_result))
        .or_else(|| entry.launch_failure.map(by_class))
        .unwrap_or(CommunityPluginSubjectResultV1::NotRun)
}

/// The result a receipt governs: its failure by class, else its disposition.
fn receipt_result(receipt: &CommunityInvocationReceiptV1) -> CommunityPluginSubjectResultV1 {
    receipt.failure.map_or_else(|| settled(receipt), by_class)
}

/// The result of a receipt that records no failure.
const fn settled(receipt: &CommunityInvocationReceiptV1) -> CommunityPluginSubjectResultV1 {
    match receipt.disposition {
        ReceiptDispositionV1::Staged => CommunityPluginSubjectResultV1::Staged {
            output_digest: receipt.output_digest,
            metering: receipt.metering,
        },
        ReceiptDispositionV1::Committed => CommunityPluginSubjectResultV1::Committed {
            output_digest: receipt.output_digest,
            metering: receipt.metering,
        },
        ReceiptDispositionV1::Discarded => CommunityPluginSubjectResultV1::Discarded,
    }
}

/// `Refused` for a pre-execution rejection, `Failed` for every other class.
const fn by_class(error: CommunityPluginHostErrorV1) -> CommunityPluginSubjectResultV1 {
    match error.class() {
        HostFailureClassV1::PreExecutionRejection => refused(error),
        HostFailureClassV1::Authoritative | HostFailureClassV1::Operational => failed(error),
    }
}

const fn failed(error: CommunityPluginHostErrorV1) -> CommunityPluginSubjectResultV1 {
    CommunityPluginSubjectResultV1::Failed {
        error: error.name(),
        class: error.class().name(),
    }
}

const fn refused(error: CommunityPluginHostErrorV1) -> CommunityPluginSubjectResultV1 {
    CommunityPluginSubjectResultV1::Refused {
        error: error.name(),
        basis: error.basis_name(),
        class: error.class().name(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
