//! The provider conformance cases as one machine-readable manifest (#216).
//!
//! The guest collector, the host checker and the suite itself must agree on
//! what every case runs and what it must show. [`case_manifest_v1`] is that
//! one statement, built from [`ProviderConformanceCase`] and the adapter plan,
//! and a committed copy of it is the vector that the non-Rust parts read. A
//! test keeps the copy equal to what the code states.
//!
//! Each case names its driver, which tells the runner what it needs besides
//! the adapter: `single-execute` runs one attempt, `control` also acts on it
//! (cancel, revoke, broker crash), `admission` is refused before any attempt,
//! and `concurrent` runs several attempts at once.

use serde_json::{json, Value};

use crate::{
    ExpectedPublicOutcome, ProviderConformanceCase, MEMORY_CEILING_BYTES, OUTPUT_CEILING_BYTES,
    TASK_CEILING, WATCHDOG_CEILING_MS, WORK_CEILING_BYTES,
};

/// The manifest's version.
const VERSION: u64 = 1;

/// What the runner needs of a case besides its adapter.
const fn driver(case: ProviderConformanceCase) -> &'static str {
    match case {
        ProviderConformanceCase::CancelBeforeRelease
        | ProviderConformanceCase::CancelWhileRunning
        | ProviderConformanceCase::BrokerCrashRecovery
        | ProviderConformanceCase::RevokedWhileRunning => "control",
        ProviderConformanceCase::RevokedBeforeAdmission
        | ProviderConformanceCase::MissingHostFeature => "admission",
        ProviderConformanceCase::ConcurrentAttempts => "concurrent",
        _ => "single-execute",
    }
}

/// The public outcome a case must show, in the report's own names.
fn expectation(outcome: ExpectedPublicOutcome) -> Value {
    match outcome {
        ExpectedPublicOutcome::Terminal { outcome, codes } => {
            json!({ "kind": "terminal", "outcome": format!("{outcome:?}"), "codes": codes })
        }
        ExpectedPublicOutcome::Refused(codes) => {
            let names: Vec<String> = codes.iter().map(|code| format!("{code:?}")).collect();
            json!({ "kind": "refused", "codes": names })
        }
    }
}

fn entry(case: ProviderConformanceCase) -> Value {
    json!({
        "id": case.id(),
        "attempts": case.attempts(),
        "driver": driver(case),
        "arguments": case.adapter_plan().arguments(),
        "expect": expectation(case.expectation()),
    })
}

/// The manifest of every case, in report order, with the ceilings the cases'
/// attempts are built with.
#[must_use]
pub fn case_manifest_v1() -> Value {
    json!({
        "version": VERSION,
        "ceilings": {
            "memory_bytes": MEMORY_CEILING_BYTES,
            "tasks": TASK_CEILING,
            "watchdog_ms": WATCHDOG_CEILING_MS,
            "output_bytes": OUTPUT_CEILING_BYTES,
            "work_bytes": WORK_CEILING_BYTES,
        },
        "cases": ProviderConformanceCase::ALL.map(entry),
    })
}
