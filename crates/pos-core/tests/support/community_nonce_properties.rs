//! Shared fallible property runner for public framing invariants.

use proptest::strategy::Strategy;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Exercise each complete boundary matrix with eight generated inputs. The
/// runner retains shrinking and regression persistence; every original length
/// and refusal case still runs for every generated nonce.
pub(super) fn check<S: Strategy>(
    strategy: S,
    property: impl Fn(S::Value) -> TestResult,
) -> TestResult {
    let mut runner = TestRunner::new(Config {
        cases: 8,
        source_file: Some(file!()),
        ..Config::default()
    });
    runner
        .run(&strategy, |value| {
            property(value).map_err(|error| TestCaseError::fail(error.to_string()))
        })
        .map_err(|error| format!("generated framing input failed: {error}").into())
}
