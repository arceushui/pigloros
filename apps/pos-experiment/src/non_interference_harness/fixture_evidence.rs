//! The repository test-fixture-only executor key of the checked-in
//! non-interference evidence (owner note
//! `ADR-062_R8_NonInterference_Executions`, decision 1).
//!
//! Every checked-in NIA1 under `fixtures/conformance/non-interference/` is
//! signed with [`non_interference_fixture_executor_key_v1`], whose public key
//! `non-interference/executor.json` declares. Its secret is a public
//! derivation, so its signatures are engineering evidence and attest nothing.

use super::HostExecutorKeyV1;

/// The key id of the repository test-fixture-only executor key.
pub const NON_INTERFERENCE_FIXTURE_EXECUTOR_KEY_ID_V1: &str =
    "pigloros.fixture.non-interference-executor";

const EXECUTOR_KEY_CONTEXT: &str =
    "PiglorOS repository test-fixture-only non-interference executor key v1";

/// The repository test-fixture-only executor key of the checked-in
/// non-interference evidence.
#[must_use]
pub fn non_interference_fixture_executor_key_v1() -> HostExecutorKeyV1 {
    HostExecutorKeyV1::from_secret_bytes(&blake3::derive_key(EXECUTOR_KEY_CONTEXT, b""))
}
