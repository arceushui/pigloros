#![forbid(unsafe_code)]

//! The metric-conformance subject adapter of plugins/eval (ADR-062 Revision 7 slice 4, #1217).
//!
//! [`run()`] reads one EAI1 attempt, runs the sub-cases of its payload through the public
//! `MTI1`/`MTQ1` codecs and computation of plugins/eval (the implementation under test), and
//! writes one EAO1 observation; the `pos-metric-conformance-adapter` binary only wires the
//! process's standard streams to it. It is the `exported-artifact` subject adapter of profile
//! `pigloros.w8.metric-computation` (claim layer `MetricConformance = 5`).
//!
//! The order of checks:
//! 1. The EAI1 stream decodes, else there is no EAO1 stream and the exit code is non-zero.
//! 2. The claim layer is `metric-conformance` and the mode is Local or Air-Gapped, else the
//!    result is `Unavailable` with zero usage.
//! 3. The BLAKE3 of the schema member is the digest pinned for the family (provider contract
//!    2.0.0), and
//! 4. an auxiliary member is the family's `MCS1` composite: otherwise the attempt is not
//!    executed (no EAO1 stream, a non-zero exit). There is no reader for the Draft provider
//!    contract 1.0.0 (`fixture-ratio`), so its attempts are not executed.
//! 5. A payload that violates the grammar of the payload module, or names a member the
//!    composite lacks, is the failure `payload-invalid`.
//! 6. Each sub-case runs on its own: its stimulus gate first (a capability other than
//!    `read-public-bundle` or any network use is denied, a step request above the attempt's
//!    execution-step budget is a resource limit, another provider contract is incompatible, an
//!    oversized member goes through the #222 transport), then plugins/eval decodes and computes
//!    its `MTI1` or `MTQ1` member. A sub-case the subject does not decide (the evaluator's
//!    acceptance of a foreign `MTR1`, `dgr.3`, and the generator check, `ind.2`) is recorded
//!    and not executed: plugins/eval has no `MTR1` decoder.
//! 7. A `canonical-output` family (positive, deletion-redaction, independent-evaluation)
//!    outputs its record of every sub-case, which equals the oracle only when every result is
//!    the expected `MTR1`/`MQR1`. A `namespaced-failure` family returns its family failure when
//!    every sub-case is as expected, else `subcase-mismatch`.
//!
//! The adapter meters one execution step per member plugins/eval decodes; its other usage
//! counters are 0. Results are Local-relaxation engineering evidence, not hosted conformance; a
//! pass claims metric computation only (ADR-062 Revision 7 section 4.1 item 2).

mod subject;

pub use subject::{
    exit_code, run, AdapterRunErrorV1, CAPABILITY_ID, CONTRACT_VERSION, PAYLOAD_INVALID,
    PROVIDER_ID, SCHEMA_ID, SUBCASE_MISMATCH,
};
