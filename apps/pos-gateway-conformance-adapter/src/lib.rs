#![forbid(unsafe_code)]
// The whole crate needs the nonproduction fixture registration of the Gateway action registry.
#![cfg(feature = "test-support")]

//! The gateway-client-conformance subject adapter of apps/piglor-gateway (provider contract
//! 2.0.0, Redmine #1295).
//!
//! [`run()`] reads one EAI1 attempt, runs the HTTP exchanges of its payload on fresh
//! in-process Gateways through the public `router` and `spectator_router` (raw HTTP requests,
//! no socket), and writes one EAO1 observation; the `pos-gateway-conformance-adapter` binary
//! only wires the process's standard streams to it. It is the `public-gateway-protocol` subject
//! adapter of profile `pigloros.w8.gateway-client-seam` (claim layer
//! `GatewayClientConformance = 3`). The exchange grammar, the compositions, the normalization
//! and the result are those of
//! `fixtures/conformance/profiles/gateway-client-conformance/normative-requirements.md`.
//!
//! The order of checks:
//! 1. The EAI1 stream decodes, else there is no EAO1 stream and the exit code is non-zero.
//! 2. The claim layer is `gateway-client-conformance` and the mode is Local or Air-Gapped, else
//!    the result is `Unavailable` with zero usage.
//! 3. The BLAKE3 of the schema member is the digest pinned for the family (provider contract
//!    2.0.0), else the attempt is not executed (no EAO1 stream, a non-zero exit). There is no
//!    reader for the Draft provider contract 1.0.0.
//! 4. A payload that violates the grammar is the failure `payload-invalid`.
//! 5. Each sub-case runs on its own Gateway. An exchange whose route capability the attempt
//!    does not hold is refused before any request.
//! 6. A `canonical-output` family (positive, deletion-redaction, independent-evaluation)
//!    outputs its record of every sub-case. A `namespaced-failure` family returns its family
//!    failure when every exchange matched, else `subcase-mismatch`.
//!
//! The `authorized` composition is explicitly fixture-only: the fixture registration of the
//! Gateway action registry and a fixture authority, from which no production authority is
//! sourced (ADR-108). Results are Local-relaxation engineering evidence, not hosted
//! conformance.

mod normalize;
mod subject;

pub use normalize::{normalize_response_v1, observation_v1};
pub use subject::{
    executor_declaration, exit_code, run, AdapterRunErrorV1, ABI_MAJOR, ABI_MINOR, ACTOR_ENTITY_ID,
    BODY_ENTITY_ID, CAPABILITY_IDS, CONTRACT_VERSION, PAYLOAD_INVALID, PROVIDER_ID, SCHEMA_ID,
    SUBCASE_MISMATCH,
};
