//! Rust guest of the ADR-061 revisions 4 and 5 compatibility prototype (#539).
//!
//! It implements `pigloros:plugin/community-plugin@0.1.0` with no WASI import.
//! The C guest in `../c-guest` implements the same behaviour, specified in
//! `docs/evidence/adr-061-r4-prototype.md`, so that both Components return
//! identical results for identical inputs.

// `build-fixtures.sh` writes these bindings with the pinned wit-bindgen CLI.
include!("../generated/community_plugin.rs");

use exports::pigloros::plugin::guest_v1::Guest;
use pigloros::plugin::contract_v1::{
    BoundedText, Digest32, EventDraft, MigrationOutput, MigrationRequest, PluginDescriptor,
    PluginError, PluginErrorCode, PluginInvocation, PluginOutput,
};
use pigloros::plugin::host_v1;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const RANDOM_BYTES: u32 = 16;
const TRAP_OBSERVATION: &[u8] = b"trap";

struct Prototype;

fn text(value: &str) -> BoundedText {
    BoundedText {
        utf8: value.as_bytes().to_vec(),
    }
}

fn filled_digest(byte: u8) -> Digest32 {
    Digest32 {
        value: vec![byte; 32],
    }
}

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn invoke(
    input: PluginInvocation,
    log_message: &str,
    event_type: &str,
) -> Result<PluginOutput, PluginError> {
    if input.observation_bytes == TRAP_OBSERVATION {
        host_v1::record_operational_log(2, &text("trapping"))?;
        core::arch::wasm32::unreachable();
    }
    let now = host_v1::simulation_time();
    let random = host_v1::deterministic_random(
        &input.deterministic_random_domain,
        input.timeline_position.seq,
        RANDOM_BYTES,
    )?;
    host_v1::record_operational_log(1, &text(log_message))?;
    let mut hash = fnv1a(FNV_OFFSET, &input.prior_state_bytes);
    hash = fnv1a(hash, &input.observation_bytes);
    hash = fnv1a(hash, &now.to_le_bytes());
    hash = fnv1a(hash, &random);
    let state = hash.to_le_bytes().to_vec();
    Ok(PluginOutput {
        invocation_id: input.invocation_id.clone(),
        event_drafts: vec![EventDraft {
            event_schema_id: 1,
            entity_id: input.invocation_id,
            event_type: text(event_type),
            canonical_payload: state.clone(),
            dependency_digests: Vec::new(),
        }],
        next_state_schema: input.prior_state_schema,
        next_state_bytes: state.clone(),
        trace_annotations: Vec::new(),
        consumed_dependencies: Vec::new(),
        output_digest: Digest32 {
            value: state.repeat(4),
        },
    })
}

impl Guest for Prototype {
    fn describe() -> Result<PluginDescriptor, PluginError> {
        Ok(PluginDescriptor {
            plugin_id: text("pigloros.compatibility-prototype"),
            release_semver: text("0.1.0"),
            world: text("pigloros:plugin/community-plugin@0.1.0"),
            abi_major: 0,
            min_abi_minor: 1,
            max_abi_minor: 1,
            required_features: Vec::new(),
            event_schema_digests: vec![filled_digest(1)],
            state_schema_digest: filled_digest(2),
            capabilities: Vec::new(),
            migrations: Vec::new(),
            dependencies: Vec::new(),
            manifest_digest: filled_digest(0),
            release_digest: filled_digest(0),
        })
    }

    fn reduce(input: PluginInvocation) -> Result<PluginOutput, PluginError> {
        invoke(input, "reduce", "prototype.reduced")
    }

    fn drive(input: PluginInvocation) -> Result<PluginOutput, PluginError> {
        invoke(input, "drive", "prototype.driven")
    }

    fn migrate_state(_input: MigrationRequest) -> Result<MigrationOutput, PluginError> {
        Err(PluginError {
            code: PluginErrorCode::GuestDeclaredFailure(1),
            canonical_coordinate: None,
            related_digest: None,
        })
    }
}

export!(Prototype);
