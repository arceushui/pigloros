//! Exact retained CNT1; a tuple comparison never authenticates a release/owner.

use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMemberBindingInputV1, CommunityMemberBindingV1,
};
use pos_core::{Hash, ImplementationKeyV1};
use pos_crypto::plugin_execution::{
    is_valid_id_v1, DeterministicBudgetV1, PluginCapabilityDescriptorV1,
};
use zeroize::Zeroizing;

use super::profile::write_profile_body;
use super::{
    cbor, CommunityPluginExecutionProfileV1, CommunityPluginModeV1, NegotiatedCommunityPluginV1,
    PinnedComponentRuntimeV1,
};

type Result<T> = std::result::Result<T, Error>;
const MAX_RECORD: usize = 1_048_576;
const MAX_ROWS: usize = 256;
const MAX_LABEL: usize = 128;

// Maximum permitted strings, numeric widths, array heads and fixed fields fit
// before writing. Each buffer reserves its full row-count bound before copies.
const _: () = assert!(
    1024 + MAX_ROWS * (512 + 4 * 128 + 3 * 9 + 32)
        + MAX_ROWS * 137
        + MAX_ROWS * 137
        + MAX_ROWS * (2 * 137 + 3)
        < MAX_RECORD
);

/// CNT1 bound to an actual negotiated tuple and its exact recorded profile.
///
/// Runtime metadata is privately staged without a permissive second serializer.
/// This type is data, not release trust, current admission or a guest permit.
pub struct CommunityNegotiatedTupleV1<'a> {
    negotiated: &'a NegotiatedCommunityPluginV1,
    profile_body: Zeroizing<Vec<u8>>,
}

impl<'a> CommunityNegotiatedTupleV1<'a> {
    /// Validate retained-format bounds and exact mode/runtime/profile identity.
    ///
    /// # Errors
    /// Rejects absent/foreign runtime/profile, zero release identities and
    /// unsupported larger metadata. Negotiation's actual PMF1/clamping and
    /// release/current-authority verification remain independently required.
    pub fn new(
        negotiated: &'a NegotiatedCommunityPluginV1,
        profile: &CommunityPluginExecutionProfileV1,
    ) -> Result<Self> {
        profile
            .runtime()
            .ok_or(Error::InvalidBinding)
            .and_then(|runtime| {
                validate_bounds(negotiated, runtime).and_then(|()| {
                    if negotiated.mode() != profile.mode()
                        || negotiated.pmf1_digest() == [0; 32]
                        || negotiated.release_digest() == [0; 32]
                        || !ordered_capabilities(negotiated.not_granted_capabilities())
                    {
                        return Err(Error::InvalidBinding);
                    }
                    let capacity = 1024
                        + 64
                        + runtime.resolved_features().len() * (MAX_LABEL + 9)
                        + runtime.trap_table().len() * (2 * MAX_LABEL + 27);
                    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
                    write_profile_body(&mut body, profile.ceilings().values(), runtime);
                    let profile_digest = profile_body_digest(&body);
                    if negotiated.execution_profile_digest() == Some(*profile_digest.as_bytes()) {
                        Ok(Self {
                            negotiated,
                            profile_body: body,
                        })
                    } else {
                        Err(Error::InvalidBinding)
                    }
                })
            })
    }

    /// Borrow the original tuple; no cloned capabilities/features are created.
    #[must_use]
    pub const fn negotiated(&self) -> &'a NegotiatedCommunityPluginV1 {
        self.negotiated
    }

    /// Bind the exact installed implementation to this complete retained CNT1.
    ///
    /// PMF1 and tuple identities are derived from actual negotiated data; callers
    /// cannot substitute their hashes. State/initializer/owner arguments remain
    /// data until the qualified owner verifies the admitted release/generation.
    ///
    /// # Errors
    /// Rejects a foreign Plugin ID/release, invalid stable entry or zero required
    /// identity. This does not install or authorize a new member/generation.
    pub fn member_binding<'binding>(
        &self,
        stable_entry: &'binding str,
        implementation: &'binding ImplementationKeyV1,
        state_schema_digest: Hash,
        initial_state_content_digest: Hash,
        protected_owner_binding_digest: Hash,
    ) -> Result<CommunityMemberBindingV1<'binding>> {
        if implementation.plugin_id() != self.negotiated.plugin_id()
            || implementation.release_digest().as_bytes() != &self.negotiated.release_digest()
        {
            return Err(Error::InvalidBinding);
        }
        CommunityMemberBindingV1::new(CommunityMemberBindingInputV1 {
            stable_entry,
            implementation,
            pmf1_digest: Hash::from_bytes(self.negotiated.pmf1_digest()),
            state_schema_digest,
            negotiated_tuple_digest: self.digest(),
            initial_state_content_digest,
            protected_owner_binding_digest,
        })
    }

    /// Encode exact16-field CNT1 with all eight limits and explicit live mode.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let tuple = self.negotiated;
        let capacity = 1024
            + self.profile_body.len()
            + tuple.required_features().len() * (MAX_LABEL + 9)
            + tuple.not_granted_capabilities().len() * (512 + 4 * MAX_LABEL + 3 * 9 + 32);
        let mut out = Zeroizing::new(Vec::with_capacity(capacity));
        cbor::array(&mut out, 16);
        cbor::bytes(&mut out, b"CNT1");
        cbor::unsigned(&mut out, 1);
        cbor::text(&mut out, tuple.world());
        cbor::text(&mut out, tuple.plugin_id());
        cbor::bytes(&mut out, &tuple.pmf1_digest());
        cbor::bytes(&mut out, &tuple.release_digest());
        let (major, minor) = tuple.abi();
        let (minimum, maximum) = tuple.declared_minor_range();
        for value in [major, minor, minimum, maximum] {
            cbor::unsigned(&mut out, u64::from(value));
        }
        cbor::array(&mut out, tuple.required_features().len());
        for feature in tuple.required_features() {
            cbor::text(&mut out, feature);
        }
        cbor::array(&mut out, tuple.not_granted_capabilities().len());
        for capability in tuple.not_granted_capabilities() {
            encode_capability(&mut out, capability);
        }
        cbor::unsigned(
            &mut out,
            match tuple.mode() {
                CommunityPluginModeV1::Local => 0,
                CommunityPluginModeV1::AirGapped => 1,
            },
        );
        let limits = tuple.limits().values();
        cbor::array(&mut out, 8);
        for limit in [
            limits.memory_bytes,
            limits.fuel,
            limits.host_calls,
            limits.event_count,
            limits.event_bytes,
            limits.state_bytes,
            limits.log_calls,
            limits.log_bytes,
        ] {
            cbor::unsigned(&mut out, limit);
        }
        cbor::bytes(&mut out, &self.profile_body);
        // Constructor checked Some and its exact preimage; derive from retained
        // bytes directly rather than inventing a zero for an absent digest.
        cbor::bytes(&mut out, profile_body_digest(&self.profile_body).as_bytes());
        out
    }

    /// Protected logical CNT1 identity, including mode excluded by profile hash.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let bytes = self.to_canonical_cbor();
        let mut hasher = Zeroizing::new(blake3::Hasher::new());
        hasher.update(b"PiglorOS.Community.CNT1.v1\0");
        hasher.update(&bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Compare retained bytes to the actual reconstructed tuple/profile.
    ///
    /// The owner reconstructs the recorded PMF1/profile, never a current default
    /// substituted for historical execution. This does not deserialize a new
    /// worker profile or accept claimed effective limits from wire bytes.
    ///
    /// # Errors
    /// Rejects oversized bytes, invalid expected metadata and any exact-byte
    /// mismatch, including nonpreferred/unknown/trailing/omitted fields.
    pub fn validate_canonical_cbor(
        bytes: &[u8],
        negotiated: &'a NegotiatedCommunityPluginV1,
        profile: &CommunityPluginExecutionProfileV1,
    ) -> Result<Self> {
        if bytes.len() > MAX_RECORD {
            return Err(Error::BoundsExceeded);
        }
        Self::new(negotiated, profile).and_then(|record| {
            if bytes == record.to_canonical_cbor().as_slice() {
                Ok(record)
            } else {
                Err(Error::InvalidBinding)
            }
        })
    }
}

fn profile_body_digest(body: &[u8]) -> Hash {
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    hasher.update(b"PiglorOS.Plugin.ExecutionProfile.v1\0");
    hasher.update(&cbor::length(body.len()).to_be_bytes());
    hasher.update(body);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn validate_bounds(
    tuple: &NegotiatedCommunityPluginV1,
    runtime: &PinnedComponentRuntimeV1,
) -> Result<()> {
    if !bounded_text(runtime.wasmtime_version(), 64)
        || runtime.resolved_features().len() > MAX_ROWS
        || runtime.trap_table().len() > MAX_ROWS
        || runtime
            .resolved_features()
            .iter()
            .any(|text| !bounded_text(text, MAX_LABEL))
        || runtime
            .trap_table()
            .iter()
            .any(|row| !bounded_text(&row.trap_code, MAX_LABEL))
        || tuple.required_features().len() > MAX_ROWS
        || tuple
            .not_granted_capabilities()
            .iter()
            .any(|capability| !valid_capability(capability))
    {
        Err(Error::BoundsExceeded)
    } else {
        Ok(())
    }
}

fn valid_capability(capability: &PluginCapabilityDescriptorV1) -> bool {
    is_valid_id_v1(&capability.capability_id)
        && is_valid_id_v1(&capability.operation)
        && valid_label(&capability.resource_pattern, 512)
        && valid_label(&capability.purpose, MAX_LABEL)
        && valid_label(&capability.audience, MAX_LABEL)
        && capability.max_calls <= DeterministicBudgetV1::MAXIMA.host_calls
        && capability.max_request_bytes <= DeterministicBudgetV1::MAXIMA.event_bytes
        && capability.max_response_bytes <= DeterministicBudgetV1::MAXIMA.event_bytes
}

fn valid_label(text: &str, maximum: usize) -> bool {
    bounded_text(text, maximum) && !text.chars().any(char::is_control)
}

type CapabilityKey<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str);

fn capability_key(capability: &PluginCapabilityDescriptorV1) -> CapabilityKey<'_> {
    (
        &capability.capability_id,
        &capability.operation,
        &capability.resource_pattern,
        &capability.purpose,
        &capability.audience,
    )
}

fn ordered_capabilities(capabilities: &[PluginCapabilityDescriptorV1]) -> bool {
    capabilities
        .windows(2)
        .all(|pair| capability_key(&pair[0]) < capability_key(&pair[1]))
}

const fn bounded_text(text: &str, maximum: usize) -> bool {
    !text.is_empty() && text.len() <= maximum
}

fn encode_capability(out: &mut Vec<u8>, capability: &PluginCapabilityDescriptorV1) {
    cbor::array(out, 9);
    for text in [
        &capability.capability_id,
        &capability.operation,
        &capability.resource_pattern,
        &capability.purpose,
        &capability.audience,
    ] {
        cbor::text(out, text);
    }
    cbor::boolean(out, capability.required);
    for value in [
        capability.max_calls,
        capability.max_request_bytes,
        capability.max_response_bytes,
    ] {
        cbor::unsigned(out, value);
    }
}
