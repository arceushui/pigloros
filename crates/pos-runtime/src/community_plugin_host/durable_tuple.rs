//! Exact retained CNT1; a tuple comparison never authenticates a release/owner.

use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityLifecycleErrorV1 as Error, CommunityMemberBindingInputV1,
    CommunityMemberBindingV1, CommunityProfileMemberV1,
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

// The largest valid record fits the retained-format limit. Private staging uses
// a counting pass of the actual encoder, rather than this conservative bound.
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
                    let body = cbor::encode_zeroizing(|out| {
                        write_profile_body(out, profile.ceilings().values(), runtime);
                    });
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
        self.require_implementation(implementation).and_then(|()| {
            CommunityMemberBindingV1::new(CommunityMemberBindingInputV1 {
                stable_entry,
                implementation,
                pmf1_digest: Hash::from_bytes(self.negotiated.pmf1_digest()),
                state_schema_digest,
                negotiated_tuple_digest: self.digest(),
                initial_state_content_digest,
                protected_owner_binding_digest,
            })
        })
    }

    /// Build the profile's cycle-free roster policy from the actual full CNT1.
    ///
    /// This row excludes the later CMB1/COB1 identities. The installed owner
    /// still verifies the actual State schema and admitted initializer source.
    ///
    /// # Errors
    /// Rejects a foreign implementation, invalid entry or zero required identity.
    pub fn profile_member<'binding>(
        &self,
        stable_entry: &'binding str,
        implementation: &'binding ImplementationKeyV1,
        state_schema_digest: Hash,
        initializer: ArtifactRefV1,
    ) -> Result<CommunityProfileMemberV1<'binding>> {
        self.require_implementation(implementation).and_then(|()| {
            CommunityProfileMemberV1::new(
                stable_entry,
                implementation,
                Hash::from_bytes(self.negotiated.pmf1_digest()),
                state_schema_digest,
                self.digest(),
                initializer,
            )
        })
    }

    fn require_implementation(&self, implementation: &ImplementationKeyV1) -> Result<()> {
        if implementation.plugin_id() != self.negotiated.plugin_id()
            || implementation.release_digest().as_bytes() != &self.negotiated.release_digest()
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(())
        }
    }

    /// Encode exact 16-field CNT1 with all eight limits and explicit live mode.
    /// Count the same immutable record first so private copies never need a
    /// growing allocation, without reserving unrelated maximum-size metadata.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let profile_digest = profile_body_digest(&self.profile_body);
        cbor::encode_zeroizing(|out| self.write_canonical(out, profile_digest))
    }

    fn write_canonical(&self, out: &mut cbor::Encoder<'_>, profile_digest: Hash) {
        let tuple = self.negotiated;
        out.array(16);
        out.bytes(b"CNT1");
        out.unsigned(1);
        out.text(tuple.world());
        out.text(tuple.plugin_id());
        out.bytes(&tuple.pmf1_digest());
        out.bytes(&tuple.release_digest());
        let (major, minor) = tuple.abi();
        let (minimum, maximum) = tuple.declared_minor_range();
        for value in [major, minor, minimum, maximum] {
            out.unsigned(u64::from(value));
        }
        out.array(tuple.required_features().len());
        for feature in tuple.required_features() {
            out.text(feature);
        }
        out.array(tuple.not_granted_capabilities().len());
        for capability in tuple.not_granted_capabilities() {
            encode_capability(out, capability);
        }
        out.unsigned(match tuple.mode() {
            CommunityPluginModeV1::Local => 0,
            CommunityPluginModeV1::AirGapped => 1,
        });
        let limits = tuple.limits().values();
        out.array(8);
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
            out.unsigned(limit);
        }
        out.bytes(&self.profile_body);
        // Constructor checked Some and its exact preimage; derive from retained
        // bytes directly rather than inventing a zero for an absent digest.
        out.bytes(profile_digest.as_bytes());
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

fn encode_capability(out: &mut cbor::Encoder<'_>, capability: &PluginCapabilityDescriptorV1) {
    out.array(9);
    for text in [
        &capability.capability_id,
        &capability.operation,
        &capability.resource_pattern,
        &capability.purpose,
        &capability.audience,
    ] {
        out.text(text);
    }
    out.boolean(capability.required);
    for value in [
        capability.max_calls,
        capability.max_request_bytes,
        capability.max_response_bytes,
    ] {
        out.unsigned(value);
    }
}
