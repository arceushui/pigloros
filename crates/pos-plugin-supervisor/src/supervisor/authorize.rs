//! The launch refusals that precede every worker (ADR-061 revision 7 decisions 3 and 8).
//!
//! The numbering follows decision 3: refusal 1 is a missing or closed-pass authorization,
//! refusal 2 an authorization for another release or other Component bytes, and refusal 3 an
//! invalid or unbound invocation.
//!
//! The authorization is taken by value and dropped here once it has been checked: it is
//! consumed by exactly one launch whether or not the launch is refused.

use pos_crypto::plugin_manifest::component_digest_v1;
use pos_runtime::community_plugin_host::{
    CommunityPassAuthorizationV1, CommunityPluginHostErrorV1, NegotiatedCommunityPluginV1,
    PluginInvocationV1,
};

use super::{NOT_ACTIVE, UNAVAILABLE};

type Error = CommunityPluginHostErrorV1;

/// Refusals 1 and 2 of decision 3, the only ones `describe` has.
pub(super) fn check_describe(
    authorization: Option<CommunityPassAuthorizationV1>,
    negotiated: &NegotiatedCommunityPluginV1,
    component: &[u8],
) -> Result<(), Error> {
    authorize(authorization, negotiated, component).map(drop)
}

/// Refusals 1 and 2 of decision 3, then the shape of the invocation and its bindings (refusal 3).
pub(super) fn check_invocation(
    authorization: Option<CommunityPassAuthorizationV1>,
    negotiated: &NegotiatedCommunityPluginV1,
    component: &[u8],
    invocation: &PluginInvocationV1,
) -> Result<(), Error> {
    let authorization = authorize(authorization, negotiated, component)?;
    invocation.validate()?;
    require_bindings(&authorization, negotiated, invocation)
}

/// An authorization that exists, belongs to an open pass, and names this Driver's release and
/// the Component bytes it holds.
fn authorize(
    authorization: Option<CommunityPassAuthorizationV1>,
    negotiated: &NegotiatedCommunityPluginV1,
    component: &[u8],
) -> Result<CommunityPassAuthorizationV1, Error> {
    let authorization = authorization
        .filter(CommunityPassAuthorizationV1::is_pass_open)
        .ok_or(UNAVAILABLE)?;
    let identical = authorization.plugin_id() == negotiated.plugin_id()
        && authorization.pmf1_digest() == negotiated.pmf1_digest()
        && authorization.release_digest() == negotiated.release_digest()
        && authorization.component_digest() == component_digest_v1(component);
    identical.then_some(authorization).ok_or(NOT_ACTIVE)
}

/// The invocation carries the pass Tick, the authenticated TPS1 digest and the negotiated
/// record's profile digest (a record without one binds nothing).
fn require_bindings(
    authorization: &CommunityPassAuthorizationV1,
    negotiated: &NegotiatedCommunityPluginV1,
    invocation: &PluginInvocationV1,
) -> Result<(), Error> {
    let bound = invocation.timeline_position.tick == authorization.tick()
        && invocation.trust_policy_snapshot_digest == authorization.tps1_digest()
        && negotiated.execution_profile_digest() == Some(invocation.execution_profile_digest);
    bound.then_some(()).ok_or(Error::InvalidInvocation)
}
