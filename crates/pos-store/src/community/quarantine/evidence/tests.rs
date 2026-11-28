//! The CAV1 of a `SetReason` (I235, ADR-129 R16.5(4)): its head ref is the
//! CMI1 reference of the first roster member's selected CSR1.

use pos_core::community_lifecycle::{
    CommunityCurrentViewV1, CommunityPassFrontierV1, RevocationBasisV1 as Basis,
};
use pos_core::AuthorityTrustRootSealV1;

use super::super::check_shape;
use crate::community::current_view_head::tests::state_revisions;
use crate::community_initialization_fixture::{
    claim, hash, profile_until, with_set_reason, Fallible, QuarantineCase, Revocation, Roster,
    HORIZON,
};
use crate::plugin_trust_registry_fixtures::release_one;

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

/// The CAV1 the `SetReason` reads inside its guard, over no key rows, the
/// call's steps before the writer, and the independent rebuild of the head
/// ref from T's sealed initialization records.
#[test]
fn a_set_reason_states_the_first_members_state_revision() -> Fallible<()> {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let refs = state_revisions(&case.domain.world.domain)?;
    assert_eq!(refs.len(), 2);
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let view: CommunityCurrentViewV1 = with_set_reason(
        &SEAL,
        &mut case,
        &profile,
        &release_one(),
        claim(Basis::Artifact),
        |world, metadata, context, call| -> Fallible<CommunityCurrentViewV1> {
            let key = check_shape(&call)?;
            let reservation = world.authority.reserve_control(&mut world.domain)?;
            let write = world
                .domain
                .metadata_write(context, &reservation, metadata)?;
            let operation =
                world
                    .domain
                    .operation(&world.authority, context, call, (key, write))?;
            let inventory = world.domain.inventory_generation;
            Ok(world
                .domain
                .view(&world.authority, &operation, &[], inventory)?)
        },
    )??;
    let read = view.as_input();
    assert!(matches!(read.frontier, CommunityPassFrontierV1::Initial));
    assert!(read.selected_head == Some(refs[0]));
    assert_eq!(read.authority_rows.len(), 1);
    assert!(read.scope_rows.is_empty());
    Ok(())
}
