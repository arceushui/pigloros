//! A Reserve that publishes its records, then an Abort of that pass: the
//! contract between the Reserve's key provisioning and the authenticated
//! Abort (#560 A4c-3c-ii, A4e-2a): the Abort finds the pass metadata key
//! open, copies the CPR1 the Reserve sealed, and leaves the failure cohort
//! key it only uses.

use pos_core::community_lifecycle::{
    CommunityAbortReasonV1, CommunityAbortV1, CommunityLifecycleErrorV1 as Error,
    CommunityMetadataSchemaV1, CommunityReservationV1,
};

use super::{
    publication, snapshot, target, Case, Fallible, Roster, TestResult, FAILURE, HORIZON, METADATA,
    OPERATION, SEAL,
};
use crate::community::private_hash::private_digest;
use crate::community::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1, CommunityPassAbortCallV1,
    CommunityPassAbortReceiptV1, CommunityPassStatusV1,
};
use crate::community_initialization_fixture::DATA_LEAF;

/// The authenticated Abort of reason 0 on the pass `OPERATION`, over the
/// CDP1 and policy the Reserve was published under.
fn abort(case: &mut Case<'_>) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
    let request =
        CommunityAdministrativeRequestV1::derive(&CommunityAdministrativeOperationV1::PassAbort {
            timeline: target(),
            reservation_operation_id: OPERATION,
        })?;
    let credential = case.domain.world.credential(request)?;
    let context = publication(&case.profile, &case.policy).context;
    let world = &mut case.domain.world;
    Ok(world.domain.abort_pass(
        &SEAL,
        context,
        &mut world.authority,
        &mut case.domain.metadata,
        CommunityPassAbortCallV1 {
            credential: &credential,
            timeline: target(),
            reservation_operation_id: OPERATION,
            reason: CommunityAbortReasonV1::AuthenticatedCancellation,
            administrative_leaf: DATA_LEAF,
        },
    ))
}

/// Whether the key `id` still seals one probe record under the pass metadata
/// cover: a closed key refuses.
fn seals(case: &mut Case<'_>, id: [u8; 16]) -> Fallible<bool> {
    let domain = &mut case.domain.world.domain;
    let generation = domain.pass_states.get(&target()).ok_or("state")?.generation;
    let scope = super::super::reserve_scope(
        domain.store_incarnation,
        (target(), generation),
        domain.keys.get(&METADATA).ok_or("metadata key")?,
        HORIZON,
    )?;
    Ok(domain
        .keys
        .get_mut(&id)
        .ok_or("key")?
        .seal(&scope, CommunityMetadataSchemaV1::Cab1, b"probe")
        .is_ok())
}

/// What a refused Abort must leave alone besides the Reserve's snapshot: the
/// committed Aborts and the credits each pass key has burned.
fn abort_snapshot(case: &Case<'_>) -> Fallible<(usize, [u32; 2])> {
    let domain = &case.domain.world.domain;
    let credits = |id: [u8; 16]| Ok::<_, &str>(domain.keys.get(&id).ok_or("key")?.burned_credits());
    Ok((
        domain.pass_aborts.len(),
        [credits(METADATA)?, credits(FAILURE)?],
    ))
}

/// A published Reserve is aborted only once its `run_pass` call has ended
/// (15 while it is live); the Abort then commits against the keys and
/// records the Reserve left, and a retry returns the original receipt.
#[test]
fn a_published_reserve_is_aborted_once_its_call_ended() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let mut case = Case::new(&roster, &rows)?;
    let staged = case.stage(OPERATION)?;
    let reservation = CommunityReservationV1::new(staged.record.reserved.reservation)?;
    let pass_key = staged.record.reserved.reservation.pass_key;
    let publication = publication(&case.profile, &case.policy);
    case.domain
        .world
        .domain
        .publish_reserved_pass(&SEAL, staged, publication)?;

    // The call that reserved the pass is live: the Abort is refused and
    // changes nothing.
    assert!(case.domain.world.domain.pass_is_live(target(), OPERATION));
    let before = (snapshot(&case.domain.world.domain), abort_snapshot(&case)?);
    assert_eq!(abort(&mut case)?.err(), Some(Error::OperationActive));
    assert_eq!(
        (snapshot(&case.domain.world.domain), abort_snapshot(&case)?),
        before
    );
    assert_eq!(
        case.domain.world.domain.pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Reserved)
    );
    assert!(seals(&mut case, METADATA)?);

    case.domain
        .world
        .domain
        .end_live_call(&SEAL, target(), OPERATION);
    let receipt = abort(&mut case)??;

    // The CAB1 copies the CPR1 the Reserve sealed.
    let original = case
        .domain
        .world
        .domain
        .original_reserve(target(), OPERATION)?;
    assert_eq!(
        original.reservation(),
        reservation.to_canonical_cbor().as_slice()
    );
    let abort_record = CommunityAbortV1::from_canonical_cbor(receipt.abort())?;
    let fields = abort_record.as_input();
    assert!(fields.pass_key == pass_key);
    assert_eq!(fields.reservation_digest, reservation.digest());
    assert_eq!(
        fields.evidence_not_after_micros,
        reservation.as_input().evidence_not_after_micros
    );
    assert_eq!(fields.sealed_result_digest, None);
    assert!(matches!(
        fields.reason,
        CommunityAbortReasonV1::AuthenticatedCancellation
    ));

    // The pass is Aborted, its pending entry gone, its floor kept.
    let domain = &case.domain.world.domain;
    assert_eq!(
        domain.pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Aborted)
    );
    assert!(!domain
        .pending_reservations
        .contains_key(&(target(), OPERATION)));
    assert_eq!(
        domain
            .pass_states
            .get(&target())
            .ok_or("state")?
            .highest_pass_ordinal,
        1
    );
    assert_eq!(pass_key.ordinal(), 1);

    // The Abort closes the pass metadata key, and only uses the failure
    // cohort key, which the Reserve left open.
    assert!(!seals(&mut case, METADATA)?);
    assert!(seals(&mut case, FAILURE)?);

    // The Reserve's records still open after the Abort closed their key.
    let after = case
        .domain
        .world
        .domain
        .original_reserve(target(), OPERATION)?;
    assert_eq!(after.request(), original.request());

    // A retry returns the original receipt.
    let retry = abort(&mut case)??;
    assert_eq!(retry.abort_digest(), receipt.abort_digest());
    assert_eq!(retry.abort(), receipt.abort());
    assert_eq!(
        private_digest(b"PiglorOS.Community.CAB1.v1", &[receipt.abort()]),
        receipt.abort_digest()
    );
    Ok(())
}
