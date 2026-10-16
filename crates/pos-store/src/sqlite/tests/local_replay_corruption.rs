//! Independently durable classifier facts must agree before any suffix escapes.

use super::*;
use crate::ForkEventPermitIssuerPortV1;

#[test]
fn local_suffix_refuses_cross_record_classifier_mismatches(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut store, mut session, fork, source) = classified_registration_fixture()?;
    store.register_fork_classifier_in_transaction(
        &session,
        Hash::from_bytes([77; 32]),
        fork.child_id,
        fork.admission_digest,
        &source,
    )?;
    let issuer = session.take_event_permit_issuer().ok_or("event issuer")?;
    let permit = store.issue_append_source_permit(
        &issuer,
        &session,
        fork.child_id,
        &source,
        ForkAppendSourceIdentityV1::HostInternal,
    )?;
    store.append_classified(
        &session,
        &permit,
        Hash::from_bytes([78; 32]),
        make_draft(EntityId::new(), b"local classifier corruption control"),
    )?;
    let original = store.read_fork_event_suffix(fork.child_id, 1)?;
    assert_eq!(original.len(), 1);
    let table = fork_replay_classifier::classifier_table_with_context(
        &store.conn,
        fork.child_id,
        &mut crate::fork_replay::NativeReadContextV1::ordinary(),
    )?;
    let registration = fork_replay_classifier::classifier_registration_with_context(
        &store.conn,
        fork.child_id,
        &mut crate::fork_replay::NativeReadContextV1::ordinary(),
    )?;
    for fault in 0..3 {
        let foreign = Hash::from_bytes([0x97; 32]);
        if fault == 2 {
            let mut input = registration.input().clone();
            input.fork_admission_digest = foreign;
            let changed = ForkClassifierRegistrationV1::new(input)?;
            assert_eq!(
                store.conn.execute(
                    "UPDATE fork_classifier_registrations SET fcr1_cbor=?1 WHERE child_id=?2",
                    params![changed.to_canonical_cbor(), fork.child_id.to_string()],
                )?,
                1
            );
        } else {
            let mut input = table.input().clone();
            if fault == 0 {
                input.fork_admission_digest = foreign;
            } else {
                input.source_configuration_revision_digest = foreign;
            }
            let changed = ForkClassifierTableV1::new(input)?;
            assert_eq!(
                store.conn.execute(
                    "UPDATE fork_classifier_tables SET fct1_cbor=?1 WHERE child_id=?2",
                    params![changed.to_canonical_cbor(), fork.child_id.to_string()],
                )?,
                1
            );
        }
        assert_eq!(
            store.read_fork_event_suffix(fork.child_id, 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority),
            "accepted classifier mismatch {fault}"
        );
        store.conn.execute(
            "UPDATE fork_classifier_tables SET fct1_cbor=?1 WHERE child_id=?2",
            params![table.to_canonical_cbor(), fork.child_id.to_string()],
        )?;
        store.conn.execute(
            "UPDATE fork_classifier_registrations SET fcr1_cbor=?1 WHERE child_id=?2",
            params![registration.to_canonical_cbor(), fork.child_id.to_string()],
        )?;
        assert_eq!(store.read_fork_event_suffix(fork.child_id, 1)?, original);
    }
    Ok(())
}
