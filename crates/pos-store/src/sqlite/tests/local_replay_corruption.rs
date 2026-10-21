//! Independently durable classifier facts must agree before any suffix escapes.

use super::*;
use crate::ForkEventPermitIssuerPortV1;

#[derive(Clone, Copy, Debug)]
enum ClassifierBindingFault {
    TableAdmissionDigest,
    SourceRoom,
    SourceRegistrar,
    Routes,
    RegistrationChild,
}

#[test]
fn local_permit_issuer_refuses_independent_classifier_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let (store, mut session, fork, source) = classified_registration_fixture()?;
    store.register_fork_classifier_in_transaction(
        &session,
        Hash::from_bytes([79; 32]),
        fork.child_id,
        fork.admission_digest,
        &source,
    )?;
    let issuer = session.take_event_permit_issuer().ok_or("event issuer")?;
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
    for fault in [
        ClassifierBindingFault::TableAdmissionDigest,
        ClassifierBindingFault::SourceRoom,
        ClassifierBindingFault::SourceRegistrar,
        ClassifierBindingFault::Routes,
        ClassifierBindingFault::RegistrationChild,
    ] {
        assert_eq!(
            store
                .issue_append_source_permit(
                    &issuer,
                    &session,
                    fork.child_id,
                    &source,
                    ForkAppendSourceIdentityV1::HostInternal,
                )?
                .child_timeline_id(),
            fork.child_id,
        );
        let mut source_input = source.input().clone();
        let mut table_input = table.input().clone();
        let mut registration_input = registration.input().clone();
        let foreign = Hash::from_bytes([0x98; 32]);
        match fault {
            ClassifierBindingFault::TableAdmissionDigest => {
                table_input.fork_admission_digest = foreign;
            }
            ClassifierBindingFault::SourceRoom => {
                source_input.room_revision_descriptor_hash = foreign;
            }
            ClassifierBindingFault::SourceRegistrar => {
                source_input.registrar_identifier.push_str("-foreign");
            }
            ClassifierBindingFault::Routes => {
                table_input.routes = vec![pos_core::ForkExternalInputRouteV1::new(
                    pos_core::ForkEventSourceDescriptorV1::new("foreign-route", foreign)?,
                    false,
                )];
            }
            ClassifierBindingFault::RegistrationChild => {
                registration_input.child_timeline_id = TimelineId::new();
                assert_ne!(registration_input.child_timeline_id, fork.child_id);
            }
        }
        // Corrupt durable bytes, not a legal registration transition. Keep
        // both digest links exact so an incidental digest mismatch cannot
        // conceal the independent admission/source/route/child binding under test.
        let changed_source = ForkClassifierSourceV1::new(source_input)?;
        table_input.source_configuration_revision_digest = changed_source.digest();
        let changed_table = ForkClassifierTableV1::new(table_input)?;
        registration_input.classifier_revision_digest = changed_table.digest();
        let changed_registration = ForkClassifierRegistrationV1::new(registration_input)?;
        replace_classifier_records(
            &store,
            &changed_source,
            &changed_table,
            &changed_registration,
        )?;
        assert_eq!(
            store
                .issue_append_source_permit(
                    &issuer,
                    &session,
                    fork.child_id,
                    &changed_source,
                    ForkAppendSourceIdentityV1::HostInternal,
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::CorruptAuthority),
            "accepted classifier binding {fault:?}",
        );
        replace_classifier_records(&store, &source, &table, &registration)?;
    }
    assert!(store
        .issue_append_source_permit(
            &issuer,
            &session,
            fork.child_id,
            &source,
            ForkAppendSourceIdentityV1::HostInternal,
        )
        .is_ok());
    Ok(())
}

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
