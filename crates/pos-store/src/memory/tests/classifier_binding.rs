//! Private graph corruption observed through the public suffix-read port.
//!
//! These inconsistent bindings cannot be created by public registration. They
//! are not legal append transitions or authenticated imported Fork fixtures.

use super::classified_suffix_store;
use crate::{ForkEventAuthorityErrorV1, ForkEventProvenanceAuthorityPortV1};
use pos_core::{
    ForkAppendOperationV1, ForkAppendSourceIdentityV1, ForkClassifierRegistrationV1,
    ForkClassifierSourceV1, ForkClassifierTableV1, ForkEventClassifierV1, ForkEventOriginKindV1,
    ForkEventProvenanceErrorV1, ForkEventSourceDescriptorV1, ForkExternalInputRouteV1, Hash,
};
use std::error::Error;

#[test]
fn classified_suffix_requires_the_bound_event_origin() -> Result<(), Box<dyn Error>> {
    let (mut store, child, _, event) = classified_suffix_store()?;
    let before = store.read_fork_event_suffix(child, 1)?;
    assert_eq!(before.len(), 1);
    // An absent origin is not an orphan row: the anchor scan has nothing to
    // inspect, so the per-Event provenance lookup must independently refuse.
    let origin = store
        .fork_event_origins
        .remove(&event.id)
        .ok_or("missing fixture EOR1")?;
    assert_eq!(
        store.read_fork_event_suffix(child, 1),
        Err(ForkEventAuthorityErrorV1::CorruptAuthority),
    );
    store.fork_event_origins.insert(event.id, origin);
    assert_eq!(store.read_fork_event_suffix(child, 1)?, before);
    Ok(())
}

#[test]
fn classified_suffix_requires_the_operation_source_in_the_retained_table(
) -> Result<(), Box<dyn Error>> {
    let (mut store, child, operation, _) = classified_suffix_store()?;
    let before = store.read_fork_event_suffix(child, 1)?;
    assert_eq!(before.len(), 1);
    let mut input = operation.input().clone();
    input.source = ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: "foreign-adapter".to_owned(),
        source: ForkEventSourceDescriptorV1::new("foreign-route", Hash::from_bytes([0xe2; 32]))?,
    };
    let table = store
        .fork_classifier_tables
        .get(&child)
        .ok_or("fixture FCT1")?;
    assert_eq!(
        ForkEventClassifierV1::from_table(table).classify_identity(&input.source),
        Err(ForkEventProvenanceErrorV1::SourceRejected),
    );
    let altered = ForkAppendOperationV1::new(input)?;
    assert_eq!(
        store
            .fork_append_operations
            .insert(operation.input().operation_id, altered),
        Some(operation.clone()),
    );
    // Keep every Event, graph digest, origin and operation key unchanged.
    // Only membership of the retained source in the valid table is broken.
    assert_eq!(
        store.read_fork_event_suffix(child, 1),
        Err(ForkEventAuthorityErrorV1::CorruptAuthority),
    );
    store
        .fork_append_operations
        .insert(operation.input().operation_id, operation);
    assert_eq!(store.read_fork_event_suffix(child, 1)?, before);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum BindingFault {
    TableAdmission,
    TableRoom,
    SourceRoom,
    SourceRegistrar,
    SourceRevision,
    Routes,
    RegistrationAdmission,
    RegistrationRoom,
    RegistrationClassifier,
}

#[test]
fn classified_suffix_rejects_each_inconsistent_classifier_binding() -> Result<(), Box<dyn Error>> {
    for fault in [
        BindingFault::TableAdmission,
        BindingFault::TableRoom,
        BindingFault::SourceRoom,
        BindingFault::SourceRegistrar,
        BindingFault::SourceRevision,
        BindingFault::Routes,
        BindingFault::RegistrationAdmission,
        BindingFault::RegistrationRoom,
        BindingFault::RegistrationClassifier,
    ] {
        let (mut store, child, operation, event) = classified_suffix_store()?;
        let before = store.read_fork_event_suffix(child, 1)?;
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].0.input().fork_timeline_id, child);
        assert_eq!(before[0].0.input().logical_seq, 1);
        assert_eq!(before[0].0.input().event_id, event.id);
        assert_eq!(
            before[0].0.input().classification.origin(),
            ForkEventOriginKindV1::HostInternal,
        );
        assert!(!before[0].0.input().classification.intervention());
        assert_eq!(before[0].1, None);
        assert_eq!(before[0].2, operation);
        let tables = store.fork_classifier_tables.clone();
        let sources = store.fork_classifier_sources.clone();
        let registrations = store.fork_classifier_registrations.clone();
        let mut table = tables
            .get(&child)
            .ok_or("missing fixture FCT1")?
            .input()
            .clone();
        let mut source = sources
            .get(&(
                table.room_revision_descriptor_hash,
                table.registrar_identifier.clone(),
            ))
            .ok_or("missing fixture FCS1")?
            .input()
            .clone();
        let mut registration = registrations
            .values()
            .find(|row| row.input().child_timeline_id == child)
            .ok_or("missing fixture FCR1")?
            .input()
            .clone();
        let wrong = Hash::from_bytes([0xe1; 32]);
        match fault {
            // The first binding block: table/admission, then source/table.
            BindingFault::TableAdmission => table.fork_admission_digest = wrong,
            BindingFault::TableRoom => table.room_revision_descriptor_hash = wrong,
            BindingFault::SourceRoom => source.room_revision_descriptor_hash = wrong,
            BindingFault::SourceRegistrar => source.registrar_identifier.push_str("-foreign"),
            // The source revision remains exact in the route-only case.
            BindingFault::SourceRevision => table.source_configuration_revision_digest = wrong,
            BindingFault::Routes => {
                table.routes = vec![ForkExternalInputRouteV1::new(
                    ForkEventSourceDescriptorV1::new("foreign-route", wrong)?,
                    false,
                )];
            }
            // The selected registration keeps its child and operation identity.
            BindingFault::RegistrationAdmission => registration.fork_admission_digest = wrong,
            BindingFault::RegistrationRoom => registration.room_revision_descriptor_hash = wrong,
            BindingFault::RegistrationClassifier => registration.classifier_revision_digest = wrong,
        }
        // Preserve the selected lookup even for a changed table descriptor;
        // absence must not intercept the intended cross-record binding check.
        store.fork_classifier_sources.insert(
            (
                table.room_revision_descriptor_hash,
                table.registrar_identifier.clone(),
            ),
            ForkClassifierSourceV1::new(source)?,
        );
        store
            .fork_classifier_tables
            .insert(child, ForkClassifierTableV1::new(table)?);
        store.fork_classifier_registrations.insert(
            registration.operation_id,
            ForkClassifierRegistrationV1::new(registration)?,
        );
        assert_eq!(
            store.read_fork_event_suffix(child, 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority),
            "fault={fault:?}",
        );
        // Restore only the test's exact original graph, then re-read publicly.
        store.fork_classifier_tables = tables;
        store.fork_classifier_sources = sources;
        store.fork_classifier_registrations = registrations;
        assert_eq!(
            store.read_fork_event_suffix(child, 1)?,
            before,
            "fault={fault:?}"
        );
    }
    Ok(())
}
