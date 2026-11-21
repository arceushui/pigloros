#![cfg(any(test, feature = "test-support"))]
//! Public ADR-137 L8 vectors for the owner V2 consent permit (Redmine #1480):
//! a store binds the Gateway permit or the owner permit, once, never both.

use std::sync::Arc;

use pos_core::owner_consent_v2_permit::mint_owner_consent_v2_permit;
use pos_core::{
    AppendDedupScope, ConsentAuthority, ConsentRevokedV1, CoreError, EntityId,
    ErasureContainmentGateV1, EventDraft, EventStore, Kind, OwnerConsentV2PermitV1,
    EVENT_TYPE_CONSENT_REVOKED_V1,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn refused(result: Result<(), CoreError>, message: &str) {
    assert_eq!(
        result.map_err(|error| error.to_string()),
        Err(format!("storage error: {message}"))
    );
}

fn stores() -> Result<[Box<dyn EventStore>; 2], CoreError> {
    Ok([
        Box::new(MemoryStore::new()),
        Box::new(SqliteStore::open_in_memory()?),
    ])
}

fn two_permits() -> Result<(OwnerConsentV2PermitV1, OwnerConsentV2PermitV1), CoreError> {
    Ok((
        mint_owner_consent_v2_permit()?,
        mint_owner_consent_v2_permit()?,
    ))
}

#[test]
fn each_mint_is_a_fresh_permit() -> TestResult {
    let (first, second) = two_permits()?;
    assert_ne!(first, second);
    assert_eq!(format!("{first:?}"), "OwnerConsentV2PermitV1(..)");
    Ok(())
}

#[test]
fn the_owner_permit_binds_once_and_refuses_a_different_one() -> TestResult {
    for mut store in stores()? {
        let (permit, other) = two_permits()?;
        store.bind_owner_consent_v2_permit(permit)?;
        store.bind_owner_consent_v2_permit(permit)?;
        refused(
            store.bind_owner_consent_v2_permit(other),
            "owner consent permit is already bound",
        );
        store.bind_owner_consent_v2_permit(permit)?;
    }
    Ok(())
}

#[test]
fn the_gateway_permit_binds_once_and_refuses_a_different_one() -> TestResult {
    for mut store in stores()? {
        let permit = ConsentAuthority::new().append_permit();
        store.bind_consent_authority(permit)?;
        store.bind_consent_authority(permit)?;
        refused(
            store.bind_consent_authority(ConsentAuthority::new().append_permit()),
            "Gateway consent authority is already bound",
        );
    }
    Ok(())
}

#[test]
fn a_store_never_binds_both_permits() -> TestResult {
    let both = "a store binds the Gateway or the owner consent permit, not both";
    for mut store in stores()? {
        store.bind_owner_consent_v2_permit(mint_owner_consent_v2_permit()?)?;
        refused(
            store.bind_consent_authority(ConsentAuthority::new().append_permit()),
            both,
        );
    }
    for mut store in stores()? {
        let gateway = ConsentAuthority::new().append_permit();
        store.bind_consent_authority(gateway)?;
        refused(
            store.bind_owner_consent_v2_permit(mint_owner_consent_v2_permit()?),
            both,
        );
        store.bind_consent_authority(gateway)?;
    }
    Ok(())
}

#[test]
fn an_owner_bound_store_refuses_gateway_consent_appends() -> TestResult {
    for mut store in stores()? {
        store.bind_owner_consent_v2_permit(mint_owner_consent_v2_permit()?)?;
        let timeline = store.create_timeline("owner-bound")?;
        // Appends pass the erasure gate first; an open one lets this reach the permit check.
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let subject = EntityId::new();
        let revocation = ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: 1,
        };
        let draft = EventDraft::new(
            subject,
            Kind::new(EVENT_TYPE_CONSENT_REVOKED_V1),
            revocation.encode()?,
        );
        let refusal = store
            .append_consent_revocation_bounded(
                timeline.id(),
                std::slice::from_ref(&draft),
                ConsentAuthority::new().append_permit(),
                1,
                AppendDedupScope::from_keyed_hash([9; 32]),
            )
            .map(|_| ())
            .map_err(|error| error.to_string());
        assert_eq!(
            refusal,
            Err("storage error: Gateway consent authority is not bound".to_owned())
        );
    }
    Ok(())
}
