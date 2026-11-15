#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::{
    CanonicalBytes, EntityId, EventStore, GeoLocationAdmissionFenceV1,
    OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStore, OwnTracksIngressInputV1,
    OwnTracksIngressStore,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected ingress fixture error: {error:?}"
            )))
        })
    }
}

impl<T> TestValueExt<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing ingress fixture value")))
    }
}

const OWNER_KEY: [u8; 32] = [17; 32];
const BASIC_HANDLE: [u8; 32] = [23; 32];
const BASIC_SECRET: [u8; 32] = [29; 32];

fn input(owner_key: [u8; 32], basic_secret: [u8; 32]) -> OwnTracksIngressInputV1 {
    let payload = CanonicalBytes::from_static(b"owntracks-v1-minimized-geo-location");
    let mut verifier_material = Vec::with_capacity(96);
    verifier_material.extend_from_slice(b"pigloros/owntracks/verifier/v1\0");
    verifier_material.extend_from_slice(&BASIC_HANDLE);
    verifier_material.extend_from_slice(&basic_secret);
    let candidate_verifier = *blake3::keyed_hash(&owner_key, &verifier_material).as_bytes();
    let rate_key = owntracks_key(
        &owner_key,
        b"pigloros/owntracks/rate/v1\0",
        basic_secret,
        &payload,
        false,
    );
    let intent = owntracks_key(
        &owner_key,
        b"pigloros/owntracks/intent/v1\0",
        basic_secret,
        &payload,
        true,
    );
    let fingerprint = owntracks_key(
        &owner_key,
        b"pigloros/owntracks/fingerprint/v1\0",
        basic_secret,
        &payload,
        true,
    );
    OwnTracksIngressInputV1::new(candidate_verifier, rate_key, intent, fingerprint, payload)
}

fn owntracks_key(
    owner_key: &[u8; 32],
    domain: &[u8],
    basic_secret: [u8; 32],
    payload: &CanonicalBytes,
    includes_payload: bool,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(owner_key);
    hasher.update(domain);
    hasher.update(&BASIC_HANDLE);
    if includes_payload {
        hasher.update(&basic_secret);
        hasher.update(payload.as_slice());
    }
    *hasher.finalize().as_bytes()
}

fn verifier() -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + 32 + 32);
    material.extend_from_slice(b"pigloros/owntracks/verifier/v1\0");
    material.extend_from_slice(&BASIC_HANDLE);
    material.extend_from_slice(&BASIC_SECRET);
    *blake3::keyed_hash(&OWNER_KEY, &material).as_bytes()
}

fn assert_ingress_contract<S>(store: &mut S)
where
    S: EventStore + OwnTracksEnrollmentStore + OwnTracksIngressStore,
{
    let valid = input(OWNER_KEY, BASIC_SECRET);
    assert!(store.prepare_owntracks_ingress(valid.clone()).is_err());

    let timeline = store.create_timeline("owntracks-ingress").test_ok();
    let entity = EntityId::new();
    store
        .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
            verifier(),
        ))
        .test_ok();

    let prepared = store.prepare_owntracks_ingress(valid.clone()).test_ok();
    assert_eq!(
        prepared.rate_key(),
        store
            .prepare_owntracks_ingress(input(OWNER_KEY, BASIC_SECRET))
            .test_ok()
            .rate_key()
    );
    let admission = prepared.into_admission_request();
    assert_eq!(admission.timeline(), timeline.id());
    assert_eq!(admission.entity(), entity);
    assert_eq!(
        admission.payload(),
        &CanonicalBytes::from_static(b"owntracks-v1-minimized-geo-location")
    );

    assert!(store
        .prepare_owntracks_ingress(input([0; 32], BASIC_SECRET))
        .is_err());
    assert!(store
        .prepare_owntracks_ingress(input(OWNER_KEY, [0; 32]))
        .is_err());

    store.revoke_owntracks_enrollment().test_ok();
    assert!(store.prepare_owntracks_ingress(valid).is_err());
}

#[test]
fn memory_authenticated_ingress_contract() {
    assert_ingress_contract(&mut MemoryStore::new());
}

#[test]
fn sqlite_authenticated_ingress_contract() {
    assert_ingress_contract(&mut SqliteStore::open_in_memory().test_ok());
}

/// ADR-134 §8: on a bound file, an `OwnTracks` ingest through a handle
/// attached to a pre-rotation epoch, or never attached, commits no location.
#[test]
fn sqlite_a_stale_or_unattached_handle_ingests_nothing() {
    use pos_core::{
        geo_admission::GeoLocationAdmissionStore, CoreError, GatewayModeBindingHostV1,
        GatewayModeBindingPortV1, GatewayModeProfileRefV1, Seq,
    };

    let local = |byte| GatewayModeProfileRefV1::try_new("gateway-mode-local-v1", [byte; 32]);
    let database = tempfile::NamedTempFile::new().test_ok();
    let path = database.path().to_str().test_ok();
    let open = || {
        let mut store = SqliteStore::open(path).test_ok();
        store
            .bind_erasure_gate(std::sync::Arc::new(
                pos_core::ErasureContainmentGateV1::new_test_open(),
            ))
            .test_ok();
        store
    };
    let mut binder = open();
    binder
        .bind_empty_store_mode(GatewayModeBindingHostV1::new().authorize_bind(local(1).test_ok()))
        .test_ok();
    let timeline = binder.create_timeline("bound-owntracks").test_ok().id();
    binder
        .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
            timeline,
            EntityId::new(),
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
            verifier(),
        ))
        .test_ok();
    let mut stale = open();
    stale.attach_mode_binding(&local(1).test_ok()).test_ok();
    let mut unattached = open();
    let permit = GatewayModeBindingHostV1::new()
        .authorize_rotation(local(1).test_ok(), local(2).test_ok())
        .test_ok();
    binder.rotate_mode(permit).test_ok();

    // The bound handle authenticates the ingest; each writer then commits it.
    let request = binder
        .prepare_owntracks_ingress(input(OWNER_KEY, BASIC_SECRET))
        .test_ok()
        .into_admission_request();
    for writer in [&mut stale, &mut unattached] {
        assert!(matches!(
            writer.admit_geo_location(request.clone()),
            Err(CoreError::ModeBindingStale)
        ));
    }
    let admitted = binder.admit_geo_location(request).test_ok();
    assert!(admitted.is_accepted());
    assert_eq!(admitted.event_seq(), Some(Seq::from_u64(1)));
}
