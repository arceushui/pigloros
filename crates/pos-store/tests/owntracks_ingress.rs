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
