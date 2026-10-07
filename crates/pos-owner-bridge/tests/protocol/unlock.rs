//! Unlock: Get ceremony, wait for exit, open, persist the binding update, then release.

use pos_owner_bridge::fake::clock::FakeRandom;
use pos_owner_bridge::fake::honest::HonestConfig;
use pos_owner_bridge::fake::signer::{Backup, ReplyShape, FIXTURE_COSE_KEY};
use pos_owner_bridge::{
    BindingUpdate, BridgeError, BridgeStatus, OwnerError, OwnerErrorKind, RejectedCode,
    UnavailableCode,
};
use pos_owner_bridge_codec::{
    CoseEs256PublicKey, SubjectCredentialBindingInputV1, SubjectCredentialBindingV1, SubjectId,
    TransportCodes,
};

use super::{
    bytes16, bytes32, expected_prf, honest, user_handle, Boxed, Call, FakeUnlock, Rig, TestResult,
    CREDENTIAL_ID,
};

type Tweak = fn(&mut ReplyShape);

fn binding(
    owner: &str,
    sign_count: u32,
) -> Result<SubjectCredentialBindingV1<'_>, Box<dyn std::error::Error>> {
    SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
        owner_id: owner,
        subject_id: SubjectId::from_bytes(bytes16(0x10)),
        epoch: 1,
        credential_id: &CREDENTIAL_ID,
        user_handle: user_handle(),
        public_key: CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY).boxed()?,
        backup_eligible: false,
        backup_state: false,
        sign_count,
        transports: TransportCodes::new(&[0]).boxed()?,
    })
    .boxed()
}

fn rig(page: HonestConfig) -> Result<Rig, Box<dyn std::error::Error>> {
    Rig::new(page, FakeRandom::seeded(9))
}

#[test]
fn unlock_opens_persists_and_only_then_releases() -> TestResult {
    let page = honest(0);
    let prf = expected_prf(&page);
    let mut rig = rig(page)?;
    let mut port = FakeUnlock::new();
    let binding = binding("owner", 0)?;
    let session = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port)?;
    assert_eq!(session, prf);
    assert_eq!(port.calls, [Call::Open, Call::Persist, Call::Release]);
    assert_eq!(port.prf, Some(prf));
    assert_eq!(
        port.updates,
        [BindingUpdate {
            sign_count: 1,
            backup_state: false
        }]
    );
    assert_eq!(rig.bridge.status(), BridgeStatus::Ready);
    Ok(())
}

#[test]
fn a_failed_binding_update_releases_no_root() -> TestResult {
    let mut rig = rig(honest(0))?;
    let mut port = FakeUnlock::new();
    port.persist_error = Some(OwnerError::new(OwnerErrorKind::DurableWrite));
    let binding = binding("owner", 0)?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Owner(OwnerError::new(
            OwnerErrorKind::DurableWrite
        )))
    );
    assert_eq!(port.calls, [Call::Open, Call::Persist]);
    Ok(())
}

#[test]
fn a_failed_open_stops_before_the_update() -> TestResult {
    let mut rig = rig(honest(0))?;
    let mut port = FakeUnlock::new();
    port.open_error = Some(OwnerError::new(OwnerErrorKind::Wrap));
    let binding = binding("owner", 0)?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Owner(OwnerError::new(OwnerErrorKind::Wrap)))
    );
    assert_eq!(port.calls, [Call::Open]);
    Ok(())
}

const fn eligible(shape: &mut ReplyShape) {
    shape.backup = Backup::Eligible;
}

#[test]
fn a_rejected_assertion_never_reaches_the_owner_port() -> TestResult {
    let cases: [(Tweak, u32, RejectedCode); 2] = [
        (eligible, 0, RejectedCode::BackupFlags),
        (|_| {}, 5, RejectedCode::CounterRegression),
    ];
    for (tweak, counter, code) in cases {
        let page = HonestConfig {
            tweak: Some(tweak),
            ..honest(0)
        };
        let mut rig = rig(page)?;
        let mut port = FakeUnlock::new();
        let binding = binding("owner", counter)?;
        let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
        assert_eq!(outcome, Err(BridgeError::Rejected(code)));
        assert!(port.calls.is_empty());
    }
    Ok(())
}

#[test]
fn an_unavailable_surface_refuses_unlock() -> TestResult {
    let mut rig = rig(honest(0))?;
    rig.loopback.fail_probes_from(Some(1));
    let mut port = FakeUnlock::new();
    let binding = binding("owner", 0)?;
    let changed = BridgeError::Unavailable(UnavailableCode::LoopbackChanged);
    assert_eq!(
        rig.bridge.unlock(&binding, &bytes32(0x60), &mut port),
        Err(changed)
    );
    assert_eq!(
        rig.bridge.unlock(&binding, &bytes32(0x60), &mut port),
        Err(changed)
    );
    assert!(port.calls.is_empty());
    Ok(())
}

#[test]
fn an_rng_failure_refuses_unlock_before_any_environment_exists() -> TestResult {
    let mut rig = Rig::new(honest(0), FakeRandom::failing_after(2, 0))?;
    let mut port = FakeUnlock::new();
    let binding = binding("owner", 0)?;
    let outcome = rig.bridge.unlock(&binding, &bytes32(0x60), &mut port);
    assert_eq!(
        outcome,
        Err(BridgeError::Unavailable(UnavailableCode::RngUnavailable))
    );
    assert!(port.calls.is_empty());
    assert!(rig.surface.log().is_empty());
    Ok(())
}
