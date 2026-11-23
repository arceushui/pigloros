//! The ADR-110 E20 LS3 direct-ceremony seam: `run_direct`, `DirectHost` and the page hook that
//! lets one authenticator answer both the buffer protocol and the direct path.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::ceremony::plan::{Budget, CeremonyPlan, StoredGet, Verified};
use pos_owner_bridge::ceremony::timing::{CHALLENGE_TTL, INTERACTION};
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage, PageAuthenticator};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::signer::{FixtureSigner, ReplyShape, FIXTURE_COSE_KEY};
use pos_owner_bridge::fake::stepper::FakeHost;
use pos_owner_bridge::fake::surface::{FakeSurface, SurfaceConfig};
use pos_owner_bridge::{
    BridgeConfig, BridgeError, BridgeStatus, CeremonyHost, DirectHost, LifecycleCode,
    MonotonicClock, OwnerAuthenticatorPort, OwnerBridge, ProtocolCode, ReplyImage, RequestImage,
    UnavailableCode,
};
use pos_owner_bridge_codec::{
    decode_create_options, decode_get_options, CeremonyId, CeremonyKind, CoseEs256PublicKey,
    OwnerBridgeCodecError, OwnerBridgeControlV1, OwnerUserHandle, PrfInput, WebAuthnChallenge,
    CONTROL_HEADER_BYTES, CREATE_REPLY_BUFFER_CAPACITY,
};
use sha2::{Digest, Sha256};

use super::{
    bytes16, bytes32, context, create_plan, get_plan, stored_fixture, user_handle, Boxed, Call,
    FakeEnrollment, FakeUnlock, TestResult, CREDENTIAL_ID,
};

const MALFORMED: BridgeError = BridgeError::Protocol(ProtocolCode::Malformed);
const OUT_OF_BOUNDS: BridgeError = BridgeError::Protocol(ProtocolCode::LengthOutOfBounds);

/// The secret the fixture port's PRF derives from.
fn prf_secret() -> [u8; 32] {
    bytes32(0xa0)
}

fn derived_prf(prf_input: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prf_secret());
    hasher.update(prf_input);
    hasher.finalize().into()
}

/// A fixture authenticator client: it decodes the request image and answers like a native
/// client would, with no PRF result at Create (ADR-110 E20 LP3).
struct FixturePort {
    signer: FixtureSigner,
    counter: u32,
    clock: FakeClock,
    delay: Duration,
    failure: Option<BridgeError>,
    length: Option<usize>,
    deadlines: Vec<Instant>,
}

impl FixturePort {
    fn new(clock: FakeClock) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            signer: FixtureSigner::new(&CREDENTIAL_ID).boxed()?,
            counter: 0,
            clock,
            delay: Duration::ZERO,
            failure: None,
            length: None,
            deadlines: Vec::new(),
        })
    }

    fn encode(&mut self, request: &RequestImage) -> Result<Vec<u8>, OwnerBridgeCodecError> {
        let bytes = request.as_bytes();
        let header = OwnerBridgeControlV1::decode(&bytes[..CONTROL_HEADER_BYTES])?;
        let end = CONTROL_HEADER_BYTES + header.payload_len() as usize;
        let payload = &bytes[CONTROL_HEADER_BYTES..end];
        if header.kind() == CeremonyKind::Create {
            let options = decode_create_options(payload)?;
            let shape = ReplyShape::honest(0, None);
            return self.signer.attestation_payload(
                options.ceremony_id(),
                &options.challenge(),
                &shape,
            );
        }
        let options = decode_get_options(payload)?;
        self.counter += 1;
        let prf = derived_prf(options.prf_input().as_bytes());
        let shape = ReplyShape::honest(self.counter, Some(prf));
        self.signer
            .assertion_payload(options.ceremony_id(), &options.challenge(), &shape)
    }
}

impl OwnerAuthenticatorPort for FixturePort {
    fn perform(
        &mut self,
        request: &RequestImage,
        reply: &mut ReplyImage,
        deadline: Instant,
        _clock: &dyn MonotonicClock,
    ) -> Result<usize, BridgeError> {
        self.deadlines.push(deadline);
        self.clock.advance(self.delay);
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        let encoded = self.encode(request).or(Err(MALFORMED))?;
        reply.as_mut_bytes()[..encoded.len()].copy_from_slice(&encoded);
        Ok(self.length.unwrap_or(encoded.len()))
    }
}

/// One fixture port shared by a host and the test that inspects it.
#[derive(Clone)]
struct Shared(Rc<RefCell<FixturePort>>);

impl OwnerAuthenticatorPort for Shared {
    fn perform(
        &mut self,
        request: &RequestImage,
        reply: &mut ReplyImage,
        deadline: Instant,
        clock: &dyn MonotonicClock,
    ) -> Result<usize, BridgeError> {
        self.0.borrow_mut().perform(request, reply, deadline, clock)
    }
}

/// A clock that moves forward by `step` every time it is read.
struct SteppingClock {
    base: Instant,
    step: Duration,
    reads: Cell<u32>,
}

impl MonotonicClock for SteppingClock {
    fn now(&self) -> Instant {
        let reads = self.reads.get();
        self.reads.set(reads + 1);
        self.base + self.step * reads
    }
}

fn run(
    plan: CeremonyPlan,
    port: &mut FixturePort,
    clock: &FakeClock,
) -> (Result<Verified, BridgeError>, CeremonyDriver) {
    let mut driver = CeremonyDriver::for_test(plan);
    let result = driver.run_direct(port, clock);
    (result, driver)
}

#[test]
fn a_direct_create_verifies_wipes_the_request_and_bounds_the_interaction() -> TestResult {
    let clock = FakeClock::start();
    let mut port = FixturePort::new(clock.clone())?;
    let (result, driver) = run(create_plan(&clock), &mut port, &clock);
    let registration = result?.into_registration()?;
    assert_eq!(registration.credential_id, CREDENTIAL_ID);
    assert!(!registration.prf_present);
    assert!(driver.request_clear());
    assert_eq!(driver.generation(), 1);
    assert_eq!(driver.first_receipt_at(), Some(clock.now()));
    assert_eq!(port.deadlines, [clock.now() + INTERACTION]);
    Ok(())
}

#[test]
fn a_direct_get_returns_the_prf_and_runs_only_once() -> TestResult {
    let clock = FakeClock::start();
    let mut port = FixturePort::new(clock.clone())?;
    let mut driver = CeremonyDriver::for_test(get_plan(&clock, stored_fixture(0)?));
    let assertion = driver.run_direct(&mut port, &clock)?.into_assertion()?;
    assert_eq!(assertion.sign_count, 1);
    assert_eq!(*driver.prf(), derived_prf(&bytes32(0x60)));
    assert!(driver.request_clear());
    let again = driver.run_direct(&mut port, &clock);
    assert_eq!(
        again,
        Err(BridgeError::Protocol(ProtocolCode::UnexpectedState))
    );
    assert_eq!(*driver.prf(), [0; 32]);
    assert_eq!(port.deadlines.len(), 1);
    Ok(())
}

#[test]
fn a_port_failure_is_returned_and_wipes_the_ceremony() -> TestResult {
    let clock = FakeClock::start();
    let mut port = FixturePort::new(clock.clone())?;
    let failure = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);
    port.failure = Some(failure);
    let (result, driver) = run(create_plan(&clock), &mut port, &clock);
    assert_eq!(result, Err(failure));
    assert!(driver.request_clear());
    Ok(())
}

#[test]
fn the_interaction_bound_starts_at_the_first_ctap_command() -> TestResult {
    let clock = FakeClock::start();
    let plan = create_plan(&clock);
    clock.advance(Duration::from_secs(20));
    let mut port = FixturePort::new(clock.clone())?;
    port.delay = INTERACTION.saturating_sub(Duration::from_secs(1));
    let (result, _) = run(plan, &mut port, &clock);
    assert!(result.is_ok());

    let plan = create_plan(&clock);
    port.delay = INTERACTION;
    let (result, driver) = run(plan, &mut port, &clock);
    let timeout = BridgeError::Lifecycle(LifecycleCode::InteractionTimeout);
    assert_eq!(result, Err(timeout));
    assert!(driver.request_clear());
    Ok(())
}

#[test]
fn the_challenge_ttl_caps_the_deadline_and_expires_the_reply() -> TestResult {
    let clock = FakeClock::start();
    let plan = create_plan(&clock);
    let t0 = clock.now();
    clock.advance(Duration::from_secs(40));
    let mut port = FixturePort::new(clock.clone())?;
    port.delay = Duration::from_secs(110);
    let (result, _) = run(plan, &mut port, &clock);
    let expired = BridgeError::Lifecycle(LifecycleCode::ChallengeExpired);
    assert_eq!(result, Err(expired));
    assert_eq!(port.deadlines, [t0 + CHALLENGE_TTL]);
    Ok(())
}

#[test]
fn an_expired_challenge_or_budget_never_reaches_the_port() -> TestResult {
    let clock = FakeClock::start();
    let mut port = FixturePort::new(clock.clone())?;
    let plan = create_plan(&clock);
    clock.advance(CHALLENGE_TTL);
    let (result, _) = run(plan, &mut port, &clock);
    let expired = BridgeError::Lifecycle(LifecycleCode::ChallengeExpired);
    assert_eq!(result, Err(expired));

    let budget = Budget::with_limit(clock.now(), Duration::from_secs(3));
    let plan = create_plan(&clock).with_budget(budget);
    clock.advance(Duration::from_secs(3));
    let (result, _) = run(plan, &mut port, &clock);
    let exceeded = BridgeError::Lifecycle(LifecycleCode::EnrollmentBudgetExceeded);
    assert_eq!(result, Err(exceeded));
    assert!(port.deadlines.is_empty());

    let plan = create_plan(&clock).with_budget(Budget::with_limit(clock.now(), INTERACTION));
    clock.advance(Duration::from_secs(1));
    let (result, _) = run(plan, &mut port, &clock);
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn a_request_that_cannot_be_encoded_never_reaches_the_port() -> TestResult {
    let clock = FakeClock::start();
    let mut port = FixturePort::new(clock.clone())?;
    let public_key = CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY).boxed()?;
    let empty = StoredGet::new(Vec::new(), user_handle(), public_key, false, false, 0);
    let (result, _) = run(get_plan(&clock, empty), &mut port, &clock);
    assert_eq!(result, Err(OUT_OF_BOUNDS));
    assert!(port.deadlines.is_empty());
    Ok(())
}

#[test]
fn a_reply_length_outside_the_capacity_is_refused() -> TestResult {
    let clock = FakeClock::start();
    let mut port = FixturePort::new(clock.clone())?;
    let capacity = CREATE_REPLY_BUFFER_CAPACITY as usize - CONTROL_HEADER_BYTES;
    for length in [0, capacity + 1] {
        port.length = Some(length);
        let (result, _) = run(create_plan(&clock), &mut port, &clock);
        assert_eq!(result, Err(OUT_OF_BOUNDS), "length {length}");
    }
    port.length = Some(capacity);
    let (result, _) = run(create_plan(&clock), &mut port, &clock);
    assert_eq!(result, Err(MALFORMED));
    Ok(())
}

#[test]
fn a_challenge_that_expires_during_verification_wipes_the_prf() -> TestResult {
    let base = Instant::now();
    let clock = SteppingClock {
        base,
        step: CHALLENGE_TTL / 2,
        reads: Cell::new(0),
    };
    let stored = stored_fixture(0)?;
    let plan = CeremonyPlan::for_test(
        CeremonyKind::Get,
        CeremonyId::from_bytes(bytes16(0)),
        WebAuthnChallenge::from_bytes(bytes32(0x20)),
        OwnerUserHandle::from_bytes(bytes32(0x40)),
        PrfInput::from_bytes(bytes32(0x60)),
        base,
    )
    .with_stored(Some(stored));
    let mut port = FixturePort::new(FakeClock::start())?;
    let mut driver = CeremonyDriver::for_test(plan);
    let result = driver.run_direct(&mut port, &clock);
    let expired = BridgeError::Lifecycle(LifecycleCode::ChallengeExpired);
    assert_eq!(result, Err(expired));
    assert_eq!(clock.reads.get(), 3);
    assert_eq!(*driver.prf(), [0; 32]);
    Ok(())
}

#[test]
fn the_direct_host_enrolls_and_unlocks_through_the_bridge() -> TestResult {
    let clock = FakeClock::start();
    let port = Shared(Rc::new(RefCell::new(FixturePort::new(clock.clone())?)));
    let host = DirectHost::new(port.clone(), clock.clone());
    let mut bridge = OwnerBridge::new(host, FakeRandom::seeded(5), clock, BridgeConfig::default());
    let mut enrollment = FakeEnrollment::new();
    bridge.enroll(&context(), &mut enrollment)?;
    assert_eq!(
        enrollment.calls,
        [Call::Unbound, Call::Seal, Call::Confirm, Call::Commit]
    );
    let (_, prf_input, _) = enrollment.sealed_over.clone().ok_or("nothing was sealed")?;
    assert_eq!(enrollment.seal_prf, Some(derived_prf(prf_input.as_bytes())));
    let committed = enrollment.committed.ok_or("nothing was committed")?;
    let binding = committed.binding().boxed()?;
    let mut unlock = FakeUnlock::new();
    bridge.unlock(&binding, prf_input.as_bytes(), &mut unlock)?;
    assert_eq!(unlock.prf, enrollment.seal_prf);
    assert_eq!(unlock.calls, [Call::Open, Call::Persist, Call::Release]);
    assert!(bridge.secret_slots_clear());
    assert_eq!(bridge.status(), BridgeStatus::Ready);
    assert_eq!(port.0.borrow().deadlines.len(), 4);
    Ok(())
}

#[test]
fn the_direct_host_never_holds_a_quarantined_ceremony() -> TestResult {
    let clock = FakeClock::start();
    let mut host = DirectHost::new(FixturePort::new(clock.clone())?, clock);
    let polled = host.poll_quarantine();
    assert!(polled.driver.is_none());
    assert!(!polled.remaining);
    Ok(())
}

type BufferBridge = OwnerBridge<FakeHost, FakeRandom, FakeClock>;

/// A bridge over the fake buffer protocol whose page answers with `port`.
fn buffer_bridge(port: &Shared) -> Result<BufferBridge, Box<dyn std::error::Error>> {
    let clock = FakeClock::start();
    let loopback = FakeLoopback::default();
    let page = HonestPage::new(HonestConfig::standard(&CREDENTIAL_ID))
        .boxed()?
        .with_authenticator(PageAuthenticator::new(port.0.clone(), clock.clone()));
    let surface = FakeSurface::new(
        clock.clone(),
        loopback.clone(),
        Box::new(page),
        SurfaceConfig::default(),
    );
    let host = FakeHost::new(clock.clone(), surface, loopback, FakeStore::default());
    Ok(OwnerBridge::new(
        host,
        FakeRandom::seeded(3),
        clock,
        BridgeConfig::default(),
    ))
}

#[test]
fn a_buffer_enrollment_unlocks_through_run_direct_with_the_same_prf() -> TestResult {
    let port = Shared(Rc::new(RefCell::new(FixturePort::new(FakeClock::start())?)));
    let mut bridge = buffer_bridge(&port)?;
    let mut enrollment = FakeEnrollment::new();
    bridge.enroll(&context(), &mut enrollment)?;
    let (_, prf_input, _) = enrollment.sealed_over.clone().ok_or("nothing was sealed")?;
    let committed = enrollment.committed.ok_or("nothing was committed")?;
    let binding = committed.binding().boxed()?;
    assert_eq!(port.0.borrow().deadlines.len(), 3);

    let clock = FakeClock::start();
    let host = DirectHost::new(port, clock.clone());
    let mut direct = OwnerBridge::new(host, FakeRandom::seeded(4), clock, BridgeConfig::default());
    let mut unlock = FakeUnlock::new();
    direct.unlock(&binding, prf_input.as_bytes(), &mut unlock)?;
    assert_eq!(unlock.prf, enrollment.seal_prf);
    assert_eq!(unlock.prf, Some(derived_prf(prf_input.as_bytes())));
    Ok(())
}

#[test]
fn a_page_authenticator_that_fails_or_overflows_fails_the_buffer_ceremony() -> TestResult {
    let failed = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
    let capacity = CREATE_REPLY_BUFFER_CAPACITY as usize;
    for (failure, length) in [(Some(MALFORMED), None), (None, Some(capacity + 1))] {
        let port = Shared(Rc::new(RefCell::new(FixturePort::new(FakeClock::start())?)));
        port.0.borrow_mut().failure = failure;
        port.0.borrow_mut().length = length;
        let mut bridge = buffer_bridge(&port)?;
        let mut enrollment = FakeEnrollment::new();
        assert_eq!(bridge.enroll(&context(), &mut enrollment), Err(failed));
        assert!(enrollment.calls.is_empty());
    }
    Ok(())
}
