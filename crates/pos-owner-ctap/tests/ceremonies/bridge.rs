#![cfg(any(test, feature = "test-support"))]
//! Full ADR-097 enrollment and unlock through `OwnerBridge`, the real codec and the shared
//! verifier, with the native client over the software authenticator (ADR-110 E20 LG, LE).

use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;
use std::time::Instant;

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage, PageAuthenticator};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::stepper::FakeHost;
use pos_owner_bridge::fake::surface::{FakeSurface, SurfaceConfig};
use pos_owner_bridge::{
    BindingUpdate, BridgeConfig, BridgeError, CeremonyHost, CeremonyReply, ConfirmedBinding,
    EnrollmentContext, EnrollmentPort, MonotonicClock, OwnerAuthenticatorPort, OwnerBridge,
    OwnerError, PrfOutput, QuarantinePoll, ReplyImage, RequestImage, RootFingerprint, SealInputs,
    UnlockPort,
};
use pos_owner_bridge_codec::SubjectId;
use pos_owner_ctap::{CtapAuthenticator, Drbg, MemoryHid, Notice};
use sha2::{Digest, Sha256};

use super::{text, Prompt, Rig, TestResult, PIN, PRF_UNSUPPORTED};

type Client = CtapAuthenticator<MemoryHid, Prompt, Drbg>;

/// One native client shared by a host and a page.
#[derive(Clone)]
struct Shared(Rc<RefCell<Client>>);

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

/// The Linux `CeremonyHost` shape (Redmine #1438): every ceremony runs through `run_direct`.
struct DirectHost<P: OwnerAuthenticatorPort, C: MonotonicClock> {
    port: P,
    clock: C,
}

impl<P: OwnerAuthenticatorPort, C: MonotonicClock> DirectHost<P, C> {
    const fn new(port: P, clock: C) -> Self {
        Self { port, clock }
    }
}

impl<P: OwnerAuthenticatorPort, C: MonotonicClock> CeremonyHost for DirectHost<P, C> {
    fn run(&mut self, mut driver: CeremonyDriver) -> CeremonyReply {
        let result = driver.run_direct(&mut self.port, &self.clock);
        CeremonyReply {
            result,
            driver: Some(driver),
        }
    }

    fn poll_quarantine(&mut self) -> QuarantinePoll {
        QuarantinePoll::default()
    }
}

fn fingerprint(prf: &[u8; 32]) -> RootFingerprint {
    RootFingerprint::from_bytes(Sha256::digest(prf).into())
}

/// An owner adapter that seals and confirms a root bound to the PRF it was given.
#[derive(Default)]
struct Enrollment {
    sealed: Option<[u8; 32]>,
    prf_input: Option<[u8; 32]>,
    committed: Option<ConfirmedBinding>,
}

impl EnrollmentPort for Enrollment {
    type Candidate = [u8; 32];

    fn credential_unbound(&mut self, _credential_id: &[u8]) -> Result<bool, OwnerError> {
        Ok(true)
    }

    fn seal_candidate(
        &mut self,
        prf: PrfOutput<'_>,
        inputs: SealInputs<'_>,
    ) -> Result<([u8; 32], RootFingerprint), OwnerError> {
        self.sealed = Some(*prf.as_bytes());
        self.prf_input = Some(*inputs.prf_input().as_bytes());
        Ok((*prf.as_bytes(), fingerprint(prf.as_bytes())))
    }

    fn confirm_candidate(
        &mut self,
        _candidate: &[u8; 32],
        prf: PrfOutput<'_>,
    ) -> Result<RootFingerprint, OwnerError> {
        Ok(fingerprint(prf.as_bytes()))
    }

    fn commit(
        &mut self,
        _candidate: [u8; 32],
        binding: ConfirmedBinding,
    ) -> Result<(), OwnerError> {
        self.committed = Some(binding);
        Ok(())
    }

    fn abandon(&mut self, _candidate: [u8; 32]) {}
}

/// An owner adapter that opens with whatever PRF the unlock produced.
#[derive(Default)]
struct Unlock {
    opened: Option<[u8; 32]>,
    updates: Vec<BindingUpdate>,
}

impl UnlockPort for Unlock {
    type Pending = [u8; 32];
    type Session = [u8; 32];

    fn open_pending(&mut self, prf: PrfOutput<'_>) -> Result<[u8; 32], OwnerError> {
        self.opened = Some(*prf.as_bytes());
        Ok(*prf.as_bytes())
    }

    fn persist_binding_update(&mut self, update: &BindingUpdate) -> Result<(), OwnerError> {
        self.updates.push(*update);
        Ok(())
    }

    fn release(&mut self, pending: [u8; 32]) -> [u8; 32] {
        pending
    }
}

fn context() -> EnrollmentContext {
    let mut subject = [0; 16];
    subject.copy_from_slice(&Drbg::new("subject").draw()[..16]);
    EnrollmentContext {
        owner_id: "owner".to_owned(),
        subject_id: SubjectId::from_bytes(subject),
        epoch: 1,
        owner_window: None,
    }
}

fn shared(rig: Rig) -> (Shared, MemoryHid, Prompt) {
    (
        Shared(Rc::new(RefCell::new(rig.port))),
        rig.device,
        rig.prompt,
    )
}

fn direct_bridge(
    port: Shared,
) -> OwnerBridge<DirectHost<Shared, FakeClock>, FakeRandom, FakeClock> {
    let clock = FakeClock::start();
    OwnerBridge::new(
        DirectHost::new(port, clock.clone()),
        FakeRandom::seeded(11),
        clock,
        BridgeConfig::default(),
    )
}

/// Unlock `enrollment`'s credential through `run_direct` and return the PRF it opened with.
fn unlock(port: Shared, enrollment: &Enrollment) -> Result<[u8; 32], Box<dyn Error>> {
    let committed = enrollment.committed.as_ref().ok_or("nothing committed")?;
    let binding = text(committed.binding())?;
    let prf_input = enrollment.prf_input.ok_or("nothing sealed")?;
    let mut opened = Unlock::default();
    let session = direct_bridge(port).unlock(&binding, &prf_input, &mut opened)?;
    assert_eq!(opened.updates.len(), 1);
    assert_eq!(opened.opened, Some(session));
    Ok(session)
}

#[test]
fn a_native_enrollment_takes_three_pin_entries_and_unlocks_with_one() -> TestResult {
    let (port, device, prompt) = shared(Rig::new(false));
    for _ in 0..4 {
        prompt.enter(PIN);
    }
    let mut enrollment = Enrollment::default();
    direct_bridge(port.clone()).enroll(&context(), &mut enrollment)?;
    assert_eq!(prompt.asked().len(), 3);
    let opened = unlock(port, &enrollment)?;
    assert_eq!(Some(opened), enrollment.sealed);
    assert_eq!(prompt.asked(), [8, 8, 8, 8]);
    assert_eq!(prompt.notices(), [Notice::Touch; 4]);
    assert_eq!(device.requests().len(), 20);
    Ok(())
}

#[test]
fn a_key_that_fails_the_capability_check_never_enrolls() {
    let (port, device, _) = shared(Rig::new(false));
    device.with_authenticator(|soft| soft.set_info(vec![0xa0]));
    let mut enrollment = Enrollment::default();
    let mut bridge = direct_bridge(port);
    assert_eq!(
        bridge.enroll(&context(), &mut enrollment),
        Err(PRF_UNSUPPORTED)
    );
    assert!(enrollment.sealed.is_none());
    assert_eq!(device.requests(), [vec![0x04]]);
}

#[test]
fn a_buffer_enrollment_with_the_native_client_unlocks_through_run_direct() -> TestResult {
    let (port, _, _) = shared(Rig::new(true));
    let clock = FakeClock::start();
    let loopback = FakeLoopback::default();
    let page = text(HonestPage::new(HonestConfig::standard(&[1])))?
        .with_authenticator(PageAuthenticator::new(port.0.clone(), clock.clone()));
    let surface = FakeSurface::new(
        clock.clone(),
        loopback.clone(),
        Box::new(page),
        SurfaceConfig::default(),
    );
    let host = FakeHost::new(clock.clone(), surface, loopback, FakeStore::default());
    let mut buffered =
        OwnerBridge::new(host, FakeRandom::seeded(12), clock, BridgeConfig::default());
    let mut enrollment = Enrollment::default();
    buffered.enroll(&context(), &mut enrollment)?;
    let opened = unlock(port.clone(), &enrollment)?;
    assert_eq!(Some(opened), enrollment.sealed);
    let mut host = DirectHost::new(port, FakeClock::start());
    assert!(host.poll_quarantine().driver.is_none());
    Ok(())
}
