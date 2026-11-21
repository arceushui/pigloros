#![cfg(any(test, feature = "test-support"))]
//! The real enrollment adapter behind `OwnerBridge::enroll` (ADR-110 §8 E1-E5,
//! ADR-137 P3), driven by `FakeSurface`, the fixture signer and a test
//! directory under the E16 encryptor lock.
#![cfg(target_os = "linux")]

use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pos_core::EntityId;
use pos_crypto::subject_key::{
    subject_owner_id, SubjectKeyWrapParamsV1, SubjectKeyWrapV1, SubjectPrfOutputV1,
    SubjectRootKeyV1,
};
use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerRowV1, SubjectNonceLedgerV1, SubjectStoreFileIdV1,
};
use pos_owner_adapter::enrollment::{
    EnrollmentStore, OwnerEnrollmentAdapter, SubjectKeyRegistration, VolatileEnrollmentStore,
};
use pos_owner_bridge::encryptor_lock::linux::SubjectEncryptorLock;
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::stepper::FakeHost;
use pos_owner_bridge::fake::surface::{FakeSurface, SurfaceConfig};
use pos_owner_bridge::{
    BridgeConfig, BridgeError, ConfirmedBinding, EnrollmentPort, OwnerBridge, OwnerError,
    OwnerErrorKind, PrfOutput, RejectedCode, RootFingerprint, SealInputs, UnavailableCode,
};
use pos_owner_bridge_codec::{decode_subject_credential_binding, SubjectId};
use sha2::{Digest, Sha256};
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Bridge = OwnerBridge<FakeHost, FakeRandom, FakeClock>;

const SUBJECT: SubjectId = SubjectId::from_bytes([0x10; 16]);
const OTHER: SubjectId = SubjectId::from_bytes([0x20; 16]);
const CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];
const FILE: SubjectStoreFileIdV1 = SubjectStoreFileIdV1::Linux {
    device: 7,
    inode: 9,
};
const WRAP: BridgeError = BridgeError::Owner(OwnerError::new(OwnerErrorKind::Wrap));
const REGISTRY: BridgeError = BridgeError::Owner(OwnerError::new(OwnerErrorKind::Registry));
const DURABLE_WRITE: OwnerError = OwnerError::new(OwnerErrorKind::DurableWrite);
static NEXT: AtomicU64 = AtomicU64::new(0);

/// A private test directory, removed when dropped.
struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> TestResult<Self> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pigloros-owner-adapter-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes).and_then(|()| fs::set_permissions(path, Permissions::from_mode(0o600)))
}

/// A held encryptor lock over a fresh test directory with an empty SNL1 ledger.
struct Fixture {
    lock: SubjectEncryptorLock,
    sandbox: Sandbox,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let sandbox = Sandbox::new()?;
        let lock = SubjectEncryptorLock::acquire(&sandbox.0)?;
        let fixture = Self { lock, sandbox };
        fixture.write_ledger(&[])?;
        Ok(fixture)
    }

    fn state(&self) -> PathBuf {
        self.sandbox.0.join("pigloros")
    }

    fn keys(&self) -> PathBuf {
        self.state().join("subject-keys.v1")
    }

    fn ledger(&self) -> PathBuf {
        self.state().join("subject-nonce-ledger.v1")
    }

    fn write_ledger(&self, rows: &[SubjectNonceLedgerRowV1]) -> TestResult {
        let ledger = SubjectNonceLedgerV1::new(rows.to_vec())?;
        Ok(write_private(&self.ledger(), ledger.as_bytes())?)
    }

    fn ledger_rows(&self) -> TestResult<Vec<SubjectNonceLedgerRowV1>> {
        let ledger = SubjectNonceLedgerV1::from_bytes(&fs::read(self.ledger())?)?;
        Ok(ledger.rows().cloned().collect())
    }

    /// Write a private file into `subject-keys.v1`, admitting it first.
    fn put(&self, name: &str, bytes: &[u8]) -> TestResult {
        self.lock.list_and_read_subject_key_artifacts()?;
        Ok(write_private(&self.keys().join(name), bytes)?)
    }

    fn names(&self) -> TestResult<Vec<String>> {
        let mut names = fs::read_dir(self.keys())?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    fn open<S: EnrollmentStore>(
        &self,
        subject: SubjectId,
        store: S,
        random: FakeRandom,
    ) -> Result<OwnerEnrollmentAdapter<'_, S, FakeRandom>, BridgeError> {
        OwnerEnrollmentAdapter::open(&self.lock, subject, None, store, random)
    }
}

const fn entity(subject: SubjectId) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes(*subject.as_bytes()))
}

fn owner(subject: SubjectId) -> String {
    subject_owner_id(entity(subject)).unwrap_or_default()
}

fn hex(subject: SubjectId) -> String {
    owner(subject).replace("subject:", "")
}

fn wrap_name(subject: SubjectId, epoch: u64) -> String {
    format!("wrap.{}.{epoch}.skw1", hex(subject))
}

fn binding_name(subject: SubjectId, epoch: u64) -> String {
    format!("binding.{}.{epoch}.scb1", hex(subject))
}

fn row(subject: SubjectId, epoch: u64) -> SubjectNonceLedgerRowV1 {
    SubjectNonceLedgerRowV1 {
        owner_id: owner(subject),
        epoch,
        root_material_digest: [0x77; 32],
        store_file_id: FILE,
        data_next: 5,
        bootstrap_next: 6,
    }
}

/// Valid `SubjectKeyWrapV1` bytes for a fixture identity.
fn wrap_fixture(subject: SubjectId, epoch: u64, credential_id: &[u8]) -> TestResult<Vec<u8>> {
    let params = SubjectKeyWrapParamsV1 {
        subject_id: entity(subject),
        epoch,
        rp_id: "localhost".to_owned(),
        credential_id: credential_id.to_vec(),
        prf_input: [1; 32],
        wrap_salt: [2; 32],
        subkey_salt: [3; 32],
        wrap_nonce: [4; 12],
    };
    let root = SubjectRootKeyV1::from_bytes([5; 32]);
    let wrap = SubjectKeyWrapV1::seal(params, &root, &SubjectPrfOutputV1::from_bytes([6; 32]))?;
    Ok(wrap.to_bytes())
}

fn honest() -> HonestConfig {
    HonestConfig::standard(&CREDENTIAL_ID)
}

/// An owner bridge over `FakeSurface` and the honest fixture page.
fn bridge(page: HonestConfig) -> TestResult<Bridge> {
    let clock = FakeClock::start();
    let loopback = FakeLoopback::default();
    let page = HonestPage::new(page)
        .ok()
        .ok_or("the fixture page refused its configuration")?;
    let surface = FakeSurface::new(
        clock.clone(),
        loopback.clone(),
        Box::new(page),
        SurfaceConfig::default(),
    );
    let host = FakeHost::new(clock.clone(), surface, loopback, FakeStore::default());
    Ok(OwnerBridge::new(
        host,
        FakeRandom::seeded(1),
        clock,
        BridgeConfig::default(),
    ))
}

/// Run one enrollment of `port` with `context`, and return its outcome.
fn enroll(
    page: HonestConfig,
    context: &pos_owner_bridge::EnrollmentContext,
    port: &mut impl EnrollmentPort,
) -> TestResult<Result<(), BridgeError>> {
    Ok(bridge(page)?.enroll(context, port))
}

/// Open an adapter over `store` and run one honest enrollment through it.
fn enroll_subject<S: EnrollmentStore>(
    fixture: &Fixture,
    subject: SubjectId,
    store: S,
) -> TestResult<Result<(), BridgeError>> {
    let mut adapter = fixture.open(subject, store, FakeRandom::seeded(5))?;
    let context = adapter.context().clone();
    enroll(honest(), &context, &mut adapter)
}

/// A port that forwards to `port`, runs `before_commit` first in `commit`,
/// and commits through `committer` when one is given.
struct Interposed<'a, P> {
    port: &'a mut P,
    committer: Option<&'a mut P>,
    before_commit: Box<dyn FnMut() + 'a>,
}

impl<P: EnrollmentPort> EnrollmentPort for Interposed<'_, P> {
    type Candidate = P::Candidate;

    fn credential_unbound(&mut self, credential_id: &[u8]) -> Result<bool, OwnerError> {
        self.port.credential_unbound(credential_id)
    }

    fn seal_candidate(
        &mut self,
        prf: PrfOutput<'_>,
        inputs: SealInputs<'_>,
    ) -> Result<(Self::Candidate, RootFingerprint), OwnerError> {
        self.port.seal_candidate(prf, inputs)
    }

    fn confirm_candidate(
        &mut self,
        candidate: &Self::Candidate,
        prf: PrfOutput<'_>,
    ) -> Result<RootFingerprint, OwnerError> {
        self.port.confirm_candidate(candidate, prf)
    }

    fn commit(
        &mut self,
        candidate: Self::Candidate,
        binding: ConfirmedBinding,
    ) -> Result<(), OwnerError> {
        (self.before_commit)();
        self.committer
            .as_deref_mut()
            .unwrap_or(&mut *self.port)
            .commit(candidate, binding)
    }

    fn abandon(&mut self, candidate: Self::Candidate) {
        self.port.abandon(candidate);
    }
}

/// Which store step a [`FaultyStore`] fails.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Fail {
    Nothing,
    Staging,
    Register,
}

/// A volatile store that runs `on_staging` as step 3 begins and can fail
/// step 3 or step 6 with `DurableWrite`.
struct FaultyStore<'a> {
    inner: VolatileEnrollmentStore,
    on_staging: Box<dyn FnMut() + 'a>,
    fail: Fail,
}

impl<'a> FaultyStore<'a> {
    fn new(fail: Fail, on_staging: impl FnMut() + 'a) -> Self {
        Self {
            inner: VolatileEnrollmentStore::new(FILE),
            on_staging: Box::new(on_staging),
            fail,
        }
    }
}

impl EnrollmentStore for FaultyStore<'_> {
    fn registry_epoch_ceiling(
        &mut self,
        owner_id: &str,
        subject_id: EntityId,
    ) -> Result<u64, OwnerError> {
        self.inner.registry_epoch_ceiling(owner_id, subject_id)
    }

    fn commit_staging_record(
        &mut self,
        owner_id: &str,
        epoch: u64,
    ) -> Result<SubjectStoreFileIdV1, OwnerError> {
        (self.on_staging)();
        if self.fail == Fail::Staging {
            return Err(DURABLE_WRITE);
        }
        self.inner.commit_staging_record(owner_id, epoch)
    }

    fn register(&mut self, registration: &SubjectKeyRegistration) -> Result<(), OwnerError> {
        if self.fail == Fail::Register {
            return Err(DURABLE_WRITE);
        }
        self.inner.register(registration)
    }
}

fn staged(store: &VolatileEnrollmentStore) -> Vec<(String, u64)> {
    store
        .staging_records()
        .map(|(owner_id, epoch)| (owner_id.to_owned(), epoch))
        .collect()
}

#[test]
fn enrollment_stages_the_wrap_binding_and_row_and_registers_the_opened_epoch() -> TestResult {
    let fixture = Fixture::new()?;
    // Rows of a lower and a higher owner force the new row into the middle.
    let lower = SubjectId::from_bytes([0x05; 16]);
    fixture.write_ledger(&[row(lower, 1), row(OTHER, 8)])?;
    // A file of another name that parses as neither codec is ignored.
    fixture.put("notes", b"not a subject key")?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    store.record_epoch(&owner(SUBJECT), 2);
    let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::seeded(5))?;
    let context = adapter.context().clone();
    assert_eq!(
        (context.owner_id.as_str(), context.subject_id, context.epoch),
        (owner(SUBJECT).as_str(), SUBJECT, 3)
    );
    assert_eq!(context.owner_window, None);
    // The exclusive owner lock is held for the whole enrollment.
    assert!(fixture
        .lock
        .try_lock_subject_owner_shared(&owner(SUBJECT))
        .is_err());
    enroll(honest(), &context, &mut adapter)??;
    drop(adapter);
    assert!(fixture
        .lock
        .try_lock_subject_owner_shared(&owner(SUBJECT))
        .is_ok());

    assert_eq!(
        fixture.names()?,
        [
            binding_name(SUBJECT, 3),
            "notes".to_owned(),
            wrap_name(SUBJECT, 3)
        ]
    );
    let wrap =
        SubjectKeyWrapV1::from_bytes(&fs::read(fixture.keys().join(wrap_name(SUBJECT, 3)))?)?;
    let params = wrap.params();
    assert_eq!(
        (wrap.owner_id(), params.subject_id, params.epoch),
        (owner(SUBJECT), entity(SUBJECT), 3)
    );
    assert_eq!(params.rp_id, "localhost");
    assert_eq!(params.credential_id, CREDENTIAL_ID);
    // The wrap opens under the fixture authenticator's PRF of its PRF input.
    let mut prf = Sha256::new();
    prf.update(honest().prf_secret);
    prf.update(params.prf_input);
    let root = wrap.open(&SubjectPrfOutputV1::from_bytes(prf.finalize().into()))?;
    let digest = *root.material_digest().as_bytes();

    let binding_bytes = fs::read(fixture.keys().join(binding_name(SUBJECT, 3)))?;
    let binding = decode_subject_credential_binding(&binding_bytes)
        .ok()
        .ok_or("the staged binding did not decode")?;
    assert_eq!(
        (
            binding.owner_id(),
            binding.subject_id(),
            binding.epoch(),
            binding.credential_id()
        ),
        (
            owner(SUBJECT).as_str(),
            SUBJECT,
            3,
            CREDENTIAL_ID.as_slice()
        )
    );

    let mut new_row = row(SUBJECT, 3);
    new_row.root_material_digest = digest;
    (new_row.data_next, new_row.bootstrap_next) = (1, 1);
    assert_eq!(
        fixture.ledger_rows()?,
        [row(lower, 1), new_row, row(OTHER, 8)]
    );
    assert_eq!(
        store.registrations(),
        [SubjectKeyRegistration {
            owner_id: owner(SUBJECT),
            subject_id: entity(SUBJECT),
            epoch: 3,
            root_material_digest: digest,
        }]
    );
    assert!(staged(&store).is_empty());
    Ok(())
}

#[test]
fn a_randomness_failure_is_a_wrap_failure_that_leaves_no_trace() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::failing_after(5, 0))?;
    let context = adapter.context().clone();
    assert_eq!(enroll(honest(), &context, &mut adapter)?, Err(WRAP));
    drop(adapter);
    assert!(fixture.names()?.is_empty());
    assert!(fixture.ledger_rows()?.is_empty());
    assert!(staged(&store).is_empty());
    assert!(store.registrations().is_empty());
    Ok(())
}

#[test]
fn a_confirmation_under_another_prf_fails_the_open_and_abandons() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::seeded(5))?;
    let context = adapter.context().clone();
    let mut commits = 0;
    let mut port = Interposed {
        port: &mut adapter,
        committer: None,
        before_commit: Box::new(|| commits += 1),
    };
    let page = HonestConfig {
        substitute_get_prf: Some([0x33; 32]),
        ..honest()
    };
    assert_eq!(enroll(page, &context, &mut port)?, Err(WRAP));
    drop(port);
    drop(adapter);
    assert_eq!(commits, 0);
    assert!(fixture.names()?.is_empty());
    assert!(staged(&store).is_empty());
    Ok(())
}

#[test]
fn a_credential_that_any_wrap_or_binding_holds_is_already_bound() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    enroll_subject(&fixture, SUBJECT, &mut store)??;
    assert_eq!(
        enroll_subject(&fixture, OTHER, &mut store)?,
        Err(BridgeError::Rejected(RejectedCode::CredentialAlreadyBound))
    );
    assert_eq!(store.registrations().len(), 1);

    // An unregistered wrap alone, under any name, also holds its credential.
    let fixture = Fixture::new()?;
    fixture.put("orphan", &wrap_fixture(OTHER, 1, &CREDENTIAL_ID)?)?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        enroll_subject(&fixture, SUBJECT, &mut store)?,
        Err(BridgeError::Rejected(RejectedCode::CredentialAlreadyBound))
    );
    assert!(staged(&store).is_empty());
    Ok(())
}

#[test]
fn unrecognized_or_unreadable_inventories_refuse_opening() -> TestResult {
    // A reserved name whose file parses as neither codec.
    let fixture = Fixture::new()?;
    fixture.put(&format!("{}.tmp", binding_name(OTHER, 1)), b"torn")?;
    let store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );

    // An entry that is not a regular file.
    let fixture = Fixture::new()?;
    fixture.put("notes", b"ignored")?;
    fs::create_dir(fixture.keys().join("nested"))?;
    let store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );

    // A directory that cannot be admitted.
    let fixture = Fixture::new()?;
    fixture.put("notes", b"ignored")?;
    fs::set_permissions(fixture.keys(), Permissions::from_mode(0o755))?;
    let store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );
    Ok(())
}

#[test]
fn an_entry_that_appears_after_opening_refuses_the_unbound_check() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::seeded(5))?;
    let context = adapter.context().clone();
    fixture.put(&wrap_name(OTHER, 1), b"torn")?;
    assert_eq!(enroll(honest(), &context, &mut adapter)?, Err(REGISTRY));
    drop(adapter);
    assert!(staged(&store).is_empty());
    Ok(())
}

#[test]
fn the_epoch_is_above_every_epoch_an_artifact_names_for_the_owner() -> TestResult {
    // A file of any name counts through its parsed contents.
    let fixture = Fixture::new()?;
    fixture.put("copy", &wrap_fixture(SUBJECT, 6, &[1])?)?;
    fixture.put("foreign", &wrap_fixture(OTHER, 20, &[2])?)?;
    let opened = fixture.open(
        SUBJECT,
        VolatileEnrollmentStore::new(FILE),
        FakeRandom::seeded(5),
    );
    assert_eq!(opened?.context().epoch, 7);

    // A reserved name counts through its name, here a staging name above
    // the epoch its contents carry.
    let fixture = Fixture::new()?;
    fixture.put(
        &format!("{}.tmp", wrap_name(SUBJECT, 9)),
        &wrap_fixture(SUBJECT, 1, &[1])?,
    )?;
    let opened = fixture.open(
        SUBJECT,
        VolatileEnrollmentStore::new(FILE),
        FakeRandom::seeded(5),
    );
    assert_eq!(opened?.context().epoch, 10);
    Ok(())
}

#[test]
fn the_epoch_is_above_every_snl1_row_of_the_owner() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.write_ledger(&[row(SUBJECT, 12), row(OTHER, 30)])?;
    let opened = fixture.open(
        SUBJECT,
        VolatileEnrollmentStore::new(FILE),
        FakeRandom::seeded(5),
    );
    assert_eq!(opened?.context().epoch, 13);
    Ok(())
}

#[test]
fn opening_refuses_when_no_epoch_is_left_or_the_ledger_is_unusable() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    store.record_epoch(&owner(SUBJECT), u64::MAX);
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );

    fs::remove_file(fixture.ledger())?;
    let store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );

    write_private(&fixture.ledger(), b"not SNL1")?;
    let store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );
    Ok(())
}

#[test]
fn opening_refuses_the_nil_subject_a_held_owner_and_a_fenced_subject() -> TestResult {
    let fixture = Fixture::new()?;
    let nil = SubjectId::from_bytes([0; 16]);
    let store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        fixture.open(nil, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );

    let held = fixture
        .lock
        .try_lock_subject_owner_shared(&owner(SUBJECT))?;
    let store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(BridgeError::Unavailable(
            UnavailableCode::InterfaceUnavailable
        ))
    );
    drop(held);

    let mut store = VolatileEnrollmentStore::new(FILE);
    store.fence(entity(SUBJECT));
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );
    let store = VolatileEnrollmentStore::new(FILE);
    assert!(fixture.open(SUBJECT, store, FakeRandom::seeded(5)).is_ok());
    Ok(())
}

#[test]
fn sealing_refuses_a_context_other_than_the_adapters() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::seeded(5))?;
    let mut context = adapter.context().clone();
    context.owner_window = Some(7);
    assert_eq!(enroll(honest(), &context, &mut adapter)?, Err(REGISTRY));
    drop(adapter);
    assert!(fixture.names()?.is_empty());
    Ok(())
}

#[test]
fn commit_refuses_an_epoch_that_no_longer_follows_p3_step_2() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::seeded(5))?;
    let context = adapter.context().clone();
    assert_eq!(context.epoch, 1);
    // A later artifact of this owner moves P3 step 2 on to epoch 5.
    fixture.put("late", &wrap_fixture(SUBJECT, 4, &[9])?)?;
    assert_eq!(enroll(honest(), &context, &mut adapter)?, Err(REGISTRY));
    drop(adapter);
    assert_eq!(fixture.names()?, ["late"]);
    assert!(staged(&store).is_empty());
    Ok(())
}

#[test]
fn commit_repeats_the_unbound_check() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::seeded(5))?;
    let context = adapter.context().clone();
    let late = wrap_fixture(OTHER, 1, &CREDENTIAL_ID)?;
    let mut port = Interposed {
        port: &mut adapter,
        committer: None,
        before_commit: Box::new(|| {
            assert!(fixture.put("late", &late).is_ok());
        }),
    };
    assert_eq!(enroll(honest(), &context, &mut port)?, Err(REGISTRY));
    drop(port);
    drop(adapter);
    assert_eq!(fixture.names()?, ["late"]);
    assert!(staged(&store).is_empty());
    Ok(())
}

#[test]
fn commit_refuses_an_inventory_or_ledger_that_became_unusable() -> TestResult {
    for torn in [true, false] {
        let fixture = Fixture::new()?;
        let mut store = VolatileEnrollmentStore::new(FILE);
        let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::seeded(5))?;
        let context = adapter.context().clone();
        let mut port = Interposed {
            port: &mut adapter,
            committer: None,
            before_commit: Box::new(|| {
                let changed = if torn {
                    fixture.put(&wrap_name(OTHER, 1), b"torn")
                } else {
                    fs::remove_file(fixture.ledger()).map_err(Into::into)
                };
                assert!(changed.is_ok());
            }),
        };
        assert_eq!(enroll(honest(), &context, &mut port)?, Err(REGISTRY));
        drop(port);
        drop(adapter);
        assert!(staged(&store).is_empty());
        assert!(fixture
            .names()?
            .iter()
            .all(|name| !name.starts_with("binding")));
    }
    Ok(())
}

/// Rows of `OTHER` that fill the SNL1 ledger so closely to its 1 MiB bound
/// that no further row fits.
///
/// Each row encodes to 105 bytes (an epoch of 5 bytes and the widest store
/// file identity) after a 10-byte header: 9,986 rows take 1,048,540 bytes,
/// leaving 36, below the 85 bytes of the smallest row `SUBJECT` can add.
fn full_ledger() -> Vec<SubjectNonceLedgerRowV1> {
    (0..9_986)
        .map(|index| SubjectNonceLedgerRowV1 {
            epoch: 65_536 + index,
            store_file_id: SubjectStoreFileIdV1::Linux {
                device: u64::MAX,
                inode: u64::MAX,
            },
            data_next: 1,
            bootstrap_next: 1,
            ..row(OTHER, 1)
        })
        .collect()
}

#[test]
fn a_ledger_without_room_for_the_row_refuses_opening() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.write_ledger(&full_ledger())?;
    let store = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        fixture.open(SUBJECT, store, FakeRandom::seeded(5)).err(),
        Some(REGISTRY)
    );
    Ok(())
}

#[test]
fn commit_refuses_a_ledger_without_room_before_staging_anything() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = VolatileEnrollmentStore::new(FILE);
    let mut adapter = fixture.open(SUBJECT, &mut store, FakeRandom::seeded(5))?;
    let context = adapter.context().clone();
    let full = full_ledger();
    let mut port = Interposed {
        port: &mut adapter,
        committer: None,
        before_commit: Box::new(|| {
            assert!(fixture.write_ledger(&full).is_ok());
        }),
    };
    assert_eq!(enroll(honest(), &context, &mut port)?, Err(REGISTRY));
    drop(port);
    drop(adapter);
    assert!(staged(&store).is_empty());
    assert!(fixture.names()?.is_empty());
    assert_eq!(fixture.ledger_rows()?, full);
    Ok(())
}

#[test]
fn commit_refuses_the_candidate_and_binding_of_another_enrollment() -> TestResult {
    let fixture = Fixture::new()?;
    let (mut first, mut second) = (
        VolatileEnrollmentStore::new(FILE),
        VolatileEnrollmentStore::new(FILE),
    );
    let mut committer = fixture.open(SUBJECT, &mut first, FakeRandom::seeded(5))?;
    let mut sealer = fixture.open(OTHER, &mut second, FakeRandom::seeded(6))?;
    let context = sealer.context().clone();
    let mut port = Interposed {
        port: &mut sealer,
        committer: Some(&mut committer),
        before_commit: Box::new(|| ()),
    };
    assert_eq!(enroll(honest(), &context, &mut port)?, Err(REGISTRY));
    drop(port);
    drop((committer, sealer));
    assert!(fixture.names()?.is_empty());
    assert!(staged(&first).is_empty());
    assert!(staged(&second).is_empty());
    Ok(())
}

#[test]
fn a_failed_staging_record_stages_nothing() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = FaultyStore::new(Fail::Staging, || ());
    assert_eq!(
        enroll_subject(&fixture, SUBJECT, &mut store)?,
        Err(BridgeError::Owner(DURABLE_WRITE))
    );
    assert!(fixture.names()?.is_empty());
    assert!(fixture.ledger_rows()?.is_empty());
    assert!(staged(&store.inner).is_empty());
    Ok(())
}

#[test]
fn a_failed_wrap_or_binding_write_stops_before_the_ledger_row() -> TestResult {
    for (blocked, staged_names) in [
        (wrap_name(SUBJECT, 1), vec![wrap_name(SUBJECT, 1)]),
        (
            binding_name(SUBJECT, 1),
            vec![binding_name(SUBJECT, 1), wrap_name(SUBJECT, 1)],
        ),
    ] {
        let fixture = Fixture::new()?;
        let keys = fixture.keys();
        let mut store = FaultyStore::new(Fail::Nothing, || {
            assert!(write_private(&keys.join(&blocked), b"present").is_ok());
        });
        assert_eq!(
            enroll_subject(&fixture, SUBJECT, &mut store)?,
            Err(BridgeError::Owner(DURABLE_WRITE))
        );
        assert_eq!(fixture.names()?, staged_names);
        assert!(fixture.ledger_rows()?.is_empty());
        // The staging record stays for ADR-137 P5 recovery (immediate
        // deletion is planned in #1487).
        assert_eq!(staged(&store.inner), [(owner(SUBJECT), 1)]);
    }
    Ok(())
}

#[test]
fn a_failed_ledger_row_leaves_the_ledger_and_the_staged_files() -> TestResult {
    let fixture = Fixture::new()?;
    let blocker = fixture.state().join("subject-nonce-ledger.v1.tmp");
    let mut store = FaultyStore::new(Fail::Nothing, || {
        assert!(write_private(&blocker, b"busy").is_ok());
    });
    assert_eq!(
        enroll_subject(&fixture, SUBJECT, &mut store)?,
        Err(BridgeError::Owner(DURABLE_WRITE))
    );
    assert_eq!(
        fixture.names()?,
        [binding_name(SUBJECT, 1), wrap_name(SUBJECT, 1)]
    );
    assert!(fixture.ledger_rows()?.is_empty());

    let fixture = Fixture::new()?;
    let ledger = fixture.ledger();
    let mut store = FaultyStore::new(Fail::Nothing, || {
        assert!(write_private(&ledger, b"not SNL1").is_ok());
    });
    assert_eq!(
        enroll_subject(&fixture, SUBJECT, &mut store)?,
        Err(BridgeError::Owner(DURABLE_WRITE))
    );
    assert_eq!(fs::read(fixture.ledger())?, b"not SNL1");
    Ok(())
}

#[test]
fn a_failed_registration_leaves_every_artifact_staged() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = FaultyStore::new(Fail::Register, || ());
    assert_eq!(
        enroll_subject(&fixture, SUBJECT, &mut store)?,
        Err(BridgeError::Owner(DURABLE_WRITE))
    );
    assert_eq!(
        fixture.names()?,
        [binding_name(SUBJECT, 1), wrap_name(SUBJECT, 1)]
    );
    let rows = fixture.ledger_rows()?;
    assert_eq!(
        rows.iter()
            .map(|row| (row.owner_id.as_str(), row.epoch))
            .collect::<Vec<_>>(),
        [(owner(SUBJECT).as_str(), 1)]
    );
    assert_eq!(staged(&store.inner), [(owner(SUBJECT), 1)]);
    assert!(store.inner.registrations().is_empty());
    Ok(())
}
