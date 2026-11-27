#![cfg(any(test, feature = "test-support"))]
//! The #399 acceptance matrix (ADR-091 Migration step 3, ADR-110 E20 LE) end to
//! end: `OwnerBridge::enroll` and `OwnerBridge::unlock` run over `FakeSurface`
//! and the fixture signer, through the real enrollment and unlock adapters,
//! the durable subject key staging store (an in-memory `SqliteStore` behind
//! the adapter's store traits) and a test directory under the E16 encryptor lock.
//! Each case lives in its own module; this root holds their shared fixture.
//!
//! Cargo discovers this directory's `main.rs` as a test target without a
//! manifest entry, so the second gate empties the crate unless the adapter's
//! `test-support` feature is on, as `required-features` does for the others.
#![cfg(feature = "test-support")]
#![cfg(target_os = "linux")]

mod already_bound;
mod durable_store;
mod durable_store_wrapper;
mod missing_prf;
mod persist_failure;
mod rng_failure;
mod swapped_wraps;
mod tampered_wrap;
mod wrong_identity;
mod wrong_prf;

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pos_core::{ids::TimelineId, EntityId};
use pos_crypto::subject_key::{subject_owner_id, SubjectKeyWrapV1};
use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerRowV1, SubjectNonceLedgerV1, SubjectStoreFileIdV1,
};
use pos_owner_adapter::enrollment::{
    EnrollmentStore, OwnerEnrollmentAdapter, SubjectKeyRegistration,
};
use pos_owner_adapter::unlock::{OwnerUnlockAdapter, SubjectKeyringEntry, UnlockStore};
use pos_owner_bridge::encryptor_lock::linux::SubjectEncryptorLock;
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::stepper::FakeHost;
use pos_owner_bridge::fake::surface::{FakeSurface, SurfaceConfig};
use pos_owner_bridge::{
    BridgeConfig, BridgeError, EnrollmentContext, OwnerBridge, OwnerError, OwnerErrorKind,
    RejectedCode, UnavailableCode,
};
use pos_owner_bridge_codec::{
    decode_subject_credential_binding, SubjectCredentialBindingV1, SubjectId,
};
use pos_store::sqlite::SqliteStore;
use sha2::{Digest, Sha256};
use ulid::Ulid;

/// `N` bytes derived one-way from `label`, so no literal key material is used.
///
/// Byte `i` comes from `SHA-256(label || block)` with `block = i / 32`. The block counter
/// saturates, which no caller reaches because every caller asks for at most 32 bytes.
fn derived<const N: usize>(label: &str) -> [u8; N] {
    std::array::from_fn(|index| {
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        hasher.update([u8::try_from(index / 32).unwrap_or(u8::MAX)]);
        hasher.finalize()[index % 32]
    })
}

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Bridge = OwnerBridge<FakeHost, FakeRandom, FakeClock>;
type Enrolled = Result<(), BridgeError>;
type Unlocked = Result<SubjectKeyringEntry, BridgeError>;

/// Two subjects that one human controls: each has its own key owner.
const SUBJECT: SubjectId = SubjectId::from_bytes([0x10; 16]);
const OTHER: SubjectId = SubjectId::from_bytes([0x20; 16]);
const CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];
const OTHER_CREDENTIAL_ID: [u8; 2] = [0x90, 0x91];
const FILE: SubjectStoreFileIdV1 = SubjectStoreFileIdV1::Linux {
    device: 7,
    inode: 9,
};
/// The SNL1 store-file encoding of [`FILE`]: a three-element array, the Linux
/// tag, the device and the inode.
const FILE_BYTES: [u8; 4] = [0x83, 0x01, 0x07, 0x09];
const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);
const DURABLE_WRITE: OwnerError = OwnerError::new(OwnerErrorKind::DurableWrite);
const REGISTRY_REFUSED: BridgeError = BridgeError::Owner(REGISTRY);
const WRAP_REFUSED: BridgeError = BridgeError::Owner(OwnerError::new(OwnerErrorKind::Wrap));
const WRITE_REFUSED: BridgeError = BridgeError::Owner(DURABLE_WRITE);
const ALREADY_BOUND: BridgeError = BridgeError::Rejected(RejectedCode::CredentialAlreadyBound);
const PRF_UNSUPPORTED: BridgeError = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);
static NEXT: AtomicU64 = AtomicU64::new(0);

/// One registered identity: owner id, epoch and root fingerprint.
type Registered = (String, u64, [u8; 32]);

/// An in-memory `SqliteStore` that holds an empty P1 registry, bound to one
/// store file identity and to the Timeline of each known subject.
struct DurableEnrollmentStore {
    store: SqliteStore,
    file_id: SubjectStoreFileIdV1,
    file_bytes: Vec<u8>,
    timelines: BTreeMap<EntityId, TimelineId>,
}

/// A private test directory, removed when dropped.
struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> TestResult<Self> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pigloros-owner-matrix-{}-{nanos}-{}",
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

const fn entity(subject: SubjectId) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes(*subject.as_bytes()))
}

/// The Timeline that the durable store fences `subject` by.
const fn timeline(subject: SubjectId) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes(*subject.as_bytes()))
}

fn owner(subject: SubjectId) -> String {
    subject_owner_id(entity(subject)).unwrap_or_default()
}

fn wrap_name(subject: SubjectId, epoch: u64) -> String {
    format!(
        "wrap.{}.{epoch}.skw1",
        owner(subject).replace("subject:", "")
    )
}

fn binding_name(subject: SubjectId, epoch: u64) -> String {
    format!(
        "binding.{}.{epoch}.scb1",
        owner(subject).replace("subject:", "")
    )
}

/// The sorted file names of the wraps and bindings that `subjects` hold at epoch 1.
fn artifact_names(subjects: &[SubjectId]) -> Vec<String> {
    let mut names: Vec<String> = subjects
        .iter()
        .flat_map(|subject| [wrap_name(*subject, 1), binding_name(*subject, 1)])
        .collect();
    names.sort();
    names
}

/// The credential that the fixture authenticator holds for `subject`.
fn credential(subject: SubjectId) -> [u8; 2] {
    if subject == SUBJECT {
        CREDENTIAL_ID
    } else {
        OTHER_CREDENTIAL_ID
    }
}

/// The honest fixture page of `subject`'s authenticator.
fn page(subject: SubjectId) -> HonestConfig {
    HonestConfig::standard(&credential(subject))
}

/// An owner bridge over `FakeSurface` and the fixture page `page`.
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

/// `bytes` with the first occurrence of `field` replaced by `replacement`.
fn replaced(bytes: &[u8], field: &[u8], replacement: &[u8]) -> TestResult<Vec<u8>> {
    let start = bytes
        .windows(field.len())
        .position(|window| window == field)
        .ok_or("the field is not in the record")?;
    Ok([&bytes[..start], replacement, &bytes[start + field.len()..]].concat())
}

/// `bytes` with every byte of the first occurrence of `field` inverted.
fn inverted(bytes: &[u8], field: &[u8]) -> TestResult<Vec<u8>> {
    let flipped: Vec<u8> = field.iter().map(|byte| !byte).collect();
    replaced(bytes, field, &flipped)
}

fn sign_count(bytes: &[u8]) -> Option<u32> {
    decode_subject_credential_binding(bytes)
        .ok()
        .map(SubjectCredentialBindingV1::sign_count)
}

/// Run one unlock of `subject` at `epoch` through a bridge over `page`.
///
/// An open that the adapter refuses is the outcome, as for a failed ceremony.
fn unlock_run(
    lock: &SubjectEncryptorLock,
    store: &mut impl UnlockStore,
    subject: SubjectId,
    epoch: u64,
    page: HonestConfig,
) -> TestResult<Unlocked> {
    let mut adapter = match OwnerUnlockAdapter::open(lock, subject, epoch, store) {
        Ok(adapter) => adapter,
        Err(error) => return Ok(Err(error)),
    };
    let request = adapter.request();
    let binding = request.binding()?;
    let outcome = bridge(page)?.unlock(&binding, request.prf_input(), &mut adapter);
    Ok(outcome)
}

/// Which P3 step a [`Faulty`] store breaks.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Fail {
    /// The staging record of step 3.
    Staging,
    /// The wrap write of step 4: a file already sits at the wrap's name.
    BlockedWrap,
    /// The registration of step 6.
    Register,
}

/// The fixture's durable store, with one P3 step made to fail.
struct Faulty<'a> {
    inner: &'a mut DurableEnrollmentStore,
    fail: Fail,
    blocker: PathBuf,
}

impl EnrollmentStore for Faulty<'_> {
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
        match self.fail {
            Fail::Staging => Err(DURABLE_WRITE),
            Fail::BlockedWrap => write_private(&self.blocker, b"present")
                .or(Err(REGISTRY))
                .and_then(|()| self.inner.commit_staging_record(owner_id, epoch)),
            Fail::Register => self.inner.commit_staging_record(owner_id, epoch),
        }
    }

    fn register(&mut self, registration: &SubjectKeyRegistration) -> Result<(), OwnerError> {
        if self.fail == Fail::Register {
            Err(DURABLE_WRITE)
        } else {
            self.inner.register(registration)
        }
    }

    fn delete_staging_record(&mut self, owner_id: &str, epoch: u64) -> Result<(), OwnerError> {
        self.inner.delete_staging_record(owner_id, epoch)
    }
}

/// A held encryptor lock over a fresh test directory with an empty SNL1
/// ledger, and the durable store that enrollments register in.
struct Fixture {
    lock: SubjectEncryptorLock,
    store: DurableEnrollmentStore,
    sandbox: Sandbox,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let sandbox = Sandbox::new()?;
        let lock = SubjectEncryptorLock::acquire(&sandbox.0)?;
        let ledger = SubjectNonceLedgerV1::new(Vec::new())?;
        write_private(
            &sandbox.0.join("pigloros/subject-nonce-ledger.v1"),
            ledger.as_bytes(),
        )?;
        Ok(Self {
            lock,
            store: DurableEnrollmentStore::new(
                FILE,
                &FILE_BYTES,
                [SUBJECT, OTHER].map(|subject| (entity(subject), timeline(subject))),
            )?,
            sandbox,
        })
    }

    /// A fixture in which every one of `subjects` is enrolled at epoch 1 under
    /// its own credential.
    fn enrolled(subjects: &[SubjectId]) -> TestResult<Self> {
        let mut fixture = Self::new()?;
        for subject in subjects {
            fixture.enroll(*subject, page(*subject))??;
        }
        Ok(fixture)
    }

    fn keys(&self) -> PathBuf {
        self.sandbox.0.join("pigloros/subject-keys.v1")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.keys().join(name)
    }

    fn read(&self, name: &str) -> TestResult<Vec<u8>> {
        Ok(fs::read(self.path(name))?)
    }

    fn put(&self, name: &str, bytes: &[u8]) -> TestResult {
        Ok(write_private(&self.path(name), bytes)?)
    }

    fn names(&self) -> TestResult<Vec<String>> {
        let mut names = fs::read_dir(self.keys())?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    fn ledger_rows(&self) -> TestResult<Vec<SubjectNonceLedgerRowV1>> {
        let path = self.sandbox.0.join("pigloros/subject-nonce-ledger.v1");
        let ledger = SubjectNonceLedgerV1::from_bytes(&fs::read(path)?)?;
        Ok(ledger.rows().cloned().collect())
    }

    fn wrap(&self, subject: SubjectId, epoch: u64) -> TestResult<SubjectKeyWrapV1> {
        Ok(SubjectKeyWrapV1::from_bytes(
            &self.read(&wrap_name(subject, epoch))?,
        )?)
    }

    /// The root fingerprint the store registered for `subject` at `epoch`.
    fn digest(&self, subject: SubjectId, epoch: u64) -> TestResult<[u8; 32]> {
        let owner_id = owner(subject);
        self.store
            .registrations()?
            .into_iter()
            .find(|(registered, registered_epoch, _)| {
                *registered == owner_id && *registered_epoch == epoch
            })
            .map(|(_, _, digest)| digest)
            .ok_or_else(|| "no registration of that identity".into())
    }

    /// The staging records the store still holds.
    fn staged(&self) -> TestResult<Vec<(String, u64)>> {
        Ok(self.store.staging_records()?)
    }

    /// The signature counter of the stored binding, zero if there is none.
    fn stored_count(&self, subject: SubjectId, epoch: u64) -> u32 {
        self.read(&binding_name(subject, epoch))
            .ok()
            .and_then(|bytes| sign_count(&bytes))
            .unwrap_or_default()
    }

    /// Open an enrollment of `subject`, let `edit` change the context that the
    /// bridge enrolls under, and run the enrollment over `page`.
    fn enroll_as(
        &mut self,
        subject: SubjectId,
        page: HonestConfig,
        random: FakeRandom,
        edit: impl FnOnce(&mut EnrollmentContext),
    ) -> TestResult<Enrolled> {
        let opened =
            OwnerEnrollmentAdapter::open(&self.lock, subject, None, &mut self.store, random);
        let mut adapter = match opened {
            Ok(adapter) => adapter,
            Err(error) => return Ok(Err(error)),
        };
        let mut context = adapter.context().clone();
        edit(&mut context);
        let outcome = bridge(page)?.enroll(&context, &mut adapter);
        Ok(outcome)
    }

    /// One honest enrollment of `subject` over `page`.
    fn enroll(&mut self, subject: SubjectId, page: HonestConfig) -> TestResult<Enrolled> {
        let seed = u64::from(subject.as_bytes()[0]);
        self.enroll_as(subject, page, FakeRandom::seeded(seed), |_| ())
    }

    /// One enrollment of `subject` whose store breaks `fail`.
    fn enroll_faulty(&mut self, subject: SubjectId, fail: Fail) -> TestResult<Enrolled> {
        let blocker = self.path(&wrap_name(subject, 1));
        let store = Faulty {
            inner: &mut self.store,
            fail,
            blocker,
        };
        let opened =
            OwnerEnrollmentAdapter::open(&self.lock, subject, None, store, FakeRandom::seeded(5));
        let mut adapter = match opened {
            Ok(adapter) => adapter,
            Err(error) => return Ok(Err(error)),
        };
        let context = adapter.context().clone();
        let outcome = bridge(page(subject))?.enroll(&context, &mut adapter);
        Ok(outcome)
    }

    /// One unlock of `subject` at `epoch` over `page`, started one Get after
    /// the stored counter so that an honest authenticator advances it.
    fn unlock(
        &mut self,
        subject: SubjectId,
        epoch: u64,
        page: HonestConfig,
    ) -> TestResult<Unlocked> {
        let page = HonestConfig {
            start_counter: self.stored_count(subject, epoch),
            ..page
        };
        unlock_run(&self.lock, &mut self.store, subject, epoch, page)
    }

    /// The same unlock against `store` instead of the fixture's own.
    fn unlock_against(
        &self,
        store: &mut impl UnlockStore,
        subject: SubjectId,
        epoch: u64,
    ) -> TestResult<Unlocked> {
        let page = HonestConfig {
            start_counter: self.stored_count(subject, epoch),
            ..page(subject)
        };
        unlock_run(&self.lock, store, subject, epoch, page)
    }
}
