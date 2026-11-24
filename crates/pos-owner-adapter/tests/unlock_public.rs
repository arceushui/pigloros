#![cfg(any(test, feature = "test-support"))]
//! The real unlock adapter behind `OwnerBridge::unlock` (ADR-110 §8 unlock,
//! §9 binding update; ADR-097 §5 cross-checks), driven by `FakeSurface`, the
//! fixture signer and a test directory under the E16 encryptor lock. Each
//! subject key is first enrolled through the real enrollment adapter.
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
use pos_crypto::subject_nonce_ledger::{SubjectNonceLedgerV1, SubjectStoreFileIdV1};
use pos_owner_adapter::enrollment::{
    EnrollmentStore, OwnerEnrollmentAdapter, SubjectKeyRegistration, VolatileEnrollmentStore,
};
use pos_owner_adapter::unlock::{OwnerUnlockAdapter, SubjectKeyringEntry, UnlockStore};
use pos_owner_bridge::encryptor_lock::linux::SubjectEncryptorLock;
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage};
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::fake::stepper::FakeHost;
use pos_owner_bridge::fake::surface::{FakeSurface, SurfaceConfig};
use pos_owner_bridge::{
    BindingUpdate, BridgeConfig, BridgeError, OwnerBridge, OwnerError, OwnerErrorKind, PrfOutput,
    UnavailableCode, UnlockPort,
};
use pos_owner_bridge_codec::{
    decode_subject_credential_binding, encode_subject_credential_binding,
    SubjectCredentialBindingInputV1, SubjectCredentialBindingV1, SubjectId,
    MAX_SUBJECT_CREDENTIAL_BINDING_BYTES,
};
use sha2::{Digest, Sha256};
use ulid::Ulid;
use zeroize::Zeroizing;

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

const SUBJECT: SubjectId = SubjectId::from_bytes([0x10; 16]);
const OTHER: SubjectId = SubjectId::from_bytes([0x20; 16]);
const CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];
const SECOND_CREDENTIAL_ID: [u8; 2] = [0x90, 0x91];
const FILE: SubjectStoreFileIdV1 = SubjectStoreFileIdV1::Linux {
    device: 7,
    inode: 9,
};
const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);
const WRAP_REFUSED: BridgeError = BridgeError::Owner(OwnerError::new(OwnerErrorKind::Wrap));
const REGISTRY_REFUSED: BridgeError = BridgeError::Owner(REGISTRY);
const WRITE_REFUSED: BridgeError =
    BridgeError::Owner(OwnerError::new(OwnerErrorKind::DurableWrite));
/// A credential ID that no enrolled wrap names.
static FOREIGN_CREDENTIAL_ID: [u8; 1] = [0x99];
static NEXT: AtomicU64 = AtomicU64::new(0);

/// A private test directory, removed when dropped.
struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> TestResult<Self> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pigloros-owner-unlock-{}-{nanos}-{}",
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

/// A held encryptor lock over a fresh test directory with an empty SNL1
/// ledger, and the volatile store that enrollments register in.
struct Fixture {
    lock: SubjectEncryptorLock,
    store: VolatileEnrollmentStore,
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
            store: VolatileEnrollmentStore::new(FILE),
            sandbox,
        })
    }

    /// A fixture with `SUBJECT` enrolled at epoch 1 under `CREDENTIAL_ID`
    /// and the page `first`, and at epoch 2 under `SECOND_CREDENTIAL_ID`.
    fn enrolled(first: HonestConfig) -> TestResult<Self> {
        let mut fixture = Self::new()?;
        fixture.enroll(first, 5)?;
        fixture.enroll(HonestConfig::standard(&SECOND_CREDENTIAL_ID), 6)?;
        Ok(fixture)
    }

    fn enroll(&mut self, page: HonestConfig, seed: u64) -> TestResult {
        let mut adapter = OwnerEnrollmentAdapter::open(
            &self.lock,
            SUBJECT,
            None,
            &mut self.store,
            FakeRandom::seeded(seed),
        )?;
        let context = adapter.context().clone();
        bridge(page)?.enroll(&context, &mut adapter)?;
        Ok(())
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

    fn digest(&self, epoch: u64) -> TestResult<[u8; 32]> {
        self.store
            .registrations()
            .iter()
            .find(|registration| registration.epoch == epoch)
            .map(|registration| registration.root_material_digest)
            .ok_or_else(|| "no registration of that epoch".into())
    }

    fn wrap(&self, epoch: u64) -> TestResult<SubjectKeyWrapV1> {
        Ok(SubjectKeyWrapV1::from_bytes(
            &self.read(&wrap_name(epoch))?,
        )?)
    }
}

const fn entity(subject: SubjectId) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes(*subject.as_bytes()))
}

fn owner(subject: SubjectId) -> String {
    subject_owner_id(entity(subject)).unwrap_or_default()
}

fn hex() -> String {
    owner(SUBJECT).replace("subject:", "")
}

fn wrap_name(epoch: u64) -> String {
    format!("wrap.{}.{epoch}.skw1", hex())
}

fn binding_name(epoch: u64) -> String {
    format!("binding.{}.{epoch}.scb1", hex())
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

/// Open an unlock of `SUBJECT` at `epoch`.
fn open<'a>(
    lock: &'a SubjectEncryptorLock,
    store: &mut impl UnlockStore,
    epoch: u64,
) -> Result<OwnerUnlockAdapter<'a>, BridgeError> {
    OwnerUnlockAdapter::open(lock, SUBJECT, epoch, store)
}

/// Run one unlock of `adapter` through a bridge over `page`, started one Get
/// after enrollment's confirmation so its counter passes the enrolled one.
fn unlock(
    mut page: HonestConfig,
    adapter: &mut OwnerUnlockAdapter<'_>,
) -> TestResult<Result<SubjectKeyringEntry, BridgeError>> {
    page.start_counter = 1;
    let request = adapter.request();
    let binding = request.binding()?;
    let outcome = bridge(page)?.unlock(&binding, request.prf_input(), adapter);
    Ok(outcome)
}

/// The fixture authenticator's PRF of `prf_input`.
fn prf(prf_input: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(honest().prf_secret);
    hasher.update(prf_input);
    Zeroizing::new(hasher.finalize().into())
}

/// Call `open_pending` directly with the fixture PRF of the adapter's wrap.
fn open_pending(adapter: &mut OwnerUnlockAdapter<'_>) -> Result<(), BridgeError> {
    let slot = prf(adapter.request().prf_input());
    let opened = adapter.open_pending(PrfOutput::new(&slot));
    opened.map(drop).map_err(BridgeError::Owner)
}

const fn update(sign_count: u32, backup_state: bool) -> BindingUpdate {
    BindingUpdate {
        sign_count,
        backup_state,
    }
}

const fn input_of(binding: SubjectCredentialBindingV1<'_>) -> SubjectCredentialBindingInputV1<'_> {
    SubjectCredentialBindingInputV1 {
        owner_id: binding.owner_id(),
        subject_id: binding.subject_id(),
        epoch: binding.epoch(),
        credential_id: binding.credential_id(),
        user_handle: binding.user_handle(),
        public_key: binding.public_key(),
        backup_eligible: binding.backup_eligible(),
        backup_state: binding.backup_state(),
        sign_count: binding.sign_count(),
        transports: binding.transports(),
    }
}

/// `bytes`, a binding, re-encoded with `edit` applied to its fields.
fn edited(
    bytes: &[u8],
    edit: impl FnOnce(&mut SubjectCredentialBindingInputV1<'_>),
) -> TestResult<Vec<u8>> {
    let stored = decode_subject_credential_binding(bytes)
        .ok()
        .ok_or("the binding did not decode")?;
    let mut input = input_of(stored);
    edit(&mut input);
    let binding = SubjectCredentialBindingV1::new(input)
        .ok()
        .ok_or("the edited binding is invalid")?;
    let mut buffer = [0_u8; MAX_SUBJECT_CREDENTIAL_BINDING_BYTES];
    let length = encode_subject_credential_binding(&binding, &mut buffer)
        .ok()
        .ok_or("the edited binding did not encode")?;
    Ok(buffer[..length].to_vec())
}

fn sign_count(bytes: &[u8]) -> Option<u32> {
    decode_subject_credential_binding(bytes)
        .ok()
        .map(SubjectCredentialBindingV1::sign_count)
}

/// Valid `SubjectKeyWrapV1` bytes for `SUBJECT` at epoch 1 under `rp_id`.
fn wrap_fixture(rp_id: &str, salt: u8) -> TestResult<Vec<u8>> {
    let params = SubjectKeyWrapParamsV1 {
        subject_id: entity(SUBJECT),
        epoch: 1,
        rp_id: rp_id.to_owned(),
        credential_id: CREDENTIAL_ID.to_vec(),
        prf_input: derived("wrap fixture prf input"),
        wrap_salt: derived(&format!("wrap fixture wrap salt {salt}")),
        subkey_salt: derived("wrap fixture subkey salt"),
        wrap_nonce: derived("wrap fixture wrap nonce"),
    };
    let root = SubjectRootKeyV1::from_bytes(derived("wrap fixture root"));
    let wrap = SubjectKeyWrapV1::seal(
        params,
        &root,
        &SubjectPrfOutputV1::from_bytes(derived("wrap fixture prf output")),
    )?;
    Ok(wrap.to_bytes())
}

fn decode(bytes: &[u8]) -> TestResult<SubjectCredentialBindingV1<'_>> {
    let binding = decode_subject_credential_binding(bytes)
        .ok()
        .ok_or("the binding did not decode")?;
    Ok(binding)
}

/// A store whose registry identity has the root fingerprint `.0`.
struct Fingerprint([u8; 32]);

impl UnlockStore for Fingerprint {
    fn registered_root_material_digest(
        &mut self,
        _: &str,
        _: EntityId,
        _: u64,
    ) -> Result<[u8; 32], OwnerError> {
        Ok(self.0)
    }
}

#[test]
fn unlock_cross_checks_updates_the_binding_and_releases_the_root_and_wrap() -> TestResult {
    let mut fixture = Fixture::enrolled(honest())?;
    let names = fixture.names()?;
    let wraps = [fixture.read(&wrap_name(1))?, fixture.read(&wrap_name(2))?];
    let cases = [
        (
            1,
            honest(),
            fixture.read(&binding_name(1))?,
            fixture.digest(1)?,
        ),
        (
            2,
            HonestConfig::standard(&SECOND_CREDENTIAL_ID),
            fixture.read(&binding_name(2))?,
            fixture.digest(2)?,
        ),
    ];
    assert_ne!(cases[0].3, cases[1].3);
    // Each epoch unlocks on its own, beside the other epoch's artifacts.
    for (epoch, page, binding, digest) in cases {
        let wrap = fixture.wrap(epoch)?;
        let mut adapter = open(&fixture.lock, &mut fixture.store, epoch)?;
        let request = adapter.request();
        assert_eq!(request.prf_input(), &wrap.params().prf_input);
        assert_eq!(request.binding()?, decode(&binding)?);
        // The owner lock is held shared: another shared hold coexists with
        // it, the exclusive lock does not.
        assert!(fixture
            .lock
            .try_lock_subject_owner_shared(&owner(SUBJECT))
            .is_ok());
        assert!(fixture
            .lock
            .try_lock_subject_owner_exclusive(&owner(SUBJECT))
            .is_err());

        let entry = unlock(page, &mut adapter)??;
        assert_eq!(entry.root_material_digest(), digest);
        assert_eq!(entry.wrap(), &wrap);
        drop(adapter);
        assert!(fixture
            .lock
            .try_lock_subject_owner_exclusive(&owner(SUBJECT))
            .is_ok());

        // Only this epoch's binding changed, to exactly the stored binding
        // with the accepted counter, and no staging name is left behind.
        let expected = edited(&binding, |input| input.sign_count = 2)?;
        assert_eq!(fixture.read(&binding_name(epoch))?, expected);
        assert_eq!(fixture.names()?, names);
    }
    assert_eq!(fixture.read(&wrap_name(1))?, wraps[0]);
    assert_eq!(fixture.read(&wrap_name(2))?, wraps[1]);
    Ok(())
}

#[test]
fn a_binding_update_follows_the_counter_and_backup_rules_of_the_opened_binding() -> TestResult {
    let page = HonestConfig {
        zero_counter: true,
        ..honest()
    };
    let mut fixture = Fixture::enrolled(page)?;
    let name = binding_name(1);
    let enrolled = fixture.read(&name)?;
    assert_eq!(sign_count(&enrolled), Some(0));
    let mut adapter = open(&fixture.lock, &mut fixture.store, 1)?;
    // Nothing is written before a root has been opened.
    assert_eq!(
        adapter.persist_binding_update(&update(0, false)),
        Err(REGISTRY)
    );
    open_pending(&mut adapter)?;
    // A zero counter may stay zero; any other counter must strictly advance
    // over the last one written.
    for (count, accepted) in [
        (0, true),
        (3, true),
        (3, false),
        (2, false),
        (0, false),
        (4, true),
    ] {
        let before = fixture.read(&name)?;
        let outcome = adapter.persist_binding_update(&update(count, false));
        if accepted {
            assert_eq!(outcome, Ok(()), "{count}");
            let expected = edited(&enrolled, |input| input.sign_count = count)?;
            assert_eq!(fixture.read(&name)?, expected, "{count}");
        } else {
            assert_eq!(outcome, Err(REGISTRY), "{count}");
            assert_eq!(fixture.read(&name)?, before, "{count}");
        }
    }
    // A backup state without backup eligibility is refused.
    assert_eq!(
        adapter.persist_binding_update(&update(5, true)),
        Err(REGISTRY)
    );
    assert_eq!(sign_count(&fixture.read(&name)?), Some(4));
    Ok(())
}

#[test]
fn a_wrong_prf_fails_the_open_and_leaves_the_binding() -> TestResult {
    let mut fixture = Fixture::enrolled(honest())?;
    let binding = fixture.read(&binding_name(1))?;
    let mut adapter = open(&fixture.lock, &mut fixture.store, 1)?;
    let page = HonestConfig {
        substitute_get_prf: Some(derived("substituted prf output")),
        ..honest()
    };
    assert_eq!(unlock(page, &mut adapter)?.err(), Some(WRAP_REFUSED));
    // No root was opened, so no update is accepted either.
    assert_eq!(
        adapter.persist_binding_update(&update(2, false)),
        Err(REGISTRY)
    );
    assert_eq!(fixture.read(&binding_name(1))?, binding);
    Ok(())
}

#[test]
fn a_later_failed_open_withdraws_the_earlier_success() -> TestResult {
    let mut fixture = Fixture::enrolled(honest())?;
    let binding = fixture.read(&binding_name(1))?;
    let mut adapter = open(&fixture.lock, &mut fixture.store, 1)?;
    open_pending(&mut adapter)?;
    let wrong = Zeroizing::new(derived("wrong prf output"));
    assert_eq!(
        adapter.open_pending(PrfOutput::new(&wrong)).err(),
        Some(OwnerError::new(OwnerErrorKind::Wrap))
    );
    assert_eq!(
        adapter.persist_binding_update(&update(2, false)),
        Err(REGISTRY)
    );
    assert_eq!(fixture.read(&binding_name(1))?, binding);
    // A fresh successful open lets the same update through.
    open_pending(&mut adapter)?;
    assert_eq!(adapter.persist_binding_update(&update(2, false)), Ok(()));
    assert_eq!(sign_count(&fixture.read(&binding_name(1))?), Some(2));
    Ok(())
}

#[test]
fn a_root_whose_fingerprint_is_not_the_registry_identitys_is_refused() -> TestResult {
    let fixture = Fixture::enrolled(honest())?;
    let binding = fixture.read(&binding_name(1))?;
    let mut adapter = open(&fixture.lock, &mut Fingerprint(derived("fingerprint")), 1)?;
    assert_eq!(
        unlock(honest(), &mut adapter)?.err(),
        Some(REGISTRY_REFUSED)
    );
    assert_eq!(
        adapter.persist_binding_update(&update(2, false)),
        Err(REGISTRY)
    );
    assert_eq!(fixture.read(&binding_name(1))?, binding);
    Ok(())
}

#[test]
fn an_update_writes_only_over_the_wrap_and_binding_it_opened() -> TestResult {
    let mut fixture = Fixture::enrolled(honest())?;
    let name = binding_name(1);
    // Two unlocks hold the shared lock together. The first update wins; the
    // second, which opened the older binding, is refused.
    let mut first = open(&fixture.lock, &mut fixture.store, 1)?;
    let mut second = open(&fixture.lock, &mut fixture.store, 1)?;
    open_pending(&mut first)?;
    open_pending(&mut second)?;
    assert_eq!(first.persist_binding_update(&update(2, false)), Ok(()));
    assert_eq!(
        second.persist_binding_update(&update(3, false)),
        Err(REGISTRY)
    );
    assert_eq!(sign_count(&fixture.read(&name)?), Some(2));
    // The winner's next update applies over the binding it wrote.
    assert_eq!(first.persist_binding_update(&update(3, false)), Ok(()));
    assert_eq!(sign_count(&fixture.read(&name)?), Some(3));
    drop((first, second));

    // A wrap replaced after opening refuses the update, though the binding
    // and the cross-check still hold.
    let mut adapter = open(&fixture.lock, &mut fixture.store, 1)?;
    open_pending(&mut adapter)?;
    let wrap = fixture.read(&wrap_name(1))?;
    fixture.put(&wrap_name(1), &wrap_fixture("localhost", 7)?)?;
    assert_eq!(
        adapter.persist_binding_update(&update(4, false)),
        Err(REGISTRY)
    );
    assert_eq!(sign_count(&fixture.read(&name)?), Some(3));
    fixture.put(&wrap_name(1), &wrap)?;
    assert_eq!(adapter.persist_binding_update(&update(4, false)), Ok(()));
    assert_eq!(sign_count(&fixture.read(&name)?), Some(4));
    Ok(())
}

#[test]
fn a_failed_binding_replacement_is_a_durable_write_failure_and_releases_no_root() -> TestResult {
    let mut fixture = Fixture::enrolled(honest())?;
    let path = fixture.path(&binding_name(1));
    let enrolled = fixture.read(&binding_name(1))?;
    let mut adapter = open(&fixture.lock, &mut fixture.store, 1)?;
    // The replacement refuses a binding file that is not private.
    fs::set_permissions(&path, Permissions::from_mode(0o644))?;
    assert_eq!(unlock(honest(), &mut adapter)?.err(), Some(WRITE_REFUSED));
    assert_eq!(fixture.read(&binding_name(1))?, enrolled);
    // The failure kept the opened binding, so a later unlock still updates.
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    let entry = unlock(honest(), &mut adapter)?;
    let digest = entry
        .as_ref()
        .map(SubjectKeyringEntry::root_material_digest);
    assert_eq!(digest.ok(), Some(fixture.digest(1)?));
    assert_eq!(sign_count(&fixture.read(&binding_name(1))?), Some(2));
    Ok(())
}

#[test]
fn opening_refuses_the_nil_subject_an_unknown_epoch_a_held_owner_and_no_registration() -> TestResult
{
    let mut fixture = Fixture::enrolled(honest())?;
    let nil = OwnerUnlockAdapter::open(
        &fixture.lock,
        SubjectId::from_bytes([0; 16]),
        1,
        &mut fixture.store,
    );
    assert_eq!(nil.err(), Some(REGISTRY_REFUSED));
    for epoch in [0, 3] {
        let opened = open(&fixture.lock, &mut fixture.store, epoch);
        assert_eq!(opened.err(), Some(REGISTRY_REFUSED), "{epoch}");
    }
    let held = fixture
        .lock
        .try_lock_subject_owner_exclusive(&owner(SUBJECT))?;
    assert_eq!(
        open(&fixture.lock, &mut fixture.store, 1).err(),
        Some(BridgeError::Unavailable(
            UnavailableCode::InterfaceUnavailable
        ))
    );
    drop(held);
    // The store refuses an identity it has not registered.
    let mut empty = VolatileEnrollmentStore::new(FILE);
    assert_eq!(
        open(&fixture.lock, &mut empty, 1).err(),
        Some(REGISTRY_REFUSED)
    );
    assert!(open(&fixture.lock, &mut fixture.store, 1).is_ok());
    Ok(())
}

type Change = fn(&Fixture) -> TestResult;

#[test]
fn opening_refuses_missing_duplicate_misnamed_and_unrecognized_artifacts() -> TestResult {
    let changes: [(&str, Change); 10] = [
        ("missing binding", |fixture| {
            Ok(fs::remove_file(fixture.path(&binding_name(1)))?)
        }),
        ("missing wrap", |fixture| {
            Ok(fs::remove_file(fixture.path(&wrap_name(1)))?)
        }),
        (
            "parseable binding copy under a non-reserved name",
            |fixture| {
                let name = binding_name(1);
                fixture.put(&format!("{name}.bak"), &fixture.read(&name)?)
            },
        ),
        ("staged binding", |fixture| {
            let name = binding_name(1);
            fixture.put(&format!("{name}.tmp"), &fixture.read(&name)?)
        }),
        ("wrap copy", |fixture| {
            fixture.put("copy", &fixture.read(&wrap_name(1))?)
        }),
        ("renamed binding", |fixture| {
            Ok(fs::rename(
                fixture.path(&binding_name(1)),
                fixture.path("renamed"),
            )?)
        }),
        ("renamed wrap", |fixture| {
            Ok(fs::rename(
                fixture.path(&wrap_name(1)),
                fixture.path("renamed"),
            )?)
        }),
        ("swapped names", |fixture| {
            let (wrap, binding) = (
                fixture.read(&wrap_name(1))?,
                fixture.read(&binding_name(1))?,
            );
            fixture.put(&wrap_name(1), &binding)?;
            fixture.put(&binding_name(1), &wrap)
        }),
        ("torn reserved name", |fixture| {
            fixture.put(&format!("{}.tmp", wrap_name(9)), b"torn")
        }),
        ("nested directory", |fixture| {
            Ok(fs::create_dir(fixture.path("nested"))?)
        }),
    ];
    for (case, change) in changes {
        let mut fixture = Fixture::enrolled(honest())?;
        assert!(open(&fixture.lock, &mut fixture.store, 1).is_ok(), "{case}");
        change(&fixture)?;
        let opened = open(&fixture.lock, &mut fixture.store, 1);
        assert_eq!(opened.err(), Some(REGISTRY_REFUSED), "{case}");
    }
    Ok(())
}

#[test]
fn opening_refuses_a_wrap_outside_localhost_and_a_binding_of_another_subject_or_credential(
) -> TestResult {
    let changes: [(&str, Change); 3] = [
        ("foreign RP", |fixture| {
            fixture.put(&wrap_name(1), &wrap_fixture("example.com", 2)?)
        }),
        ("foreign subject", |fixture| {
            let name = binding_name(1);
            let bytes = edited(&fixture.read(&name)?, |input| input.subject_id = OTHER)?;
            fixture.put(&name, &bytes)
        }),
        ("foreign credential", |fixture| {
            let name = binding_name(1);
            let bytes = edited(&fixture.read(&name)?, |input| {
                input.credential_id = FOREIGN_CREDENTIAL_ID.as_slice();
            })?;
            fixture.put(&name, &bytes)
        }),
    ];
    for (case, change) in changes {
        let mut fixture = Fixture::enrolled(honest())?;
        change(&fixture)?;
        let opened = open(&fixture.lock, &mut fixture.store, 1);
        assert_eq!(opened.err(), Some(REGISTRY_REFUSED), "{case}");
    }
    // The same replacement wrap under `localhost` passes the cross-check:
    // only the RP ID refused it above.
    let mut fixture = Fixture::enrolled(honest())?;
    fixture.put(&wrap_name(1), &wrap_fixture("localhost", 2)?)?;
    assert!(open(&fixture.lock, &mut fixture.store, 1).is_ok());
    Ok(())
}

#[test]
fn the_volatile_store_returns_the_digest_of_the_exact_registration_only() -> TestResult {
    let mut store = VolatileEnrollmentStore::new(FILE);
    let registration = SubjectKeyRegistration {
        owner_id: owner(SUBJECT),
        subject_id: entity(SUBJECT),
        epoch: 2,
        root_material_digest: derived("registration root material digest"),
    };
    store
        .commit_staging_record(&registration.owner_id, 2)
        .map_err(BridgeError::Owner)?;
    store.register(&registration).map_err(BridgeError::Owner)?;
    let owner_id = owner(SUBJECT);
    assert_eq!(
        store.registered_root_material_digest(&owner_id, entity(SUBJECT), 2),
        Ok(derived("registration root material digest"))
    );
    for (owner_id, subject, epoch) in [
        (owner_id.clone(), SUBJECT, 1),
        (owner_id, OTHER, 2),
        (owner(OTHER), SUBJECT, 2),
    ] {
        assert_eq!(
            store.registered_root_material_digest(&owner_id, entity(subject), epoch),
            Err(REGISTRY)
        );
    }
    Ok(())
}
