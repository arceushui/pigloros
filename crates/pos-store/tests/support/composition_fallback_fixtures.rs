//! Shared composition fallback registry fixtures (ADR-119 section 4.3, slice #663).
//!
//! [`Backend`] abstracts the store under test, so the shared vectors run unchanged on the
//! Memory adapter and on the `SQLite` adapter. [`Harness`] owns one provisioned store, one
//! target Timeline, and the composition's host entity; [`World`] holds five implementation
//! keys whose Plugin IDs are pairwise distinct. The public tests and the adapter unit tests
//! include this one file; the items are public so that no test crate sees them as unused.

use std::{error::Error, sync::Arc};

use pos_core::{
    store::{EventStore, SeqRange},
    CanonicalBytes, CompositionPinV1, DomainFallbackPolicyV1, EntityId, ErasureContainmentGateV1,
    FallbackActivationModeV1, FallbackActivationOriginV1, FallbackEntryV1,
    FallbackTriggerBasisV1, FallbackTriggerCodeV1, Hash, Hasher, ImplementationKeyV1, Seq,
    TimelineId,
};
#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;
use pos_store::{
    composition_fallback_registry::{
        CompositionFallbackRegistryErrorV1, CompositionFallbackRegistryV1,
        CompositionFallbackTargetV1, FallbackActivateRequestV1, FallbackCommitReceiptV1,
        FallbackConformanceSetsV1, FallbackDeclareRequestV1,
    },
    memory::MemoryStore,
};

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;
pub type Registry<T> = Result<T, CompositionFallbackRegistryErrorV1>;
pub type RegistryError = CompositionFallbackRegistryErrorV1;

/// The composition scope of every fixture policy.
pub const SCOPE: &str = "scope";
/// The entry key of the first fixture entry.
pub const ALPHA: &str = "alpha";
/// The entry key of the second fixture entry.
pub const BETA: &str = "beta";

/// Keeps the temporary directory of a file-backed fixture store alive; `None` for Memory.
pub struct Guard {
    pub directory: Option<tempfile::TempDir>,
}

/// A store under test: a composition fallback registry that also appends and reads Events.
pub trait Backend: CompositionFallbackRegistryV1 + EventStore + Sized {
    /// A fresh store with an open erasure gate and `hasher` (BLAKE3 when `None`).
    ///
    /// # Errors
    /// Returns the fixture construction error.
    fn build(hasher: Option<Box<dyn Hasher>>) -> TestResult<(Self, Guard)>;
}

impl Backend for MemoryStore {
    fn build(hasher: Option<Box<dyn Hasher>>) -> TestResult<(Self, Guard)> {
        let mut store = hasher.map_or_else(Self::new, Self::with_hasher);
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        Ok((store, Guard { directory: None }))
    }
}

#[cfg(feature = "sqlite")]
impl Backend for SqliteStore {
    fn build(hasher: Option<Box<dyn Hasher>>) -> TestResult<(Self, Guard)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("composition-fallback.db");
        let path = path.to_str().ok_or("the temporary path is not UTF-8")?;
        let mut store = match hasher {
            Some(hasher) => Self::open_with_hasher(path, hasher)?,
            None => Self::open(path)?,
        };
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let directory = Some(directory);
        Ok((store, Guard { directory }))
    }
}

/// A hasher whose payload digest is not BLAKE3-256.
pub struct OffsetHasher;

impl Hasher for OffsetHasher {
    fn genesis_hash(&self) -> Hash {
        Hash::zero()
    }

    fn hash_payload(&self, payload: &CanonicalBytes) -> Hash {
        let offset = [payload.as_slice(), b"offset".as_slice()].concat();
        Hash::from_bytes(*blake3::hash(&offset).as_bytes())
    }

    fn hash_event(
        &self,
        previous_hash: &Hash,
        event_id_bytes: &[u8],
        payload: &CanonicalBytes,
    ) -> Hash {
        pos_crypto::chain::hash_event(previous_hash, event_id_bytes, payload)
    }
}

/// One implementation key of the fixture world.
///
/// # Errors
/// Returns the record error of an invalid key.
pub fn key(plugin_id: &str, release: u8) -> TestResult<ImplementationKeyV1> {
    let digest = Hash::from_bytes([release; 32]);
    let (plugin_id, version) = (plugin_id.to_owned(), "1.0.0".to_owned());
    Ok(ImplementationKeyV1::new(plugin_id, version, digest)?)
}

/// Five implementation keys with pairwise distinct Plugin IDs.
pub struct World {
    pub a: ImplementationKeyV1,
    pub b: ImplementationKeyV1,
    pub c: ImplementationKeyV1,
    pub d: ImplementationKeyV1,
    pub e: ImplementationKeyV1,
}

impl World {
    /// The fixture world.
    ///
    /// # Errors
    /// Returns the record error of an invalid key.
    pub fn new() -> TestResult<Self> {
        Ok(Self {
            a: key("plugin-a", 1)?,
            b: key("plugin-b", 2)?,
            c: key("plugin-c", 3)?,
            d: key("plugin-d", 4)?,
            e: key("plugin-e", 5)?,
        })
    }

    /// `entry_key` with `primary`, `candidates`, triggers 2 and 3, and `mode`.
    ///
    /// # Errors
    /// Returns the record error of an invalid entry.
    pub fn entry(
        entry_key: &str,
        primary: &ImplementationKeyV1,
        candidates: &[&ImplementationKeyV1],
        mode: FallbackActivationModeV1,
    ) -> TestResult<FallbackEntryV1> {
        let pins = candidates
            .iter()
            .copied()
            .map(pin)
            .collect::<TestResult<Vec<_>>>()?;
        let triggers = vec![
            FallbackTriggerCodeV1::ComponentTrap,
            FallbackTriggerCodeV1::ResourceLimit,
        ];
        let primary = pin(primary)?;
        let key = entry_key.to_owned();
        Ok(FallbackEntryV1::new(key, primary, pins, triggers, mode)?)
    }

    /// The automatic `alpha` entry: primary `a`, candidates `b` then `c`.
    ///
    /// # Errors
    /// Returns the record error of an invalid entry.
    pub fn alpha(&self) -> TestResult<FallbackEntryV1> {
        let mode = FallbackActivationModeV1::Automatic;
        Self::entry(ALPHA, &self.a, &[&self.b, &self.c], mode)
    }

    /// The manual `beta` entry: primary `d`, candidate `e`.
    ///
    /// # Errors
    /// Returns the record error of an invalid entry.
    pub fn beta(&self) -> TestResult<FallbackEntryV1> {
        Self::entry(BETA, &self.d, &[&self.e], FallbackActivationModeV1::Manual)
    }
}

/// The PPN1 pin of `key` with one role.
///
/// # Errors
/// Returns the record error of an invalid pin.
pub fn pin(key: &ImplementationKeyV1) -> TestResult<CompositionPinV1> {
    Ok(CompositionPinV1::new(key.clone(), vec!["role".to_owned()])?)
}

/// A DFP1 of [`SCOPE`].
///
/// # Errors
/// Returns the record error of an invalid policy.
pub fn policy(
    entries: Vec<FallbackEntryV1>,
    previous: Option<Hash>,
) -> TestResult<DomainFallbackPolicyV1> {
    let scope = SCOPE.to_owned();
    Ok(DomainFallbackPolicyV1::new(scope, entries, previous)?)
}

/// A provisioned store, its target Timeline, and the host entity.
pub struct Harness<S> {
    pub store: S,
    pub timeline: TimelineId,
    pub entity: EntityId,
    pub world: World,
    pub guard: Guard,
}

impl<S: Backend> Harness<S> {
    /// A provisioned harness with a BLAKE3 store.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn open() -> TestResult<Self> {
        Self::with_hasher(None)
    }

    /// A provisioned harness whose store uses `hasher`.
    ///
    /// # Errors
    /// Returns the fixture construction or registry error.
    pub fn with_hasher(hasher: Option<Box<dyn Hasher>>) -> TestResult<Self> {
        let (mut store, guard) = S::build(hasher)?;
        store.provision_fallback_registry()?;
        let timeline = store.create_timeline("composition")?.id();
        Ok(Self {
            store,
            timeline,
            entity: EntityId::new(),
            world: World::new()?,
            guard,
        })
    }

    /// The harness target.
    #[must_use]
    pub const fn target(&self) -> CompositionFallbackTargetV1 {
        CompositionFallbackTargetV1 {
            timeline: self.timeline,
            entity: self.entity,
        }
    }

    /// The current state revision, 0 before the first operation.
    ///
    /// # Errors
    /// Returns the registry error.
    pub fn revision(&self) -> TestResult<u64> {
        let row = self.store.registry_row(SCOPE, self.timeline)?;
        Ok(row.map_or(0, |row| row.state().state_revision()))
    }

    /// The target Timeline's Logical Head.
    ///
    /// # Errors
    /// Returns the store error.
    pub fn head(&self) -> TestResult<Seq> {
        Ok(self.store.logical_head(self.timeline)?)
    }

    /// The number of Events on the target Timeline.
    ///
    /// # Errors
    /// Returns the store error.
    pub fn events(&self) -> TestResult<usize> {
        Ok(self.store.read(self.timeline, SeqRange::all())?.len())
    }

    /// A declaration of `policy` at the current revision and head, with empty conformance sets.
    ///
    /// # Errors
    /// Returns the registry or store error.
    pub fn declaration(
        &self,
        policy: &DomainFallbackPolicyV1,
    ) -> TestResult<FallbackDeclareRequestV1> {
        Ok(FallbackDeclareRequestV1 {
            scope: SCOPE.to_owned(),
            target: self.target(),
            expected_state_revision: self.revision()?,
            expected_logical_head: self.head()?,
            policy_bytes: policy.to_canonical_cbor(),
            conformance: FallbackConformanceSetsV1::default(),
        })
    }

    /// Declare `policy` at the current revision and head.
    ///
    /// # Errors
    /// Returns the fixture error; the registry result is the inner value.
    pub fn declare(
        &mut self,
        policy: &DomainFallbackPolicyV1,
    ) -> TestResult<Registry<FallbackCommitReceiptV1>> {
        let request = self.declaration(policy)?;
        Ok(self.store.declare(&request))
    }

    /// An automatic activation of `entry_key` at the current revision and head.
    ///
    /// # Errors
    /// Returns the registry or store error.
    pub fn activation(
        &self,
        entry_key: &str,
        closing_tenure_ordinal: u64,
        from: &ImplementationKeyV1,
        to: &ImplementationKeyV1,
    ) -> TestResult<FallbackActivateRequestV1> {
        Ok(FallbackActivateRequestV1 {
            scope: SCOPE.to_owned(),
            target: self.target(),
            expected_state_revision: self.revision()?,
            expected_logical_head: self.head()?,
            entry_key: entry_key.to_owned(),
            closing_tenure_ordinal,
            from: from.clone(),
            to: to.clone(),
            trigger_code: FallbackTriggerCodeV1::ResourceLimit,
            trigger_basis: FallbackTriggerBasisV1 {
                cause: 7,
                origin: FallbackActivationOriginV1::Automatic,
            },
            skipped: Vec::new(),
            tick: 9,
        })
    }

    /// Run `request`.
    ///
    /// # Errors
    /// Returns the registry error.
    pub fn activate(
        &mut self,
        request: &FallbackActivateRequestV1,
    ) -> Registry<FallbackCommitReceiptV1> {
        self.store.activate(request)
    }
}
