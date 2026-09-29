//! Durable ADR-106 Fork-admission host bootstrap.
//!
//! The port owns challenge entropy and its one-use lifecycle. Host keys sign
//! only the returned canonical challenge bytes through `pos-crypto`'s typed
//! wrapper; this module never accepts a seed or a generic signing callback.

use pos_core::{
    ForkAdmissionHostRecordV1, ForkAdmissionInitializeChallengeV1, ForkAdmissionOpenChallengeV1,
    Hash, PublicKey, Signature,
};
use pos_crypto::fork_authentication::{
    verify_fork_admission_initialize_v1, verify_fork_admission_open_v1,
};
use rand::{rngs::SysRng, TryRng};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use std::{
    collections::HashSet,
    sync::{LazyLock, Mutex},
};

const SESSION_IDENTITY_DOMAIN: &[u8] = b"pigloros/fork-admission-session/v1";
const ENTROPY_ATTEMPTS: usize = 2;

#[cfg(test)]
static ISSUED_AUTHORITY_ENTROPY: LazyLock<Mutex<HashSet<[u8; 32]>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[cfg(test)]
thread_local! {
    static FAIL_AUTHORITY_ENTROPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_AUTHORITY_ENTROPY: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static ZERO_AUTHORITY_ENTROPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FORCED_AUTHORITY_ENTROPY: std::cell::RefCell<Vec<[u8; 32]>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Closed failures for the durable ADR-106 bootstrap boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAdmissionAuthorityErrorV1 {
    /// No canonical FAH1 has been provisioned.
    #[error("Fork-admission authority is uninitialized")]
    AuthorityUninitialized,
    /// Provisioning found an already initialized store.
    #[error("Fork-admission authority is already initialized")]
    AuthorityAlreadyInitialized,
    /// A host proof, policy, store, or current session binding differs.
    #[error("Fork-admission host authority does not match")]
    HostAuthorityMismatch,
    /// Operating-system entropy was unavailable.
    #[error("Fork-admission entropy is unavailable")]
    EntropyUnavailable,
    /// A public custom-clock adapter cannot host Fork authority.
    #[error("Fork-admission authority clock is unavailable")]
    AuthorityClockUnavailable,
    /// The first mutation clock moved below the durable fence.
    #[error("Fork-admission authority clock rolled back")]
    ClockRollback,
    /// The durable authority row is malformed or internally inconsistent.
    #[error("Fork-admission authority state is corrupt")]
    CorruptAuthority,
    /// Storage could not determine an outcome.
    #[error("Fork-admission authority storage outcome is indeterminate")]
    StorageIndeterminate,
}

/// Non-cloneable, non-serializable proof that one FAO1 challenge was consumed.
///
/// It contains no host key, signature, or public constructor. Future FAC1 and
/// FRP1 operations bind their host proof to its exact session identity.
#[derive(Debug)]
pub struct ForkAdmissionAuthoritySessionV1 {
    store_id: Hash,
    identity: Hash,
    host_key: PublicKey,
    policy_digest: Hash,
}

impl ForkAdmissionAuthoritySessionV1 {
    /// Return the exact FAO1-plus-signature identity FAC1 and FRP1 must bind.
    #[must_use]
    pub const fn identity(&self) -> Hash {
        self.identity
    }

    fn matches(&self, host: ForkAdmissionHostRecordV1, identity: Hash) -> bool {
        self.store_id == host.store_id()
            && self.identity == identity
            && self.host_key == host.host_verifying_key()
            && self.policy_digest == host.authentication_policy_digest()
    }
}

/// The private durable state shared by `MemoryStore` and `SQLite`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ForkAdmissionAuthorityStateV1 {
    pub(crate) host: Option<ForkAdmissionHostRecordV1>,
    pub(crate) initialize_challenge: Option<ForkAdmissionInitializeChallengeV1>,
    pub(crate) open_challenge: Option<ForkAdmissionOpenChallengeV1>,
    pub(crate) session_identity: Option<Hash>,
    pub(crate) last_authority_wall_time: u64,
}

/// Generate a distinct nonzero 256-bit challenge identity from the operating system.
pub(crate) fn authority_entropy() -> Result<Hash, ForkAdmissionAuthorityErrorV1> {
    for _ in 0..ENTROPY_ATTEMPTS {
        let mut bytes = [0_u8; 32];
        #[cfg(test)]
        let filled = if FAIL_AUTHORITY_ENTROPY.with(std::cell::Cell::get)
            || FAIL_NEXT_AUTHORITY_ENTROPY.with(|failures| {
                let remaining = failures.get();
                failures.set(remaining.saturating_sub(1));
                remaining != 0
            }) {
            Err(())
        } else if let Some(forced) =
            FORCED_AUTHORITY_ENTROPY.with(|values| values.borrow_mut().pop())
        {
            bytes = forced;
            Ok(())
        } else {
            SysRng.try_fill_bytes(&mut bytes).map_err(|_| ())
        };
        #[cfg(not(test))]
        let filled = SysRng.try_fill_bytes(&mut bytes).map_err(|_| ());
        if filled.is_err() {
            continue;
        }
        #[cfg(test)]
        if ZERO_AUTHORITY_ENTROPY.with(std::cell::Cell::get) {
            bytes = [0; 32];
        }
        if bytes == [0; 32] {
            continue;
        }
        #[cfg(test)]
        if !ISSUED_AUTHORITY_ENTROPY
            .lock()
            .is_ok_and(|mut issued| issued.insert(bytes))
        {
            continue;
        }
        return Ok(Hash::from_bytes(bytes));
    }
    Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
}

pub(crate) fn begin_initialize(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    host_key: PublicKey,
    policy_digest: Hash,
) -> Result<ForkAdmissionInitializeChallengeV1, ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    if state.host.is_some() {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized);
    }
    let store_id = authority_entropy()?;
    let nonce = authority_entropy()?;
    let challenge =
        ForkAdmissionInitializeChallengeV1::new(store_id, nonce, host_key, policy_digest)
            .map_err(|_| ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)?;
    state.initialize_challenge = Some(challenge);
    Ok(challenge)
}

pub(crate) fn finalize_initialize(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    challenge: &ForkAdmissionInitializeChallengeV1,
    signature: &Signature,
) -> Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    // Consume the outstanding FAI1 before any rejection so no path can leave
    // a stale challenge redeemable later.
    let issued = state.initialize_challenge.take();
    if state.host.is_some() {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized);
    }
    if issued != Some(*challenge) {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    }
    verify_fork_admission_initialize_v1(challenge, signature)
        .map_err(|_| ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)?;
    let host = challenge.host_record();
    state.host = Some(host);
    Ok(host)
}

pub(crate) fn begin_open(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    host_key: PublicKey,
    policy_digest: Hash,
) -> Result<ForkAdmissionOpenChallengeV1, ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    let host = state
        .host
        .ok_or(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)?;
    if host.host_verifying_key() != host_key || host.authentication_policy_digest() != policy_digest
    {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    }
    let challenge = authority_entropy().and_then(|nonce| {
        ForkAdmissionOpenChallengeV1::new(host.store_id(), nonce, policy_digest)
            .map_err(|_| ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    })?;
    state.open_challenge = Some(challenge);
    Ok(challenge)
}

pub(crate) fn finalize_open(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    challenge: &ForkAdmissionOpenChallengeV1,
    signature: &Signature,
) -> Result<ForkAdmissionAuthoritySessionV1, ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    let host = state
        .host
        .ok_or(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)?;
    let issued = state.open_challenge.take();
    if issued != Some(*challenge) {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    }
    verify_fork_admission_open_v1(&host, challenge, signature)
        .map_err(|_| ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)?;
    let identity = session_identity(challenge, signature);
    state.session_identity = Some(identity);
    Ok(ForkAdmissionAuthoritySessionV1 {
        store_id: host.store_id(),
        identity,
        host_key: host.host_verifying_key(),
        policy_digest: host.authentication_policy_digest(),
    })
}

pub(crate) fn advance_wall_fence(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    session: &ForkAdmissionAuthoritySessionV1,
) -> Result<(), ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    let host = state
        .host
        .ok_or(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)?;
    let Some(identity) = state.session_identity else {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    };
    if !session.matches(host, identity) {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    }
    authority_wall_time().and_then(|commit_now| {
        if commit_now < state.last_authority_wall_time {
            return Err(ForkAdmissionAuthorityErrorV1::ClockRollback);
        }
        state.last_authority_wall_time = commit_now;
        Ok(())
    })
}

fn session_identity(challenge: &ForkAdmissionOpenChallengeV1, signature: &Signature) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SESSION_IDENTITY_DOMAIN);
    hasher.update(&challenge.canonical_bytes());
    hasher.update(signature.as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn authority_wall_time() -> Result<u64, ForkAdmissionAuthorityErrorV1> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
        .and_then(|duration| {
            u64::try_from(duration.as_micros())
                .map_err(|_| ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
        })
}

/// Store adapter seam for ADR-106 bootstrap and the commit-time rollback fence.
pub trait ForkAdmissionAuthorityBootstrapPortV1 {
    /// Produce one opaque FAI1 challenge for an empty store.
    ///
    /// # Errors
    /// Returns an authority, clock, entropy, or storage error if the challenge cannot be issued.
    fn begin_fork_admission_initialize(
        &mut self,
        host_key: PublicKey,
        policy_digest: Hash,
    ) -> Result<ForkAdmissionInitializeChallengeV1, ForkAdmissionAuthorityErrorV1>;
    /// Verify and consume the exact outstanding FAI1 proof, then persist FAH1.
    ///
    /// # Errors
    /// Returns an authority or storage error if the proof cannot be committed.
    fn finalize_fork_admission_initialize(
        &mut self,
        challenge: &ForkAdmissionInitializeChallengeV1,
        signature: &Signature,
    ) -> Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityErrorV1>;
    /// Read the immutable FAH1 without creating authority.
    ///
    /// # Errors
    /// Returns an authority or storage error if the record cannot be read.
    fn fork_admission_host_record(
        &self,
    ) -> Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityErrorV1>;
    /// Produce one opaque FAO1 challenge after exact key and policy matching.
    ///
    /// # Errors
    /// Returns an authority, clock, entropy, or storage error if the challenge cannot be issued.
    fn begin_fork_admission_open(
        &mut self,
        host_key: PublicKey,
        policy_digest: Hash,
    ) -> Result<ForkAdmissionOpenChallengeV1, ForkAdmissionAuthorityErrorV1>;
    /// Verify and consume FAO1, yielding a non-cloneable session.
    ///
    /// # Errors
    /// Returns an authority or storage error if the proof cannot be consumed.
    fn finalize_fork_admission_open(
        &mut self,
        challenge: &ForkAdmissionOpenChallengeV1,
        signature: &Signature,
    ) -> Result<ForkAdmissionAuthoritySessionV1, ForkAdmissionAuthorityErrorV1>;
    /// Atomically advance the durable commit-time rollback fence for a live session.
    /// The adapter reads the production wall clock while it owns the write lock.
    ///
    /// # Errors
    /// Returns an authority, clock, or storage error if the fence cannot be advanced.
    fn advance_fork_admission_wall_fence(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Result<(), ForkAdmissionAuthorityErrorV1>;
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use pos_crypto::fork_authentication::ForkHostSigningKeyV1;

    fn open_after_initialize(
        store: &mut MemoryStore,
        challenge: &ForkAdmissionInitializeChallengeV1,
        signer: &ForkHostSigningKeyV1,
        policy_digest: Hash,
    ) -> Result<ForkAdmissionAuthoritySessionV1, Box<dyn std::error::Error>> {
        let signature = signer.sign_initialize(&challenge.canonical_bytes())?;
        store.finalize_fork_admission_initialize(challenge, &signature)?;
        let host_key = PublicKey::from_bytes(signer.public_key());
        let open = store.begin_fork_admission_open(host_key, policy_digest)?;
        let signature = signer.sign_open(&open.canonical_bytes())?;
        Ok(store.finalize_fork_admission_open(&open, &signature)?)
    }

    #[test]
    fn authority_entropy_fails_closed_when_the_system_source_fails_or_returns_zero() {
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(true));
        assert_eq!(
            authority_entropy(),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(false));

        ZERO_AUTHORITY_ENTROPY.with(|flag| flag.set(true));
        assert_eq!(
            authority_entropy(),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        ZERO_AUTHORITY_ENTROPY.with(|flag| flag.set(false));
    }

    #[test]
    fn authority_entropy_regenerates_zero_and_same_process_repeats(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signer = ForkHostSigningKeyV1::from_seed([13; 32])?;
        let host_key = PublicKey::from_bytes(signer.public_key());
        let policy_digest = Hash::from_bytes([2; 32]);
        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[6; 32], [0; 32]];
        });
        let mut zero_store = MemoryStore::new();
        let zero_challenge = zero_store.begin_fork_admission_initialize(host_key, policy_digest)?;
        assert_eq!(zero_challenge.store_id(), Hash::from_bytes([6; 32]));

        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[8; 32], [7; 32]];
        });
        let mut first_store = MemoryStore::new();
        let first_challenge =
            first_store.begin_fork_admission_initialize(host_key, policy_digest)?;
        assert_eq!(first_challenge.store_id(), Hash::from_bytes([7; 32]));

        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[10; 32], [9; 32], [7; 32]];
        });
        let mut second_store = MemoryStore::new();
        let second_challenge =
            second_store.begin_fork_admission_initialize(host_key, policy_digest)?;
        assert_eq!(second_challenge.store_id(), Hash::from_bytes([9; 32]));
        let first_session =
            open_after_initialize(&mut first_store, &first_challenge, &signer, policy_digest)?;
        let second_session =
            open_after_initialize(&mut second_store, &second_challenge, &signer, policy_digest)?;
        assert_eq!(
            first_store.advance_fork_admission_wall_fence(&second_session),
            Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
        );
        assert_eq!(
            second_store.advance_fork_admission_wall_fence(&first_session),
            Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
        );
        first_store.advance_fork_admission_wall_fence(&first_session)?;
        second_store.advance_fork_admission_wall_fence(&second_session)?;
        Ok(())
    }

    #[test]
    fn authority_entropy_retries_one_source_failure() -> Result<(), Box<dyn std::error::Error>> {
        FAIL_NEXT_AUTHORITY_ENTROPY.with(|failures| failures.set(1));
        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[12; 32], [11; 32]];
        });
        let mut store = MemoryStore::new();
        let challenge = store.begin_fork_admission_initialize(
            PublicKey::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]),
        )?;
        assert_eq!(challenge.store_id(), Hash::from_bytes([11; 32]));
        Ok(())
    }

    #[test]
    fn initialize_fails_closed_when_the_second_entropy_draw_repeats() {
        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[21; 32], [21; 32], [21; 32]];
        });
        let mut state = ForkAdmissionAuthorityStateV1::default();
        assert_eq!(
            begin_initialize(
                &mut state,
                true,
                PublicKey::from_bytes([1; 32]),
                Hash::from_bytes([2; 32]),
            ),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        assert_eq!(state.initialize_challenge, None);
        FORCED_AUTHORITY_ENTROPY.with(|values| values.borrow_mut().clear());
    }

    #[test]
    fn authority_entropy_failure_propagates_through_challenge_issuance(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let host_key = PublicKey::from_bytes([1; 32]);
        let policy_digest = Hash::from_bytes([2; 32]);

        let mut uninitialized = ForkAdmissionAuthorityStateV1::default();
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(true));
        assert_eq!(
            begin_initialize(&mut uninitialized, true, host_key, policy_digest),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(false));

        let mut initialized = ForkAdmissionAuthorityStateV1 {
            host: Some(ForkAdmissionHostRecordV1::new(
                Hash::from_bytes([3; 32]),
                host_key,
                policy_digest,
            )?),
            ..ForkAdmissionAuthorityStateV1::default()
        };
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(true));
        assert_eq!(
            begin_open(&mut initialized, true, host_key, policy_digest),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(false));
        Ok(())
    }
}
