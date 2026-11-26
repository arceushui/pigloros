#![cfg(any(test, feature = "test-support"))]
//! ADR-091 subject-owner session/inventory locks inside the held encryptor lock.
//!
//! The E16 lifetime lock already makes this the only owner process of the OS
//! user, so these locks are process-local and keyed by the exact subject owner.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use super::SubjectEncryptorLock;
use crate::{BridgeError, UnavailableCode};

const OWNER_PREFIX: &str = "subject:";
const OWNER_HEX_LENGTH: usize = 32;
const REFUSED: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

/// The holders of every subject owner's lock in one encryptor lock.
#[derive(Debug, Default)]
pub(super) struct SubjectOwnerLocks {
    holders: Mutex<Holders>,
}

#[derive(Debug, Default)]
struct Holders {
    shared: BTreeMap<String, usize>,
    exclusive: BTreeSet<String>,
}

/// A held ADR-091 subject-owner **shared** session/inventory lock.
///
/// Encryption, decryption and unlock hold this before the nonce ledger and
/// the registry serialization boundary (ADR-091; ADR-097 §4 step 2). Several
/// shared holders of one owner may coexist. Dropping the guard releases it.
/// The borrow keeps it inside the E16 lifetime lock it was taken from.
#[derive(Debug)]
#[must_use = "dropping the guard releases the subject-owner lock"]
pub struct SubjectOwnerSharedGuard<'lock> {
    locks: &'lock SubjectOwnerLocks,
    owner_id: String,
}

/// A held ADR-091 subject-owner **exclusive** session/inventory lock.
///
/// Enrollment, rotation (ADR-110 §8, ADR-137 P3) and destruction (ADR-137 D2)
/// hold this throughout. It exists only once every earlier shared holder of
/// the owner has released, which is the D2 step 1 drain. Dropping the guard
/// releases it. The borrow keeps it inside the E16 lifetime lock.
#[derive(Debug)]
#[must_use = "dropping the guard releases the subject-owner lock"]
pub struct SubjectOwnerExclusiveGuard<'lock> {
    locks: &'lock SubjectOwnerLocks,
    owner_id: String,
}

impl SubjectEncryptorLock {
    /// Take one subject owner's shared session/inventory lock without waiting.
    ///
    /// `owner_id` must be the exact ADR-091 owner: `subject:` followed by the
    /// 32 lowercase hex digits of a non-nil subject. The lock is held in this
    /// process only; it creates no file and touches no ledger, wrap or
    /// registry state. Other owners are unaffected.
    ///
    /// # Errors
    /// Returns `Unavailable(InterfaceUnavailable)` for any other owner
    /// spelling, while the owner's exclusive lock is held, or after a panic
    /// inside the lock table. A refusal leaves no hold behind, and the error
    /// does not say which of these causes refused it.
    pub fn try_lock_subject_owner_shared(
        &self,
        owner_id: &str,
    ) -> Result<SubjectOwnerSharedGuard<'_>, BridgeError> {
        self.subject_owners.hold(owner_id, |holders| {
            admit(!holders.exclusive.contains(owner_id)).map(|()| {
                let owner_id = owner_id.to_owned();
                *holders.shared.entry(owner_id.clone()).or_default() += 1;
                SubjectOwnerSharedGuard {
                    locks: &self.subject_owners,
                    owner_id,
                }
            })
        })
    }

    /// Take one subject owner's exclusive session/inventory lock without
    /// waiting.
    ///
    /// The owner is checked as for the shared lock. The lock is granted only
    /// when no shared or exclusive holder of this owner remains; it never
    /// waits for one to drain (ADR-123 §6: every lock is nonblocking), and a
    /// refused attempt does not fence out later shared holders. The caller
    /// retries, as D2's `DestructionRetryLater` does. ADR-110 §1a gives the
    /// ADR-091 owner locks to the one owner thread, so a shared hold ends with
    /// its operation and cannot keep the exclusive lock away indefinitely.
    ///
    /// # Errors
    /// Returns `Unavailable(InterfaceUnavailable)` for any other owner
    /// spelling, while any holder of this owner remains, or after a panic
    /// inside the lock table. A refusal leaves no hold behind, and the error
    /// does not say which of these causes refused it.
    pub fn try_lock_subject_owner_exclusive(
        &self,
        owner_id: &str,
    ) -> Result<SubjectOwnerExclusiveGuard<'_>, BridgeError> {
        self.subject_owners.hold(owner_id, |holders| {
            admit(!holders.exclusive.contains(owner_id) && !holders.shared.contains_key(owner_id))
                .map(|()| {
                    let owner_id = owner_id.to_owned();
                    holders.exclusive.insert(owner_id.clone());
                    SubjectOwnerExclusiveGuard {
                        locks: &self.subject_owners,
                        owner_id,
                    }
                })
        })
    }
}

impl SubjectOwnerLocks {
    fn hold<T>(
        &self,
        owner_id: &str,
        take: impl FnOnce(&mut Holders) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        admit(is_subject_owner(owner_id))
            .and_then(|()| self.holders.lock().map_err(|_| REFUSED))
            .and_then(|mut holders| take(&mut holders))
    }

    fn release(&self, release: impl FnOnce(&mut Holders)) {
        // A release only removes this guard's own hold, so it proceeds even
        // after a panic elsewhere; acquisition stays refused in that case.
        release(&mut self.holders.lock().unwrap_or_else(PoisonError::into_inner));
    }
}

impl SubjectOwnerSharedGuard<'_> {
    /// The exact subject owner this guard holds.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }
}

impl SubjectOwnerExclusiveGuard<'_> {
    /// The exact subject owner this guard holds.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// Whether this guard holds `owner_id` in `lock`'s own lock table.
    pub(super) fn holds(&self, lock: &SubjectEncryptorLock, owner_id: &str) -> bool {
        std::ptr::eq(self.locks, &raw const lock.subject_owners) && self.owner_id == owner_id
    }
}

impl Drop for SubjectOwnerSharedGuard<'_> {
    fn drop(&mut self) {
        self.locks.release(|holders| {
            holders.shared.retain(|owner_id, count| {
                if *owner_id == self.owner_id {
                    *count -= 1;
                }
                *count > 0
            });
        });
    }
}

impl Drop for SubjectOwnerExclusiveGuard<'_> {
    fn drop(&mut self) {
        self.locks.release(|holders| {
            holders.exclusive.remove(&self.owner_id);
        });
    }
}

/// ADR-091: exactly `subject:` and 32 lowercase hex digits of a non-nil subject.
fn is_subject_owner(owner_id: &str) -> bool {
    owner_id.strip_prefix(OWNER_PREFIX).is_some_and(|digits| {
        digits.len() == OWNER_HEX_LENGTH
            && digits
                .bytes()
                .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
            && digits.bytes().any(|digit| digit != b'0')
    })
}

fn admit(accepted: bool) -> Result<(), BridgeError> {
    accepted.then_some(()).ok_or(REFUSED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryptor_lock_test_support::Sandbox;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const OWNER: &str = "subject:0123456789abcdef0123456789abcdef";

    #[test]
    fn a_panic_inside_the_table_refuses_new_holds_but_still_releases() -> TestResult {
        // Chained rather than `?`-propagated: the unit-test code in a source
        // file is counted by the changed-code coverage gate, and a `?` error
        // arm that no test can reach is an uncovered region.
        Sandbox::new().and_then(|root| {
            SubjectEncryptorLock::acquire(&root.0)
                .map_err(Box::<dyn std::error::Error>::from)
                .and_then(|lock| {
                    lock.try_lock_subject_owner_shared(OWNER)
                        .map_err(Box::<dyn std::error::Error>::from)
                        .map(|shared| poisoned_table_refuses_then_releases(&lock, shared))
                })
        })
    }

    fn poisoned_table_refuses_then_releases(
        lock: &SubjectEncryptorLock,
        shared: SubjectOwnerSharedGuard<'_>,
    ) {
        let poisoned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _holders = lock.subject_owners.holders.lock();
                    // Unwind while the table is held, which poisons it.
                    std::panic::resume_unwind(Box::new("poison the subject-owner lock table"))
                })
                .join()
        });
        assert!(poisoned.is_err());
        assert_eq!(
            lock.try_lock_subject_owner_shared(OWNER).err(),
            Some(REFUSED)
        );
        assert_eq!(
            lock.try_lock_subject_owner_exclusive(OWNER).err(),
            Some(REFUSED)
        );
        drop(shared);
        assert!(no_holds(
            &lock
                .subject_owners
                .holders
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        ));
    }

    fn no_holds(holders: &Holders) -> bool {
        holders.shared.is_empty() && holders.exclusive.is_empty()
    }
}
