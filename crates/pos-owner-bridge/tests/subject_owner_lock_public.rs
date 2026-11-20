#![cfg(any(test, feature = "test-support"))]
//! ADR-091 subject-owner session/inventory locks through the public encryptor lock.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::Path;

use pos_owner_bridge::encryptor_lock::linux::SubjectEncryptorLock;
use pos_owner_bridge::{BridgeError, UnavailableCode};

pub mod support;
use support::Sandbox;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
const OWNER: &str = "subject:0123456789abcdef0123456789abcdef";
const OTHER_OWNER: &str = "subject:00000000000000000000000000000001";

fn listing(leaf: &Path) -> TestResult<Vec<std::ffi::OsString>> {
    let mut names = fs::read_dir(leaf)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

#[test]
fn shared_holders_coexist_and_the_exclusive_lock_waits_for_none() -> TestResult {
    let root = Sandbox::new()?;
    let lock = SubjectEncryptorLock::acquire(&root.0)?;
    let first = lock.try_lock_subject_owner_shared(OWNER)?;
    let second = lock.try_lock_subject_owner_shared(OWNER)?;
    assert_eq!((first.owner_id(), second.owner_id()), (OWNER, OWNER));
    assert_eq!(
        lock.try_lock_subject_owner_exclusive(OWNER).err(),
        Some(UNAVAILABLE)
    );
    drop(first);
    assert_eq!(
        lock.try_lock_subject_owner_exclusive(OWNER).err(),
        Some(UNAVAILABLE)
    );
    drop(second);
    let exclusive = lock.try_lock_subject_owner_exclusive(OWNER)?;
    assert_eq!(exclusive.owner_id(), OWNER);
    Ok(())
}

#[test]
fn the_exclusive_lock_refuses_every_other_holder_and_refusals_leave_no_hold() -> TestResult {
    let root = Sandbox::new()?;
    let lock = SubjectEncryptorLock::acquire(&root.0)?;
    let exclusive = lock.try_lock_subject_owner_exclusive(OWNER)?;
    assert_eq!(
        lock.try_lock_subject_owner_shared(OWNER).err(),
        Some(UNAVAILABLE)
    );
    assert_eq!(
        lock.try_lock_subject_owner_exclusive(OWNER).err(),
        Some(UNAVAILABLE)
    );
    drop(exclusive);
    // Neither refusal left a shared or exclusive hold behind.
    drop(lock.try_lock_subject_owner_exclusive(OWNER)?);
    let shared = lock.try_lock_subject_owner_shared(OWNER)?;
    drop(shared);
    drop(lock.try_lock_subject_owner_exclusive(OWNER)?);
    Ok(())
}

#[test]
fn two_subjects_of_one_human_have_independent_locks() -> TestResult {
    let root = Sandbox::new()?;
    let lock = SubjectEncryptorLock::acquire(&root.0)?;
    let destroying = lock.try_lock_subject_owner_exclusive(OWNER)?;
    let unlocking = lock.try_lock_subject_owner_shared(OTHER_OWNER)?;
    assert_eq!(
        lock.try_lock_subject_owner_exclusive(OTHER_OWNER).err(),
        Some(UNAVAILABLE)
    );
    drop(unlocking);
    let enrolling = lock.try_lock_subject_owner_exclusive(OTHER_OWNER)?;
    assert_eq!(
        (destroying.owner_id(), enrolling.owner_id()),
        (OWNER, OTHER_OWNER)
    );
    Ok(())
}

#[test]
fn a_shared_hold_on_one_thread_refuses_the_exclusive_lock_on_another() -> TestResult {
    let root = Sandbox::new()?;
    let lock = SubjectEncryptorLock::acquire(&root.0)?;
    let shared = lock.try_lock_subject_owner_shared(OWNER)?;
    let refused = std::thread::scope(|scope| {
        scope
            .spawn(|| lock.try_lock_subject_owner_exclusive(OWNER).err())
            .join()
    });
    assert_eq!(refused.ok(), Some(Some(UNAVAILABLE)));
    drop(shared);
    let granted = std::thread::scope(|scope| {
        scope
            .spawn(|| lock.try_lock_subject_owner_exclusive(OWNER).map(drop))
            .join()
    });
    assert_eq!(granted.ok(), Some(Ok(())));
    Ok(())
}

#[test]
fn only_the_exact_adr_091_owner_spelling_is_accepted() -> TestResult {
    let root = Sandbox::new()?;
    let lock = SubjectEncryptorLock::acquire(&root.0)?;
    for owner in [
        "subject:09afaf0909afaf0909afaf0909afaf09",
        "subject:ffffffffffffffffffffffffffffffff",
        OTHER_OWNER,
    ] {
        drop(lock.try_lock_subject_owner_shared(owner)?);
        drop(lock.try_lock_subject_owner_exclusive(owner)?);
    }
    let digits = "0123456789abcdef0123456789abcdef";
    let mut rejected = vec![
        String::new(),
        "subject:".to_owned(),
        digits.to_owned(),
        format!("Subject:{digits}"),
        format!("subject;{digits}"),
        format!(" subject:{digits}"),
        format!("subject:{digits} "),
        format!("subject:{}", &digits[1..]),
        format!("subject:{digits}0"),
        format!("subject:{}", "0".repeat(32)),
        format!("subject:{}", digits.to_uppercase()),
    ];
    for outside in ['/', ':', '`', 'g', 'A', 'F'] {
        rejected.push(format!("subject:{outside}{}", &digits[1..]));
    }
    for owner in &rejected {
        assert_eq!(
            lock.try_lock_subject_owner_shared(owner).err(),
            Some(UNAVAILABLE),
            "{owner:?}"
        );
        assert_eq!(
            lock.try_lock_subject_owner_exclusive(owner).err(),
            Some(UNAVAILABLE),
            "{owner:?}"
        );
    }
    Ok(())
}

#[test]
fn owner_locks_create_no_file_and_never_release_the_encryptor_lock() -> TestResult {
    let root = Sandbox::new()?;
    let leaf = root.0.join("pigloros");
    let lock = SubjectEncryptorLock::acquire(&root.0)?;
    let before = listing(&leaf)?;
    let shared = lock.try_lock_subject_owner_shared(OWNER)?;
    let exclusive = lock.try_lock_subject_owner_exclusive(OTHER_OWNER)?;
    assert_eq!(listing(&leaf)?, before);
    drop((shared, exclusive));
    assert_eq!(listing(&leaf)?, before);
    assert_eq!(
        SubjectEncryptorLock::acquire(&root.0).err(),
        Some(UNAVAILABLE)
    );
    drop(lock);
    let successor = SubjectEncryptorLock::acquire(&root.0)?;
    drop(successor.try_lock_subject_owner_exclusive(OWNER)?);
    Ok(())
}
