#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg(feature = "sqlite")]

//! Public adapter-parity evidence for the ADR-105 `FIP1` issuer-policy port.

use std::error::Error;

use ed25519_dalek::SigningKey;
use pos_core::{
    ForkAttributionIssuerPolicyEntryV1, ForkAttributionIssuerPolicyInputV1,
    ForkAttributionIssuerPolicyV1, ForkAttributionIssuerStateV1 as State, ForkAttributionIssuerV1,
    Hash, PublicKey,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, AuthenticatedOperatorPolicyPinV1,
    ForkAttributionIssuerAdmissionBasisV1 as Basis, ForkAttributionIssuerAdmissionQueryV1,
    ForkAttributionIssuerAdmissionV1, ForkAttributionIssuerPolicyErrorV1 as PolicyError,
    ForkAttributionIssuerPolicyInstallationPortV1 as PolicyPort, IssuerPolicyFloorV1,
    IssuerPolicyInstallOutcomeV1 as Outcome, IssuerPolicyInstallReceiptV1,
    MAX_FORK_ATTRIBUTION_ISSUER_POLICY_HISTORY_V1,
};

type Fallible<T> = Result<T, Box<dyn Error>>;
type Policy = ForkAttributionIssuerPolicyV1;
type Issuer = ForkAttributionIssuerV1;

const SCOPE: &str = "destination-a";
const ACTIVE: State = State::Active;
const RETIRED: State = State::Retired;
const REVOKED: State = State::Revoked;
/// A small-order Ed25519 point: decodable, but never a valid issuer key.
const WEAK_POINT: [u8; 32] = {
    let mut bytes = [0; 32];
    bytes[0] = 1;
    bytes
};
/// Bytes that do not decode as an Ed25519 point.
const INVALID_POINT: [u8; 32] = {
    let mut bytes = [0; 32];
    bytes[31] = 0xff;
    bytes
};

fn key(seed: u8) -> PublicKey {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    PublicKey::from_bytes(signing.verifying_key().to_bytes())
}

fn issuer(id: &str, epoch: u64, seed: u8) -> Fallible<Issuer> {
    Ok(Issuer::new(id, epoch, key(seed))?)
}

fn scoped_policy(
    scope: &str,
    generation: u64,
    previous: Option<Hash>,
    entries: &[(&Issuer, State)],
) -> Fallible<Policy> {
    Ok(Policy::new(ForkAttributionIssuerPolicyInputV1 {
        scope: scope.to_owned(),
        generation,
        previous_policy_digest: previous,
        entries: entries
            .iter()
            .map(|(issuer, state)| ForkAttributionIssuerPolicyEntryV1 {
                issuer: (*issuer).clone(),
                state: *state,
            })
            .collect(),
    })?)
}

fn genesis(entries: &[(&Issuer, State)]) -> Fallible<Policy> {
    scoped_policy(SCOPE, 1, None, entries)
}

fn successor(previous: &Policy, entries: &[(&Issuer, State)]) -> Fallible<Policy> {
    let generation = previous.input().generation + 1;
    scoped_policy(SCOPE, generation, Some(previous.digest()), entries)
}

fn pin(policy: &Policy) -> AuthenticatedOperatorPolicyPinV1 {
    AuthenticatedOperatorPolicyPinV1::new(policy.input().scope.clone(), policy.digest())
}

fn install(
    store: &mut dyn PolicyPort,
    policy: &Policy,
) -> Result<IssuerPolicyInstallReceiptV1, PolicyError> {
    store.install(&pin(policy), &policy.to_canonical_cbor())
}

fn installed(policy: &Policy) -> IssuerPolicyInstallReceiptV1 {
    receipt(policy, Outcome::Installed)
}

fn receipt(policy: &Policy, outcome: Outcome) -> IssuerPolicyInstallReceiptV1 {
    IssuerPolicyInstallReceiptV1 {
        floor: floor(policy),
        outcome,
    }
}

fn floor(policy: &Policy) -> IssuerPolicyFloorV1 {
    IssuerPolicyFloorV1 {
        scope: policy.input().scope.clone(),
        generation: policy.input().generation,
        digest: policy.digest(),
    }
}

fn admit(
    store: &dyn PolicyPort,
    issuer: &Issuer,
    policy_digest: Hash,
    basis: Basis,
) -> Result<ForkAttributionIssuerAdmissionV1, PolicyError> {
    store.admit_issuer(&ForkAttributionIssuerAdmissionQueryV1 {
        issuer: issuer.clone(),
        policy_digest,
        basis,
    })
}

fn admitted(policy: &Policy) -> ForkAttributionIssuerAdmissionV1 {
    ForkAttributionIssuerAdmissionV1 {
        policy_generation: policy.input().generation,
        policy_digest: policy.digest(),
    }
}

const fn committed(policy_generation: u64) -> Basis {
    Basis::CommittedImport { policy_generation }
}

/// Run one public scenario against both reference adapters.
fn on_both_adapters(scenario: impl Fn(&mut dyn PolicyPort) -> Fallible<()>) -> Fallible<()> {
    let mut memory = MemoryStore::new();
    scenario(&mut memory)?;
    let mut sqlite = SqliteStore::open_in_memory()?;
    scenario(&mut sqlite)
}

/// Install `policy`, which must be refused with `error`, and keep the floor.
fn refuse(store: &mut dyn PolicyPort, policy: &Policy, error: PolicyError) -> Fallible<()> {
    let before = store.issuer_policy_floor()?;
    assert_eq!(install(store, policy), Err(error));
    assert_eq!(store.issuer_policy_floor()?, before);
    Ok(())
}

/// Admit `issuer` under `basis`, naming `policy` as the `FAE1` field-4 digest.
fn decide(
    store: &dyn PolicyPort,
    issuer: &Issuer,
    policy: &Policy,
    basis: Basis,
) -> Result<ForkAttributionIssuerAdmissionV1, PolicyError> {
    admit(store, issuer, policy.digest(), basis)
}

#[test]
fn genesis_install_and_exact_retry_report_the_floor() -> Fallible<()> {
    let a = issuer("issuer-a", 1, 1)?;
    let b = issuer("issuer-b", 1, 2)?;
    let first = genesis(&[(&a, ACTIVE), (&b, ACTIVE)])?;
    on_both_adapters(|store| {
        assert_eq!(store.issuer_policy_floor(), Ok(None));
        assert_eq!(install(store, &first), Ok(installed(&first)));
        assert_eq!(store.issuer_policy_floor(), Ok(Some(floor(&first))));
        // A retry after an indeterminate commit that did commit changes nothing.
        let retry = receipt(&first, Outcome::AlreadyInstalled);
        assert_eq!(install(store, &first), Ok(retry));
        assert_eq!(store.issuer_policy_floor(), Ok(Some(floor(&first))));
        Ok(())
    })
}

#[test]
fn unpinned_malformed_or_invalid_key_policies_install_nothing() -> Fallible<()> {
    let a = issuer("issuer-a", 1, 1)?;
    let first = genesis(&[(&a, ACTIVE)])?;
    let bytes = first.to_canonical_cbor();
    let mut unsupported = bytes.clone();
    unsupported[6] = 2;
    let weak = Issuer::new("issuer-w", 1, PublicKey::from_bytes(WEAK_POINT))?;
    let weak = genesis(&[(&a, ACTIVE), (&weak, ACTIVE)])?;
    let invalid = Issuer::new("issuer-x", 1, PublicKey::from_bytes(INVALID_POINT))?;
    let invalid = genesis(&[(&a, ACTIVE), (&invalid, ACTIVE)])?;
    let wrong_digest = AuthenticatedOperatorPolicyPinV1::new(SCOPE, Hash::from_bytes([9; 32]));
    let wrong_scope = AuthenticatedOperatorPolicyPinV1::new("destination-b", first.digest());
    let pinned = pin(&first);
    let truncated = [0x86_u8];
    let attempts = [
        (&wrong_digest, bytes.as_slice(), PolicyError::PinMismatch),
        (&wrong_scope, bytes.as_slice(), PolicyError::PinMismatch),
        (&pinned, truncated.as_slice(), PolicyError::InvalidEncoding),
        (
            &pinned,
            unsupported.as_slice(),
            PolicyError::UnsupportedVersion,
        ),
    ];
    on_both_adapters(|store| {
        for (pin, bytes, error) in &attempts {
            assert_eq!(store.install(pin, bytes), Err(*error));
        }
        refuse(store, &weak, PolicyError::InvalidIssuerKey)?;
        refuse(store, &invalid, PolicyError::InvalidIssuerKey)?;
        assert_eq!(store.issuer_policy_floor(), Ok(None));
        Ok(())
    })
}

#[test]
fn genesis_requires_generation_one_with_only_active_newest_identities() -> Fallible<()> {
    let a = issuer("issuer-a", 1, 1)?;
    let newer_a = issuer("issuer-a", 2, 2)?;
    let unknown = Some(Hash::from_bytes([3; 32]));
    let orphan = scoped_policy(SCOPE, 2, unknown, &[(&a, ACTIVE)])?;
    let retired = genesis(&[(&a, RETIRED)])?;
    let doubled = genesis(&[(&a, ACTIVE), (&newer_a, ACTIVE)])?;
    on_both_adapters(|store| {
        refuse(store, &orphan, PolicyError::WrongPredecessor)?;
        refuse(store, &retired, PolicyError::IllegalTransition)?;
        refuse(store, &doubled, PolicyError::IllegalTransition)?;
        assert_eq!(store.issuer_policy_floor(), Ok(None));
        Ok(())
    })
}

#[test]
fn successors_advance_the_floor_and_rollback_or_skips_are_refused() -> Fallible<()> {
    let a = issuer("issuer-a", 1, 1)?;
    let b = issuer("issuer-b", 1, 2)?;
    let first = genesis(&[(&a, ACTIVE)])?;
    let second = successor(&first, &[(&a, ACTIVE), (&b, ACTIVE)])?;
    let third = successor(&second, &[(&a, RETIRED), (&b, ACTIVE)])?;
    let revoked = [(&a, REVOKED), (&b, ACTIVE)];
    let rival = successor(&second, &revoked)?;
    let skipped = scoped_policy(SCOPE, 5, Some(third.digest()), &revoked)?;
    let forked = scoped_policy(SCOPE, 4, Some(second.digest()), &revoked)?;
    let no_op = successor(&third, &[(&a, RETIRED), (&b, ACTIVE)])?;
    let other_scope = scoped_policy("destination-b", 1, None, &[(&b, ACTIVE)])?;
    let refusals = [
        (&second, PolicyError::Rollback),
        (&first, PolicyError::Rollback),
        (&rival, PolicyError::GenerationConflict),
        (&skipped, PolicyError::GenerationSkipped),
        (&forked, PolicyError::WrongPredecessor),
        (&no_op, PolicyError::NoOpSuccessor),
        (&other_scope, PolicyError::ScopeMismatch),
    ];
    on_both_adapters(|store| {
        for policy in [&first, &second, &third] {
            assert_eq!(install(store, policy), Ok(installed(policy)));
        }
        for (policy, error) in refusals {
            refuse(store, policy, error)?;
        }
        assert_eq!(store.issuer_policy_floor(), Ok(Some(floor(&third))));
        let retry = receipt(&third, Outcome::AlreadyInstalled);
        assert_eq!(install(store, &third), Ok(retry));
        Ok(())
    })
}

#[test]
fn identities_never_disappear_rekey_regress_or_enter_inactive() -> Fallible<()> {
    let a = issuer("issuer-a", 1, 1)?;
    let b = issuer("issuer-b", 1, 2)?;
    let rekeyed_b = issuer("issuer-b", 1, 3)?;
    let c = issuer("issuer-c", 1, 4)?;
    let first = genesis(&[(&a, ACTIVE), (&b, ACTIVE)])?;
    let dropped = successor(&first, &[(&a, RETIRED)])?;
    let rekeyed = successor(&first, &[(&a, ACTIVE), (&rekeyed_b, ACTIVE)])?;
    let entered_retired = successor(&first, &[(&a, ACTIVE), (&b, ACTIVE), (&c, RETIRED)])?;
    let second = successor(&first, &[(&a, RETIRED), (&b, ACTIVE)])?;
    let reactivated = successor(&second, &[(&a, ACTIVE), (&b, RETIRED)])?;
    let third = successor(&second, &[(&a, REVOKED), (&b, ACTIVE)])?;
    let unrevoked = successor(&third, &[(&a, RETIRED), (&b, RETIRED)])?;
    on_both_adapters(|store| {
        assert_eq!(install(store, &first), Ok(installed(&first)));
        refuse(store, &dropped, PolicyError::IllegalTransition)?;
        refuse(store, &rekeyed, PolicyError::IllegalTransition)?;
        refuse(store, &entered_retired, PolicyError::IllegalTransition)?;
        assert_eq!(install(store, &second), Ok(installed(&second)));
        refuse(store, &reactivated, PolicyError::IllegalTransition)?;
        assert_eq!(install(store, &third), Ok(installed(&third)));
        refuse(store, &unrevoked, PolicyError::IllegalTransition)?;
        assert_eq!(store.issuer_policy_floor(), Ok(Some(floor(&third))));
        Ok(())
    })
}

#[test]
fn rotation_must_retire_the_older_epoch_in_the_same_policy() -> Fallible<()> {
    let old = issuer("issuer-a", 1, 1)?;
    let new = issuer("issuer-a", 2, 2)?;
    let first = genesis(&[(&old, ACTIVE)])?;
    let unretired = successor(&first, &[(&old, ACTIVE), (&new, ACTIVE)])?;
    let rotated = successor(&first, &[(&old, RETIRED), (&new, ACTIVE)])?;
    on_both_adapters(|store| {
        assert_eq!(install(store, &first), Ok(installed(&first)));
        refuse(store, &unretired, PolicyError::IllegalTransition)?;
        assert_eq!(install(store, &rotated), Ok(installed(&rotated)));
        let absent = Basis::AbsentImport;
        let admission = decide(store, &new, &rotated, absent);
        assert_eq!(admission, Ok(admitted(&rotated)));
        let retired = Err(PolicyError::IssuerRetired);
        assert_eq!(decide(store, &old, &rotated, absent), retired);
        Ok(())
    })
}

#[test]
fn emergency_revocation_may_leave_no_active_issuer() -> Fallible<()> {
    let a = issuer("issuer-a", 1, 1)?;
    let first = genesis(&[(&a, ACTIVE)])?;
    let second = successor(&first, &[(&a, REVOKED)])?;
    on_both_adapters(|store| {
        assert_eq!(install(store, &first), Ok(installed(&first)));
        assert_eq!(install(store, &second), Ok(installed(&second)));
        let revoked = Err(PolicyError::IssuerRevoked);
        assert_eq!(decide(store, &a, &second, Basis::AbsentImport), revoked);
        // A durably committed import stays recoverable under its own policy.
        let recovered = decide(store, &a, &first, committed(1));
        assert_eq!(recovered, Ok(admitted(&first)));
        Ok(())
    })
}

/// The 96 single-step records reachable from 32 identities: genesis, 31
/// additions, 32 retirements, then 32 revocations.
fn lifetime_history() -> Fallible<Vec<Policy>> {
    let issuers = (0..32_u8)
        .map(|index| issuer(&format!("issuer-{index:02}"), 1, index + 1))
        .collect::<Fallible<Vec<_>>>()?;
    let mut states = vec![ACTIVE];
    let mut history = vec![genesis(&[(&issuers[0], ACTIVE)])?];
    let steps = (1..32)
        .map(|_| None)
        .chain((0..32).map(|index| Some((index, RETIRED))))
        .chain((0..32).map(|index| Some((index, REVOKED))));
    for step in steps {
        match step {
            Some((index, state)) => states[index] = state,
            None => states.push(ACTIVE),
        }
        let entries = issuers
            .iter()
            .zip(&states)
            .map(|(issuer, state)| (issuer, *state));
        let previous = history.last().ok_or("empty history")?;
        let next = successor(previous, &entries.collect::<Vec<_>>())?;
        history.push(next);
    }
    Ok(history)
}

fn same_entries(policy: &Policy) -> Vec<(&Issuer, State)> {
    policy
        .input()
        .entries
        .iter()
        .map(|entry| (&entry.issuer, entry.state))
        .collect()
}

#[test]
fn ninety_six_records_install_and_the_ninety_seventh_fails_closed() -> Fallible<()> {
    let history = lifetime_history()?;
    let last = history.last().ok_or("empty history")?;
    let ceiling = MAX_FORK_ATTRIBUTION_ISSUER_POLICY_HISTORY_V1;
    assert_eq!(last.input().generation, ceiling);
    let exhausted = successor(last, &same_entries(last))?;
    on_both_adapters(|store| {
        for policy in &history {
            assert_eq!(install(store, policy), Ok(installed(policy)));
        }
        refuse(store, &exhausted, PolicyError::HistoryExhausted)?;
        assert_eq!(store.issuer_policy_floor(), Ok(Some(floor(last))));
        Ok(())
    })
}

#[test]
fn a_thirty_third_identity_is_refused_as_out_of_bounds() -> Fallible<()> {
    let history = lifetime_history()?;
    let full = &history[31];
    assert_eq!(full.input().entries.len(), 32);
    let mut bytes = successor(full, &same_entries(full))?.to_canonical_cbor();
    // The entry-count head follows the marker, version, scope, the two-byte
    // generation 33, and the 32-byte predecessor digest.
    let count = 1 + 5 + 1 + (1 + SCOPE.len()) + 2 + (2 + 32);
    assert_eq!(bytes[count..count + 2], [0x98, 32]);
    bytes[count + 1] = 33;
    let pin = AuthenticatedOperatorPolicyPinV1::new(SCOPE, Hash::from_bytes([7; 32]));
    on_both_adapters(|store| {
        for policy in &history[..32] {
            assert_eq!(install(store, policy), Ok(installed(policy)));
        }
        let refused = store.install(&pin, &bytes);
        assert_eq!(refused, Err(PolicyError::BoundsExceeded));
        assert_eq!(store.issuer_policy_floor(), Ok(Some(floor(full))));
        Ok(())
    })
}

#[test]
fn absent_imports_need_an_active_issuer_in_the_current_floor() -> Fallible<()> {
    let a = issuer("issuer-a", 1, 1)?;
    let b = issuer("issuer-b", 1, 2)?;
    let c = issuer("issuer-c", 1, 3)?;
    let stranger = issuer("issuer-d", 1, 4)?;
    let weak = Issuer::new("issuer-a", 1, PublicKey::from_bytes(WEAK_POINT))?;
    let first = genesis(&[(&a, ACTIVE), (&b, ACTIVE), (&c, ACTIVE)])?;
    let second = successor(&first, &[(&a, ACTIVE), (&b, RETIRED), (&c, REVOKED)])?;
    let absent = Basis::AbsentImport;
    let cases = [
        (&b, &second, PolicyError::IssuerRetired),
        (&c, &second, PolicyError::IssuerRevoked),
        (&stranger, &second, PolicyError::UntrustedIssuer),
        (&weak, &second, PolicyError::InvalidIssuerKey),
        (&a, &first, PolicyError::PolicyChanged),
    ];
    on_both_adapters(|store| {
        let unavailable = Err(PolicyError::PolicyUnavailable);
        assert_eq!(decide(store, &a, &first, absent), unavailable);
        for policy in [&first, &second] {
            assert_eq!(install(store, policy), Ok(installed(policy)));
        }
        assert_eq!(decide(store, &a, &second, absent), Ok(admitted(&second)));
        for (issuer, policy, error) in cases {
            assert_eq!(decide(store, issuer, policy, absent), Err(error));
        }
        Ok(())
    })
}

#[test]
fn committed_imports_are_decided_by_their_recorded_policy_only() -> Fallible<()> {
    let a = issuer("issuer-a", 1, 1)?;
    let b = issuer("issuer-b", 1, 2)?;
    let c = issuer("issuer-c", 1, 3)?;
    let first = genesis(&[(&a, ACTIVE), (&b, ACTIVE), (&c, ACTIVE)])?;
    let second = successor(&first, &[(&a, ACTIVE), (&b, RETIRED), (&c, REVOKED)])?;
    let corrupt = PolicyError::CorruptPolicy;
    let cases = [
        (&c, &second, committed(2), PolicyError::IssuerRevoked),
        (&b, &second, committed(2), PolicyError::IssuerRetired),
        (&b, &second, committed(1), corrupt),
        (&b, &first, committed(3), corrupt),
        (&b, &first, committed(0), corrupt),
        (&b, &first, committed(u64::MAX), corrupt),
    ];
    on_both_adapters(|store| {
        assert_eq!(decide(store, &b, &first, committed(1)), Err(corrupt));
        for policy in [&first, &second] {
            assert_eq!(install(store, policy), Ok(installed(policy)));
        }
        // Retirement and revocation after commit never block recovery.
        for retained in [&b, &c] {
            let recovered = decide(store, retained, &first, committed(1));
            assert_eq!(recovered, Ok(admitted(&first)));
        }
        for (issuer, policy, basis, error) in cases {
            assert_eq!(decide(store, issuer, policy, basis), Err(error));
        }
        Ok(())
    })
}

#[test]
fn sqlite_policy_history_and_floor_survive_reopen() -> Fallible<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("issuer-policy.sqlite");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    let a = issuer("issuer-a", 1, 1)?;
    let b = issuer("issuer-b", 1, 2)?;
    let first = genesis(&[(&a, ACTIVE), (&b, ACTIVE)])?;
    let second = successor(&first, &[(&a, RETIRED), (&b, ACTIVE)])?;
    {
        let mut store = SqliteStore::open(path)?;
        for policy in [&first, &second] {
            assert_eq!(install(&mut store, policy), Ok(installed(policy)));
        }
    }
    let mut store = SqliteStore::open(path)?;
    assert_eq!(store.issuer_policy_floor(), Ok(Some(floor(&second))));
    refuse(&mut store, &first, PolicyError::Rollback)?;
    let recovered = decide(&store, &a, &first, committed(1));
    assert_eq!(recovered, Ok(admitted(&first)));
    Ok(())
}
