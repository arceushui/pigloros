//! The shape of a failure Abort's sealed input and the records derived from
//! it (I204, I207 and the derivation of I200).

use pos_core::community_lifecycle::{
    community_decision_provenance_digest_v1, CommunityAbortReasonV1 as Reason,
    CommunityDecisionProvenanceInputV1, CommunityGuestErrorCodeV1, CommunityGuestErrorV1,
    CommunityInvocationFailureV1, CommunityLifecycleErrorV1 as Error, CommunityPassFailureV1,
    CommunityPassKeyV1, CommunityPluginHostErrorV1 as Host, ComponentTrapClassV1,
    TrapReproductionV1,
};
use pos_core::{Hash, TimelineId};
use ulid::Ulid;

use super::{check_roster_order, check_shape, derive_failure};
use super::{CommunityObservedFailureV1 as Observed, CommunityPassAbortFailureInputV1 as Input};
use crate::community::pass_record::CommunityPassMemberDigestsV1;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HORIZON: u64 = 9_000;

fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([1; 16]))
}

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn pass_key() -> Result<CommunityPassKeyV1, Error> {
    CommunityPassKeyV1::new(timeline(), [0x20; 16], 7)
}

/// The three due members, in roster order.
fn due() -> [CommunityPassMemberDigestsV1; 3] {
    [1, 2, 3].map(|byte| CommunityPassMemberDigestsV1 {
        roster_index: usize::from(byte),
        cmb1_digest: hash(byte),
        cin1_digest: hash(byte + 10),
        trust_policy_snapshot_digest: hash(byte + 20),
    })
}

const TRAP: Host = Host::ComponentTrap {
    class: ComponentTrapClassV1::Other,
    reproduction: TrapReproductionV1::Unverified,
};

/// A reason-1 failure of `member`: a trap, which quarantines.
fn trap(member: u8) -> Observed<'static> {
    Observed {
        member_binding_digest: hash(member),
        invocation_id: Some([member; 16]),
        host_failure: TRAP,
        guest_error: None,
        control_operation_id: Some([member + 40; 16]),
    }
}

/// A reason-1 failure that quarantines nothing.
fn invalid_output(member: u8) -> Observed<'static> {
    Observed {
        member_binding_digest: hash(member),
        invocation_id: Some([member; 16]),
        host_failure: Host::InvalidGuestOutput,
        guest_error: None,
        control_operation_id: None,
    }
}

const fn guest_error() -> CommunityGuestErrorV1<'static> {
    CommunityGuestErrorV1 {
        code: CommunityGuestErrorCodeV1::GuestDeclaredFailure(7),
        canonical_coordinate: None,
        related_digest: None,
    }
}

fn declared(member: u8) -> Observed<'static> {
    Observed {
        member_binding_digest: hash(member),
        invocation_id: Some([member; 16]),
        host_failure: Host::GuestDeclaredFailure,
        guest_error: Some(guest_error()),
        control_operation_id: None,
    }
}

/// A reason-2 launch refusal of `member`: a missing feature.
fn refused(member: u8) -> Observed<'static> {
    Observed {
        member_binding_digest: hash(member),
        invocation_id: None,
        host_failure: Host::MissingFeature { index: 3 },
        guest_error: None,
        control_operation_id: None,
    }
}

fn input<'a>(reason: Reason, failures: &'a [Observed<'a>]) -> Input<'a> {
    Input {
        timeline: timeline(),
        reservation_operation_id: [0x30; 16],
        reason,
        failures,
    }
}

fn shape(reason: Reason, failures: &[Observed<'_>]) -> Result<(), Error> {
    check_shape(&input(reason, failures))
}

#[test]
fn a_valid_failure_input_of_each_reason_has_the_shape() -> TestResult {
    shape(
        Reason::ValidatedInvocationFailure,
        &[trap(1), invalid_output(2), declared(3)],
    )?;
    shape(Reason::AdmissionRefused, &[refused(2)])?;
    shape(Reason::ProtectedUseRefused, &[])?;
    Ok(())
}

#[test]
fn the_administrative_reasons_are_not_a_failure_input() {
    for reason in [
        Reason::AuthenticatedCancellation,
        Reason::RetiringGeneration,
    ] {
        assert_eq!(shape(reason, &[]), Err(Error::InvalidBinding));
    }
}

#[test]
fn reason_one_refuses_no_failure_and_a_missing_invocation() {
    let mut without = invalid_output(1);
    without.invocation_id = None;
    let mut zero = invalid_output(1);
    zero.invocation_id = Some([0; 16]);
    for failures in [vec![], vec![without], vec![zero]] {
        assert_eq!(
            shape(Reason::ValidatedInvocationFailure, &failures),
            Err(Error::InvalidBinding)
        );
    }
}

#[test]
fn reason_one_refuses_the_codes_a_v1_pass_cannot_observe() {
    for host_failure in [
        Host::StateMigrationFailed,
        Host::DeterministicDeadlineExceeded,
        Host::OperationalWatchdogStop,
        Host::MissingFeature { index: 0 },
    ] {
        let mut failure = invalid_output(1);
        failure.host_failure = host_failure;
        assert_eq!(
            shape(Reason::ValidatedInvocationFailure, &[failure]),
            Err(Error::InvalidBinding)
        );
    }
}

#[test]
fn a_guest_error_goes_with_the_declared_failure_only() {
    let mut extra = invalid_output(1);
    extra.guest_error = Some(guest_error());
    let mut missing = declared(1);
    missing.guest_error = None;
    for failure in [extra, missing] {
        assert_eq!(
            shape(Reason::ValidatedInvocationFailure, &[failure]),
            Err(Error::InvalidBinding)
        );
    }
}

#[test]
fn a_noncanonical_guest_error_is_refused_without_echoing_it() {
    let coordinate = [0_u8; 129];
    let mut failure = declared(1);
    failure.guest_error = Some(CommunityGuestErrorV1 {
        code: CommunityGuestErrorCodeV1::GuestDeclaredFailure(7),
        canonical_coordinate: Some(&coordinate),
        related_digest: None,
    });
    assert_eq!(
        shape(Reason::ValidatedInvocationFailure, &[failure]),
        Err(Error::InvalidBinding)
    );
}

#[test]
fn a_control_identity_goes_with_a_quarantining_failure_only() {
    let mut missing = trap(1);
    missing.control_operation_id = None;
    let mut zero = trap(1);
    zero.control_operation_id = Some([0; 16]);
    let mut extra = invalid_output(1);
    extra.control_operation_id = Some([9; 16]);
    for failure in [missing, zero, extra] {
        assert_eq!(
            shape(Reason::ValidatedInvocationFailure, &[failure]),
            Err(Error::InvalidBinding)
        );
    }
}

#[test]
fn a_control_identity_cannot_repeat() {
    let first = trap(1);
    let mut second = trap(2);
    second.control_operation_id = first.control_operation_id;
    assert_eq!(
        shape(Reason::ValidatedInvocationFailure, &[first, second]),
        Err(Error::InvalidBinding)
    );
}

#[test]
fn reason_two_is_one_launch_refusal_with_an_admitted_code() {
    let mut revoked = refused(1);
    revoked.host_failure = Host::ArtifactRevoked {
        basis: pos_core::community_lifecycle::RevocationBasisV1::Artifact,
    };
    revoked.control_operation_id = Some([9; 16]);
    let mut invoked = refused(1);
    invoked.invocation_id = Some([1; 16]);
    for failures in [
        vec![],
        vec![refused(1), refused(2)],
        vec![revoked],
        vec![invoked],
    ] {
        assert_eq!(
            shape(Reason::AdmissionRefused, &failures),
            Err(Error::InvalidBinding)
        );
    }
    let mut incompatible = refused(1);
    incompatible.host_failure = Host::IncompatibleAbi;
    assert_eq!(shape(Reason::AdmissionRefused, &[incompatible]), Ok(()));
}

#[test]
fn reason_three_carries_no_failure() {
    assert_eq!(
        shape(Reason::ProtectedUseRefused, &[invalid_output(1)]),
        Err(Error::InvalidBinding)
    );
}

#[test]
fn the_failures_must_name_due_members_in_roster_order_once() {
    let due = due();
    assert_eq!(check_roster_order(&[trap(1), trap(3)], &due), Ok(()));
    assert_eq!(
        check_roster_order(&[trap(3), trap(1)], &due),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        check_roster_order(&[trap(1), trap(1)], &due),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        check_roster_order(&[trap(9)], &due),
        Err(Error::InvalidBinding)
    );
}

#[test]
fn the_cfo1_lists_the_cfi1s_and_takes_the_first_failure() -> TestResult {
    let failures = [trap(1), declared(2), invalid_output(3)];
    let derived = derive_failure(pass_key()?, &due(), &failures, HORIZON)?;
    assert_eq!(derived.invocations.len(), 3);
    let cfo1 = CommunityPassFailureV1::from_canonical_cbor(&derived.failure)?;
    let fields = cfo1.as_input();
    assert!(fields.pass_key == Some(pass_key()?));
    assert_eq!(fields.host_failure, TRAP);
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    let listed: Vec<Hash> = fields.invocation_evidence_digests.iter().collect();
    let expected: Vec<Hash> = derived
        .invocations
        .iter()
        .map(|record| record.digest)
        .collect();
    assert_eq!(listed, expected);
    assert_eq!(cfo1.digest(), derived.failure_digest);
    let provenance = community_decision_provenance_digest_v1(CommunityDecisionProvenanceInputV1 {
        pass_key: Some(pass_key()?),
        member_binding_digest: hash(1),
        prepared_invocation_digest: Some(hash(11)),
        host_failure: Some(TRAP),
        trust_snapshot_digest: hash(21),
    });
    assert_eq!(fields.host_decision_provenance_digest, provenance);
    Ok(())
}

#[test]
fn a_cfi1_carries_the_members_cin1_and_the_guest_error() -> TestResult {
    let derived = derive_failure(pass_key()?, &due(), &[declared(2)], HORIZON)?;
    let record = derived.invocations.first().ok_or("no CFI1")?;
    let cfi1 = CommunityInvocationFailureV1::from_canonical_cbor(&record.bytes)?;
    let fields = cfi1.as_input();
    assert_eq!(fields.member_binding_digest, hash(2));
    assert_eq!(fields.prepared_invocation_digest, Some(hash(12)));
    assert_eq!(fields.invocation_id, Some([2; 16]));
    assert!(fields.guest_error == Some(guest_error()));
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    assert_eq!(cfi1.digest(), record.digest);
    assert_eq!(record.member, hash(2));
    assert_eq!(record.host_failure, Host::GuestDeclaredFailure);
    Ok(())
}

#[test]
fn a_failure_of_a_member_that_is_not_due_derives_nothing() -> TestResult {
    assert!(matches!(
        derive_failure(pass_key()?, &due(), &[trap(9)], HORIZON),
        Err(Error::InvalidBinding)
    ));
    assert!(matches!(
        derive_failure(pass_key()?, &due(), &[], HORIZON),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}
