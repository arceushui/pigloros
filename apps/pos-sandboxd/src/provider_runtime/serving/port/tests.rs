//! The execute port's refusal codes and output transfer, without a runtime.

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use ciborium::value::Value;
use pos_reference::provider_admission::execution::StagingError;
use pos_reference::sandbox_provider_protocol::SandboxProviderErrorCode as Code;
use pos_reference::selector::InstallationError;

use super::{lifecycle_answer, payload_length, staging_code, transfer_output, Answer, Transfer};
use crate::AttemptLifecycleError;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn every_refusal_before_agr1_has_its_section_7_5_code() {
    let cases = [
        (StagingError::InvalidSource, Some(Code::AuthorityMismatch)),
        (
            StagingError::Source(InstallationError::ArtifactInvalid),
            Some(Code::AuthorityMismatch),
        ),
        (
            StagingError::CapabilityMissing,
            Some(Code::ProviderCapabilityMissing),
        ),
        (
            StagingError::ImageIdentity,
            Some(Code::ImageIdentityMismatch),
        ),
        (StagingError::InputTooLarge, Some(Code::FieldOutOfBounds)),
        (StagingError::BelowControlFloor, Some(Code::TrustRevoked)),
        (StagingError::CleanupFailed, Some(Code::CleanupFailed)),
        (StagingError::QueueFull, Some(Code::AdmissionBusy)),
        (StagingError::AttemptsExhausted, Some(Code::AdmissionBusy)),
        (StagingError::AggregateExceeded, Some(Code::AdmissionBusy)),
        (
            StagingError::ControlSlotsExhausted,
            Some(Code::AdmissionBusy),
        ),
        (
            StagingError::InputWindowExpired,
            Some(Code::PayloadTransferTimeout),
        ),
        // Item P1: the initial control deadline after step 6 is 11.
        (StagingError::ControlExpired, Some(Code::SandboxUnavailable)),
        (
            StagingError::UnsafeDirectory,
            Some(Code::SandboxUnavailable),
        ),
        (
            StagingError::Io(io::Error::other("injected")),
            Some(Code::SandboxUnavailable),
        ),
        (
            StagingError::Source(InstallationError::Io),
            Some(Code::SandboxUnavailable),
        ),
        // R9 §5: a signing fault emits nothing.
        (StagingError::SignerFault, None),
        (StagingError::GrantCommitmentMismatch, None),
    ];
    for (error, code) in cases {
        assert_eq!(staging_code(&error), code, "{error:?}");
    }
}

/// The code a join answer carries, or what else it is.
fn joined(error: &AttemptLifecycleError) -> Result<Code, &'static str> {
    match lifecycle_answer(error) {
        Answer::Refused(code) => Ok(code),
        Answer::Silent => Err("silent"),
        Answer::Replay(_) => Err("replay"),
    }
}

#[test]
fn lifecycle_refusals_name_their_codes() {
    assert_eq!(
        joined(&AttemptLifecycleError::UnknownAttempt),
        Ok(Code::UnknownAttempt)
    );
    assert_eq!(
        joined(&AttemptLifecycleError::RequestConflict),
        Ok(Code::RequestIdentityConflict)
    );
    assert_eq!(
        joined(&AttemptLifecycleError::TooManyLiveAttempts),
        Ok(Code::AdmissionBusy)
    );
    assert_eq!(
        joined(&AttemptLifecycleError::Fenced),
        Ok(Code::SandboxUnavailable)
    );
    // An attempt another exchange claimed after step J.
    assert_eq!(
        joined(&AttemptLifecycleError::AttemptKnown),
        Ok(Code::SandboxUnavailable)
    );
    assert_eq!(
        joined(&AttemptLifecycleError::ResponseUnavailable),
        Err("silent")
    );
}

/// An output SBC1 record carrying `payload`.
fn record(payload: &[u8]) -> TestResult<Vec<u8>> {
    let unsigned = Value::Array(vec![
        Value::Text("SBC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(vec![1; 32]),
        Value::Bytes(vec![2; 16]),
        Value::Bytes(vec![3; 16]),
        Value::Integer(1.into()),
        Value::Integer(0.into()),
        Value::Integer(0.into()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut preimage = b"PiglorOS.SBC1.v1\0".to_vec();
    ciborium::into_writer(&unsigned, &mut preimage)?;
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &Value::Array(vec![
            unsigned,
            Value::Bytes(blake3::hash(&preimage).as_bytes().to_vec()),
        ]),
        &mut bytes,
    )?;
    Ok(bytes)
}

/// A clock that always reads 7 ns.
const CLOCK: fn() -> io::Result<u64> = || Ok(7);

fn broken_clock() -> io::Result<u64> {
    Err(io::Error::other("no clock"))
}

#[test]
fn an_output_record_counts_its_payload_bytes() -> TestResult {
    assert_eq!(payload_length(&record(b"abc")?), 3);
    assert_eq!(payload_length(b"no record"), 0);
    Ok(())
}

#[test]
fn a_complete_output_transfer_writes_every_record_in_order() -> TestResult {
    let (provider, mut selector) = UnixStream::pair()?;
    let records = [record(b"ab")?, record(b"c")?];
    assert_eq!(
        transfer_output(&provider, &records, (3, Duration::from_secs(5)), CLOCK),
        Transfer::Complete
    );
    drop(provider);
    let mut received = Vec::new();
    selector.read_to_end(&mut received)?;
    let mut expected = Vec::new();
    for record in &records {
        expected.extend(u32::try_from(record.len())?.to_be_bytes());
        expected.extend(record);
    }
    assert_eq!(received, expected);
    Ok(())
}

#[test]
fn an_output_transfer_that_runs_out_of_its_window_records_how_far_it_got() -> TestResult {
    let (provider, _selector) = UnixStream::pair()?;
    // A peer that never reads: the socket buffer fills, and the window ends.
    let large = record(&vec![0; 1024 * 1024])?;
    let records = [record(b"head")?, large.clone(), large];
    let timed_out = transfer_output(&provider, &records, (9, Duration::from_millis(50)), CLOCK);
    let Transfer::TimedOut(Some(transfer)) = timed_out else {
        return Err(format!("{timed_out:?}").into());
    };
    assert_eq!((transfer.start, transfer.finish), (7, 7));
    assert_eq!(transfer.deadline, 7 + 50_000_000);
    assert_eq!(transfer.expected_bytes, 9);
    assert!(transfer.accepted_bytes >= 4);
    assert!(!transfer.complete);
    // Without a readable clock the transfer has no record (change F).
    let (provider, _selector) = UnixStream::pair()?;
    assert_eq!(
        transfer_output(
            &provider,
            &records,
            (9, Duration::from_millis(50)),
            broken_clock
        ),
        Transfer::TimedOut(None)
    );
    Ok(())
}

#[test]
fn an_output_transfer_to_a_closed_peer_is_broken() -> TestResult {
    let (provider, selector) = UnixStream::pair()?;
    // A test forking concurrently may hold a duplicate of the peer: the
    // shutdown closes the connection whatever holds it.
    selector.shutdown(std::net::Shutdown::Both)?;
    drop(selector);
    assert_eq!(
        transfer_output(
            &provider,
            &[record(b"x")?],
            (1, Duration::from_secs(5)),
            CLOCK
        ),
        Transfer::Broken
    );
    Ok(())
}

/// The port's answers through one `Responder`, as root in the isolated
/// container, over socket pairs instead of the bound endpoints.
mod served {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};

    use pos_reference::provider_admission::execution::{ExecutePeer, ExecuteSource};
    use pos_reference::provider_admission::test_support::StagedInstallation;
    use pos_reference::sandbox_provider_protocol::{
        AdmissionGrant, RequestAuthority, SandboxCancelRequest, SandboxCancelResponse,
        SandboxCancellationResult, SandboxDescribeResponse, SandboxExecuteRequest,
        SandboxProviderError, SandboxProviderErrorCode as Code, SandboxProviderResult,
        SandboxReconcileRequest,
    };

    use super::super::{transfer_output, Transfer};
    use super::TestResult;
    use crate::provider_runtime::port::ExecutePort;
    use crate::provider_runtime::serving::tests::{
        describe, request, request_authority, Authority,
    };
    use crate::provider_runtime::serving::{
        Admission, RequestIdentity, Responder, EXECUTE, FENCED, REVOKED,
    };
    use crate::provider_runtime::tests::{
        bind_as_provider, in_isolated_root, install_spi1, spi1, test_port, RUNTIME_SEED,
    };
    use crate::provider_runtime::AdmissionState;
    use crate::{KeyFileRuntimeSigner, StagingLimits};
    use ciborium::value::Value;

    const TIMEOUT: Duration = Duration::from_secs(10);

    fn framed(records: &[&[u8]]) -> TestResult<Vec<u8>> {
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend(u32::try_from(record.len())?.to_be_bytes());
            bytes.extend(*record);
        }
        Ok(bytes)
    }

    /// Every record the peer of a connection `serve` answers receives: the
    /// source is sent without ending the write side; once `granted`, AGR1
    /// is read and the write side ended.
    fn served(
        source: &[&[u8]],
        granted: bool,
        serve: impl FnOnce(UnixStream) + Send,
    ) -> TestResult<Vec<Vec<u8>>> {
        let (server, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(TIMEOUT))?;
        peer.write_all(&framed(source)?)?;
        std::thread::scope(|scope| {
            let serving = scope.spawn(move || serve(server));
            let mut received = Vec::new();
            if granted {
                let mut prefix = [0; 4];
                peer.read_exact(&mut prefix)?;
                let mut grant = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
                peer.read_exact(&mut grant)?;
                received.push(grant);
                peer.shutdown(std::net::Shutdown::Write)?;
            }
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest)?;
            serving.join().map_err(|_| "serving panicked")?;
            let mut rest = rest.as_slice();
            while !rest.is_empty() {
                let (prefix, tail) = rest.split_at_checked(4).ok_or("short frame")?;
                let length = usize::try_from(u32::from_be_bytes(prefix.try_into()?))?;
                let (record, tail) = tail.split_at_checked(length).ok_or("short record")?;
                received.push(record.to_vec());
                rest = tail;
            }
            Ok(received)
        })
    }

    /// The code and request ID of the one SPE1 `received`.
    fn refused(received: &[Vec<u8>]) -> TestResult<(Code, Option<[u8; 16]>)> {
        assert_eq!(received.len(), 1, "one record");
        let error = SandboxProviderError::from_canonical_cbor(&received[0])?;
        Ok((error.code, error.request_id))
    }

    /// The port held by `admission`.
    fn port(admission: &OnceLock<AdmissionState>) -> TestResult<&ExecutePort> {
        match admission.get() {
            Some(AdmissionState::Open(port)) => Ok(port),
            _ => Err("no port".into()),
        }
    }

    /// Hand-offs (item P7) and reads that never got a reader (item P13).
    #[test]
    fn a_refused_charge_is_handed_off_and_an_unserved_read_gets_zero() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::a_refused_charge_is_handed_off_and_an_unserved_read_gets_zero",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let request = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        let id = Some(request.request.request_id);
        let source = [staged.evaluation(), staged.request()];
        let answered = |responder: &Responder<'_>, admission, granted| {
            served(&source, granted, |stream| {
                responder.answer(stream, admission, None);
            })
        };
        // A ledger that refuses the source's charge hands it off: 12 with
        // its identities, then 14 once the ledger is closed (item P7).
        let (_tiny_tree, tiny) = test_port(StagingLimits { aggregate_bytes: 1 })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(tiny)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        assert_eq!(
            refused(&answered(&responder, Admission::Answered, false)?)?,
            (Code::AdmissionBusy, id)
        );
        // A handed-off source read to its end fails its own step first.
        let stale = staged.changed_request(|request| request.request.policy_epoch += 1)?;
        let handed = served(&[staged.evaluation(), &stale], false, |stream| {
            responder.answer(stream, Admission::Answered, None);
        })?;
        assert_eq!(refused(&handed)?.0, Code::AuthorityMismatch);
        port(&open)?.ledger.close_for_reconciliation();
        assert_eq!(
            refused(&answered(&responder, Admission::Answered, false)?)?,
            (Code::CleanupFailed, id)
        );
        // A hand-off that waits for a reader past its deadline was never
        // read: 0 with no identity (the item P13 answer). So is a refusal
        // read that never got a place.
        let held: Vec<_> = (0..4)
            .map(|_| responder.refusals.wait(Instant::now()))
            .collect();
        assert!(held.iter().all(Option::is_some));
        let unserved = refused(&answered(&responder, Admission::Answered, false)?)?;
        assert_eq!(unserved, (Code::InvalidEncoding, None));
        let unserved = refused(&answered(&responder, Admission::Busy, false)?)?;
        assert_eq!(unserved, (Code::InvalidEncoding, None));
        drop(held);
        drop(staged);
        Ok(())
    }

    /// Busy repeats join (item P10); other requests beyond the pool are refused.
    #[test]
    fn an_exact_repeat_beyond_the_pool_joins_the_attempt() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::an_exact_repeat_beyond_the_pool_joins_the_attempt",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let request = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        let id = Some(request.request.request_id);
        let source = [staged.evaluation(), staged.request()];
        let answered = |responder: &Responder<'_>, admission, granted| {
            served(&source, granted, |stream| {
                responder.answer(stream, admission, None);
            })
        };
        // An admitted attempt, then its exact repeat beyond the answered
        // pool joins it (item P10); other bytes get 16, and a fresh request
        // beyond the pool 12.
        let (_tree, port_value) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(port_value)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        let first = answered(&responder, Admission::Answered, true)?;
        assert!(first.len() > 2);
        assert_eq!(answered(&responder, Admission::Busy, false)?, first);
        // With every busy join's place taken, the repeat waits for none: 12.
        let places: Vec<_> = (0..4)
            .map(|_| responder.joins.wait(Instant::now()))
            .collect();
        assert!(places.iter().all(Option::is_some));
        assert_eq!(
            refused(&answered(&responder, Admission::Busy, false)?)?,
            (Code::AdmissionBusy, id)
        );
        drop(places);
        assert_eq!(answered(&responder, Admission::Busy, false)?, first);
        let conflicting = staged.changed_request(|request| request.request.nonce[0] ^= 1)?;
        let busy = served(&[staged.evaluation(), &conflicting], false, |stream| {
            responder.answer(stream, Admission::Busy, None);
        })?;
        assert_eq!(refused(&busy)?, (Code::RequestIdentityConflict, id));
        let other = staged.changed_request(|request| {
            request.request.request_id[0] ^= 1;
            request.attempt_id[0] ^= 1;
        })?;
        let busy = served(&[staged.evaluation(), &other], false, |stream| {
            responder.answer(stream, Admission::Busy, None);
        })?;
        assert_eq!(refused(&busy)?.0, Code::AdmissionBusy);
        // A repeat whose connection is gone gets nothing written.
        let (server, peer) = UnixStream::pair()?;
        let mut writer = &peer;
        writer.write_all(&framed(&source)?)?;
        peer.shutdown(std::net::Shutdown::Read)?;
        responder.answer(server, Admission::Busy, None);
        drop(peer);
        drop(staged);
        Ok(())
    }

    /// A claim's wait (item P1), the second state read (§7.2) and a signer fault (R9 §5).
    #[test]
    fn the_state_after_step_6_and_a_signer_fault_decide_the_answer() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::the_state_after_step_6_and_a_signer_fault_decide_the_answer",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let request = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        let id = Some(request.request.request_id);
        let source = [staged.evaluation(), staged.request()];
        let answered = |responder: &Responder<'_>, admission, granted| {
            served(&source, granted, |stream| {
                responder.answer(stream, admission, None);
            })
        };
        // A repeat waiting on a claim past its own deadline gets 11 (item
        // P1).
        let (_claim_tree, claimed) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(claimed)));
        let claim = port(&open)?.lifecycle.claim(
            request.attempt_id,
            request.request.request_id,
            request.request_digest,
        )?;
        let responder = Responder::new(&admitted, &signer, &open, 4);
        assert_eq!(
            refused(&answered(&responder, Admission::Answered, false)?)?,
            (Code::SandboxUnavailable, id)
        );
        drop(claim);
        // The admission state read again after step 6 decides (§7.2): a
        // fence since the sample gives 11, a revocation nothing.
        let (_state_tree, state_port) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(state_port)));
        for (state, expected) in [
            (FENCED, Some((Code::SandboxUnavailable, id))),
            (REVOKED, None),
        ] {
            let responder = Responder::new(&admitted, &signer, &open, 4);
            let received = served(&source, false, |stream| {
                let source = ExecutePeer::authenticate(stream).ok().and_then(|peer| {
                    ExecuteSource::read(peer, &port(&open).ok()?.ledger, &admitted).ok()
                });
                responder.revocation.observer().advance(state);
                if let (Some(source), Ok(port)) = (source, port(&open)) {
                    responder.execute(port, source);
                }
            })?;
            match expected {
                Some(answer) => assert_eq!(refused(&received)?, answer),
                None => assert!(received.is_empty()),
            }
        }
        // A runtime signer that cannot sign under the admitted key: the
        // exchange writes zero bytes and execute admission closes, so the
        // next execute is refused with 11 (invariant 36).
        let (_signer_tree, signer_port) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(signer_port)));
        let foreign = Arc::new(KeyFileRuntimeSigner::from_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
            "foreign".to_owned(),
        ));
        let responder = Responder::new(&admitted, &foreign, &open, 4);
        assert!(answered(&responder, Admission::Answered, false)?.is_empty());
        assert!(!port(&open)?.open());
        let responder = Responder::new(&admitted, &signer, &open, 4);
        assert_eq!(
            refused(&answered(&responder, Admission::Answered, false)?)?,
            (Code::SandboxUnavailable, id)
        );
        drop(staged);
        Ok(())
    }

    /// Every record `deliver` writes to a fresh connection for `response`
    /// under `identity`, its output sent by `transfer`.
    fn delivered(
        responder: &Responder<'_>,
        port: &ExecutePort,
        (identity, response): (RequestIdentity, &Arc<crate::RetainedResponse>),
        granted: bool,
        transfer: impl FnOnce(&UnixStream, &[Vec<u8>], u64) -> Transfer + Send,
    ) -> TestResult<Vec<Vec<u8>>> {
        served(&[], false, |stream| {
            responder.deliver_within(port, &stream, (identity, response), granted, transfer);
        })
    }

    /// An output transfer that timed out before it accepted a byte, timed
    /// after the fixture's cleanup finished, whatever this host's clock
    /// reads.
    fn timed_out(_: &UnixStream, _: &[Vec<u8>], expected: u64) -> Transfer {
        Transfer::TimedOut(Some(
            pos_reference::sandbox_provider_protocol::TransferRecord {
                start: 3_000_000_000_000,
                deadline: 3_002_000_000_000,
                finish: 3_002_000_000_000,
                expected_bytes: expected,
                accepted_bytes: 0,
                complete: false,
            },
        ))
    }

    /// The output transfer itself, within [`TIMEOUT`].
    fn complete(stream: &UnixStream, records: &[Vec<u8>], expected: u64) -> Transfer {
        transfer_output(
            stream,
            records,
            (expected, TIMEOUT),
            crate::launcher::clock::monotonic_ns,
        )
    }

    /// The execute identity of the attempt `response` answers.
    fn identity_of(response: &crate::RetainedResponse) -> TestResult<RequestIdentity> {
        let grant =
            AdmissionGrant::from_canonical_cbor(response.frames().next().ok_or("no AGR1")?)?;
        Ok(RequestIdentity {
            operation: EXECUTE,
            request_id: grant.request_id,
            request_digest: [0x5d; 32],
            attempt_id: Some(grant.attempt_id),
        })
    }

    /// An SCQ1 for `attempt_id` under the AGR1 `agr1_digest`.
    fn cancel_request(attempt_id: [u8; 16], agr1_digest: [u8; 32], id: u8) -> SandboxCancelRequest {
        SandboxCancelRequest {
            request: RequestAuthority {
                request_id: [id; 16],
                apt1_digest: [1; 32],
                policy_epoch: 1,
                nonce: [id; 16],
            },
            attempt_id,
            agr1_digest,
            request_digest: [id; 32],
        }
    }

    /// Base §4: a recovery connection that delivered the stored response
    /// whole keeps it, so the abandoned connection's later output timeout
    /// re-issues nothing; without a delivery the timeout re-issues it.
    #[test]
    fn a_response_delivered_by_a_joined_connection_is_never_reissued() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::a_response_delivered_by_a_joined_connection_is_never_reissued",
        )? {
            return Ok(());
        }
        let _staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let limits = StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        };
        let (_tree, port_value) = test_port(limits)?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(port_value)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        let first = port(&open)?;
        let stored = first
            .lifecycle
            .completed_for_test()
            .map_err(|error| error.to_string())?;
        let identity = identity_of(&stored)?;
        let attempt = identity.attempt_id.ok_or("no attempt")?;
        // B, the joined recovery connection, receives every frame, SPY1 last.
        let frames: Vec<Vec<u8>> = stored.frames().map(<[u8]>::to_vec).collect();
        let joined = delivered(&responder, first, (identity, &stored), false, complete)?;
        assert_eq!(joined, frames);
        // A, abandoned during its output, times out: nothing is re-issued,
        // and A got no SPY1.
        let abandoned = delivered(&responder, first, (identity, &stored), true, timed_out)?;
        assert_eq!(
            abandoned.len(),
            frames.len() - 1 - stored.output().0.len() - 1
        );
        assert!(Arc::ptr_eq(
            &first
                .lifecycle
                .terminal_response(attempt, stored.agr1_digest())?,
            &stored
        ));
        // Undelivered, the same timeout re-issues the response.
        let (_fresh_tree, fresh) = test_port(limits)?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(fresh)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        let fresh = port(&open)?;
        let stored = fresh
            .lifecycle
            .completed_for_test()
            .map_err(|error| error.to_string())?;
        delivered(&responder, fresh, (identity, &stored), true, timed_out)?;
        assert!(!fresh
            .lifecycle
            .terminal_response(attempt, stored.agr1_digest())
            .is_ok_and(|current| Arc::ptr_eq(&current, &stored)));
        // B still holds the replaced response: it may write its output, but
        // never its SPY1.
        let late = delivered(&responder, fresh, (identity, &stored), false, complete)?;
        assert_eq!(late.len(), frames.len() - 1);
        assert_eq!(late, frames[..frames.len() - 1]);
        Ok(())
    }

    /// Another operation on the execute socket is answered by its own
    /// rules once its request ends: an SCQ1 by the port, `15` for an
    /// attempt it does not hold and SCY1 `0` for a terminal one, an SDQ1 by
    /// its SDY1, and a request of another authority by its step 6 refusal.
    #[test]
    fn the_port_answers_every_other_operation_on_the_execute_socket() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::the_port_answers_every_other_operation_on_the_execute_socket",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let (_tree, port_value) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(port_value)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        let port = port(&open)?;
        let execute = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        let authority = Authority {
            apt1: execute.request.apt1_digest,
            epoch: execute.request.policy_epoch,
        };
        let ask = |record: &[u8]| -> TestResult<Vec<Vec<u8>>> {
            let (server, mut peer) = UnixStream::pair()?;
            peer.set_read_timeout(Some(TIMEOUT))?;
            peer.write_all(&framed(&[record])?)?;
            peer.shutdown(std::net::Shutdown::Write)?;
            responder.answer(server, Admission::Answered, None);
            read_frames(&mut peer)
        };
        let cancel_record = |attempt: [u8; 16], agr1: [u8; 32], authority| {
            request(
                "SCQ1",
                1,
                vec![
                    request_authority([8; 16], authority),
                    Value::Bytes(attempt.to_vec()),
                    Value::Bytes(agr1.to_vec()),
                ],
                false,
            )
        };
        assert_eq!(
            refused(&ask(&cancel_record([9; 16], [10; 32], authority)?)?)?.0,
            Code::UnknownAttempt
        );
        let stored = port
            .lifecycle
            .completed_for_test()
            .map_err(|error| error.to_string())?;
        let attempt = identity_of(&stored)?.attempt_id.ok_or("no attempt")?;
        let answered = ask(&cancel_record(attempt, stored.agr1_digest(), authority)?)?;
        let [scy1] = &answered[..] else {
            return Err("one SCY1".into());
        };
        let scy1 = SandboxCancelResponse::from_canonical_cbor(scy1)?;
        scy1.verify_signature(responder.key().key())?;
        assert_eq!(scy1.result, SandboxCancellationResult::AlreadyTerminal);
        let described = ask(&describe([4; 16], authority)?)?;
        let [description] = &described[..] else {
            return Err("one SDY1".into());
        };
        SandboxDescribeResponse::from_canonical_cbor(description)?;
        let other = Authority {
            apt1: [0x55; 32],
            ..authority
        };
        assert_eq!(
            refused(&ask(&cancel_record([9; 16], [10; 32], other)?)?)?.0,
            Code::AuthorityMismatch
        );
        drop(staged);
        Ok(())
    }

    /// Refusals of a charged source after its read: another authority at
    /// step 6, a staging file that cannot be created (`11`), an AGR1 write
    /// that failed (nothing more, and no attempt remains), and a request ID
    /// another attempt claimed with other bytes (`16`).
    #[test]
    fn a_charged_source_is_refused_at_the_step_that_fails() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::a_charged_source_is_refused_at_the_step_that_fails",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let (tree, port_value) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(port_value)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        let port = port(&open)?;
        let execute = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        let id = Some(execute.request.request_id);
        let answered = |source: &[&[u8]], granted| {
            served(source, granted, |stream| {
                responder.answer(stream, Admission::Answered, None);
            })
        };
        let stale = staged.changed_request(|request| request.request.policy_epoch += 1)?;
        assert_eq!(
            refused(&answered(&[staged.evaluation(), &stale], false)?)?,
            (Code::AuthorityMismatch, id)
        );
        // Step S: an entry already at the staging name is never adopted.
        let name = execute
            .attempt_id
            .iter()
            .fold(String::new(), |mut name, byte| {
                use std::fmt::Write as _;
                write!(name, "{byte:02x}").ok();
                name
            });
        let planted = tree.staging().join(name);
        std::fs::write(&planted, b"")?;
        let source = [staged.evaluation(), staged.request()];
        assert_eq!(
            refused(&answered(&source, false)?)?,
            (Code::SandboxUnavailable, id)
        );
        std::fs::remove_file(&planted)?;
        // Step W: the AGR1 write fails, and nothing follows it.
        let (server, peer) = UnixStream::pair()?;
        (&peer).write_all(&framed(&source)?)?;
        peer.shutdown(std::net::Shutdown::Read)?;
        responder.answer(server, Admission::Answered, None);
        assert!(matches!(
            port.runtime.block_on(
                port.lifecycle
                    .join(execute.attempt_id, execute.request_digest)
            ),
            Ok(None)
        ));
        drop(peer);
        // Step A: another exchange claimed this request ID with other
        // bytes, under another attempt: the claim refuses it.
        port.lifecycle
            .failed_granted(
                &pos_reference::provider_admission::execution::FailedInput::fixture(
                    execute.request.request_id,
                    [0x42; 32],
                ),
            )
            .map_err(|error| error.to_string())?;
        assert_eq!(
            refused(&answered(&source, false)?)?,
            (Code::RequestIdentityConflict, id)
        );
        drop(staged);
        Ok(())
    }

    /// The frames of a whole response read from `peer` to its EOF.
    fn read_frames(peer: &mut UnixStream) -> TestResult<Vec<Vec<u8>>> {
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes)?;
        let mut rest = bytes.as_slice();
        let mut frames = Vec::new();
        while !rest.is_empty() {
            let (record, tail) = next_frame(rest)?;
            frames.push(record.to_vec());
            rest = tail;
        }
        Ok(frames)
    }

    /// The first length-prefixed record of `bytes`, and what follows it.
    fn next_frame(bytes: &[u8]) -> TestResult<(&[u8], &[u8])> {
        let (prefix, tail) = bytes.split_at_checked(4).ok_or("short frame")?;
        let length = usize::try_from(u32::from_be_bytes(prefix.try_into()?))?;
        Ok(tail.split_at_checked(length).ok_or("short record")?)
    }

    /// Base §4: while B stands mid-response with the re-issued R2, between
    /// its head and its output, A, whose transfer of the replaced R1 timed
    /// out, re-issues nothing from R2: its successor of R1 is discarded, R2
    /// stays stored, and B writes R2's SPY1 once it goes on.
    #[test]
    fn a_stale_reissue_never_replaces_the_response_another_connection_writes() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::a_stale_reissue_never_replaces_the_response_another_connection_writes",
        )? {
            return Ok(());
        }
        let _staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let (_tree, port_value) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(port_value)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        let port = port(&open)?;
        let first = port
            .lifecycle
            .completed_for_test()
            .map_err(|error| error.to_string())?;
        let identity = identity_of(&first)?;
        let attempt = identity.attempt_id.ok_or("no attempt")?;
        let current = || {
            port.lifecycle
                .terminal_response(attempt, first.agr1_digest())
        };
        // Another connection's output transfer of R1 timed out: R2.
        delivered(&responder, port, (identity, &first), true, timed_out)?;
        let second = current()?;
        assert!(!Arc::ptr_eq(&second, &first));
        let (server, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(TIMEOUT))?;
        // B writes R2's head, then stops at its output until A is done.
        let (at_output, reached) = std::sync::mpsc::channel();
        let (resume, resumed) = std::sync::mpsc::channel::<()>();
        let held = move |stream: &UnixStream, records: &[Vec<u8>], expected| {
            at_output.send(()).ok();
            resumed.recv().ok();
            complete(stream, records, expected)
        };
        std::thread::scope(|scope| -> TestResult {
            // Owned by the scope: an early return or panic drops it, so B
            // wakes and the scope's join cannot hang.
            let resume = resume;
            let writing = scope.spawn(|| {
                responder.deliver_within(port, &server, (identity, &second), false, held);
            });
            reached.recv_timeout(TIMEOUT)?;
            assert!(!writing.is_finished(), "B stands at its output");
            assert!(!second.delivered());
            // A times out on R1 while B writes R2; its peer already ended
            // its write side, so A ends at once.
            let (abandoned, other) = UnixStream::pair()?;
            other.shutdown(std::net::Shutdown::Write)?;
            responder.deliver_within(port, &abandoned, (identity, &first), true, timed_out);
            assert!(Arc::ptr_eq(&current()?, &second));
            resume.send(())?;
            peer.shutdown(std::net::Shutdown::Write)?;
            let frames = read_frames(&mut peer)?;
            writing.join().map_err(|_| "B panicked")?;
            assert_eq!(
                frames,
                second.frames().map(<[u8]>::to_vec).collect::<Vec<_>>()
            );
            Ok(())
        })?;
        assert!(second.delivered());
        Ok(())
    }

    /// Port steps 7 to W, the input, the run and the delivery: an admitted
    /// attempt whose input arrives whole runs through the port, and the
    /// connection receives its stored full response after its AGR1, SPY1
    /// last, which is then delivered.
    #[test]
    fn an_admitted_attempt_runs_and_its_stored_response_follows_its_agr1() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::an_admitted_attempt_runs_and_its_stored_response_follows_its_agr1",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let (_tree, port_value) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(port_value)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        let port = port(&open)?;
        let (server, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(TIMEOUT))?;
        staged.write_source(&mut peer)?;
        let (grant, rest) = std::thread::scope(|scope| -> TestResult<_> {
            let serving = scope.spawn(|| responder.answer(server, Admission::Answered, None));
            let mut prefix = [0; 4];
            peer.read_exact(&mut prefix)?;
            let mut grant = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
            peer.read_exact(&mut grant)?;
            staged.write_input(&mut peer)?;
            peer.shutdown(std::net::Shutdown::Write)?;
            let rest = read_frames(&mut peer)?;
            serving.join().map_err(|_| "serving panicked")?;
            Ok((grant, rest))
        })?;
        let decoded = AdmissionGrant::from_canonical_cbor(&grant)?;
        let stored = port
            .lifecycle
            .terminal_response(decoded.attempt_id, decoded.grant_digest())?;
        let frames: Vec<Vec<u8>> = stored.frames().map(<[u8]>::to_vec).collect();
        assert_eq!(frames[0], grant);
        assert_eq!(rest, frames[1..]);
        assert!(stored.delivered());
        // The run itself stops at its preparation in the container, which
        // has no mountfsd: an admitted attempt that did not execute.
        let result = SandboxProviderResult::from_canonical_cbor(stored.response().result)?;
        assert_eq!(
            result.outcome,
            pos_reference::sandbox_provider_protocol::SandboxTerminalOutcome::UnavailableAfterAdmission
        );
        assert_eq!(result.agr1_digest, Some(decoded.grant_digest()));
        drop(staged);
        Ok(())
    }

    /// A cancellation of an admitted attempt that awaits its input is
    /// recorded for its ending, which has no SPY1 yet: `11`, no fabricated
    /// SPY1 (until the N6 decision); the exchange still ends in its stored
    /// response once its input ends.
    fn cancels_an_attempt_awaiting_its_input(
        responder: &Responder<'_>,
        port: &ExecutePort,
        staged: &StagedInstallation,
        (signer, key): (&KeyFileRuntimeSigner, crate::AdmittedRuntimeKey<'_>),
    ) -> TestResult<AdmissionGrant> {
        let source = [staged.evaluation(), staged.request()];
        let (server, mut peer) = UnixStream::pair()?;
        peer.set_read_timeout(Some(TIMEOUT))?;
        peer.write_all(&framed(&source)?)?;
        std::thread::scope(|scope| -> TestResult<AdmissionGrant> {
            let serving = scope.spawn(|| responder.answer(server, Admission::Answered, None));
            let mut prefix = [0; 4];
            peer.read_exact(&mut prefix)?;
            let mut bytes = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
            peer.read_exact(&mut bytes)?;
            let grant = AdmissionGrant::from_canonical_cbor(&bytes)?;
            assert_eq!(
                port.cancel(
                    &cancel_request(grant.attempt_id, grant.grant_digest(), 6),
                    Instant::now() + TIMEOUT,
                    (signer, key),
                ),
                Err(Some(Code::SandboxUnavailable))
            );
            peer.shutdown(std::net::Shutdown::Write)?;
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest)?;
            assert!(!rest.is_empty());
            serving.join().map_err(|_| "serving panicked")?;
            Ok(grant)
        })
    }

    /// A cancellation waits for a response still being signed, and gets
    /// `11` once its deadline passes with none.
    fn cancel_waits_for_a_pending_response(
        (signer, key): (&KeyFileRuntimeSigner, crate::AdmittedRuntimeKey<'_>),
    ) -> TestResult {
        let limits = StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        };
        let (_late_tree, late) = test_port(limits)?;
        let pending = late
            .lifecycle
            .completed_pending_for_test()
            .map_err(|error| error.to_string())?;
        assert_eq!(
            late.cancel(
                &cancel_request(pending.attempt_id, pending.agr1_digest, 8),
                Instant::now() + Duration::from_millis(50),
                (signer, key),
            ),
            Err(Some(Code::SandboxUnavailable))
        );
        let (_tree, port) = test_port(limits)?;
        let pending = port
            .lifecycle
            .completed_pending_for_test()
            .map_err(|error| error.to_string())?;
        let (attempt, digest) = (pending.attempt_id, pending.agr1_digest);
        std::thread::scope(|scope| -> TestResult {
            let cancelling = scope.spawn(|| {
                port.cancel(
                    &cancel_request(attempt, digest, 9),
                    Instant::now() + TIMEOUT,
                    (signer, key),
                )
            });
            // Retained before or during the wait, the cancellation binds it.
            pending
                .retain(&port.lifecycle)
                .map_err(|error| error.to_string())?;
            let answered = cancelling
                .join()
                .map_err(|_| "cancel panicked")?
                .map_err(|code| format!("{code:?}"))?;
            let scy1 = SandboxCancelResponse::from_canonical_cbor(&answered)?;
            assert_eq!(scy1.result, SandboxCancellationResult::AlreadyTerminal);
            Ok(())
        })
    }

    /// SCY1 (base §4, §10): `0` binds the SPY1 of an attempt already
    /// terminal and delivers it, so no later timeout re-issues it; an exact
    /// repeat gets the same bytes; `1` binds the SPY1 of the attempt this
    /// request cancelled; an unknown attempt is `15`; an attempt with no
    /// SPY1 by the deadline is `11`.
    #[test]
    fn cancel_binds_the_terminal_spy1_and_delivers_it() -> TestResult {
        if !in_isolated_root(
            "provider_runtime::serving::port::tests::served::cancel_binds_the_terminal_spy1_and_delivers_it",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
        let (admitted, _, signer) = bind_as_provider()??;
        let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
        let (_tree, port_value) = test_port(StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        })?;
        let open = OnceLock::from(AdmissionState::Open(Box::new(port_value)));
        let responder = Responder::new(&admitted, &signer, &open, 4);
        let port = port(&open)?;
        let key = responder.key();
        let soon = || Instant::now() + Duration::from_secs(5);
        // Already terminal: 0, bound to the stored SPY1.
        let stored = port
            .lifecycle
            .completed_for_test()
            .map_err(|error| error.to_string())?;
        let identity = identity_of(&stored)?;
        let attempt = identity.attempt_id.ok_or("no attempt")?;
        let request = cancel_request(attempt, stored.agr1_digest(), 3);
        let answered = port
            .cancel(&request, soon(), (&*signer, key))
            .map_err(|code| format!("{code:?}"))?;
        let scy1 = SandboxCancelResponse::from_canonical_cbor(&answered)?;
        scy1.verify_signature(key.key())?;
        assert_eq!(scy1.result, SandboxCancellationResult::AlreadyTerminal);
        let terminal = SandboxProviderResult::from_canonical_cbor(stored.response().result)?;
        assert_eq!(scy1.terminal_spy1_digest, terminal.result_digest());
        // An exact repeat gets the same bytes; the SCY1 delivered the
        // response, so a later output timeout keeps it.
        assert_eq!(
            port.cancel(&request, soon(), (&*signer, key))
                .map_err(|code| format!("{code:?}"))?,
            answered
        );
        delivered(&responder, port, (identity, &stored), true, timed_out)?;
        assert!(Arc::ptr_eq(
            &port
                .lifecycle
                .terminal_response(attempt, stored.agr1_digest())?,
            &stored
        ));
        // Once the attempt is reconciled, its SCY1 is forgotten: a repeat
        // names an unknown attempt.
        port.lifecycle.reconcile(&SandboxReconcileRequest {
            request: cancel_request(attempt, stored.agr1_digest(), 5).request,
            attempt_id: attempt,
            agr1_digest: stored.agr1_digest(),
            request_digest: [5; 32],
        })?;
        assert_eq!(
            port.cancel(&request, soon(), (&*signer, key)),
            Err(Some(Code::UnknownAttempt))
        );
        assert!(port.cancelled.lock().map_err(|_| "poisoned")?.is_empty());
        // An unknown attempt, and one under another AGR1.
        assert_eq!(
            port.cancel(
                &cancel_request([0x33; 16], [0x34; 32], 4),
                soon(),
                (&*signer, key)
            ),
            Err(Some(Code::UnknownAttempt))
        );
        cancel_waits_for_a_pending_response((&signer, key))?;
        let grant =
            cancels_an_attempt_awaiting_its_input(&responder, port, &staged, (&signer, key))?;
        // A signer that cannot sign under the admitted key emits nothing and
        // closes execute admission (R9 §5); the response stays delivered.
        let foreign = KeyFileRuntimeSigner::from_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
            "foreign".to_owned(),
        );
        assert!(port.open());
        assert_eq!(
            port.cancel(
                &cancel_request(grant.attempt_id, grant.grant_digest(), 7),
                soon(),
                (&foreign, key)
            ),
            Err(None)
        );
        assert!(!port.open());
        assert!(port
            .lifecycle
            .terminal_response(grant.attempt_id, grant.grant_digest())?
            .delivered());
        drop(staged);
        Ok(())
    }
}
