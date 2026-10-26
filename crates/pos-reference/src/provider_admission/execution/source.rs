//! Root-authenticated source reconstruction and descriptor-bound input.

use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::AsFd as _,
        unix::{fs::FileExt as _, net::UnixStream},
    },
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use crate::{
    adapter_transport::{read_attempt, write_attempt},
    evaluator_protocol::EvaluationRequest,
    sandbox_provider_protocol::{
        AdmissionAuthority, AdmissionGrant, PayloadDescriptor, PayloadDirection,
        PayloadStreamValidator, SandboxExecuteRequest, SandboxPayloadChunk,
    },
    selector::installation::{
        authority::{AdmittedSelectorProvider, AuthenticatedSelectorBootstrap},
        InstalledSelectorState, PositionalReader,
    },
    selector_protocol::execute_request_for_case,
};

use super::super::{HeldImageAdmission, ProviderImageSnapshot};
use super::{
    AdmittedProviderExecution, ConnectionIdentity, ExecutionSource, GrantState,
    PreparedProviderExecution, ProviderExecutionPolicy, RetainedCase, StagingCharge, StagingError,
    StagingLedger,
};

const FRAME_LIMIT: usize = 16 * 1024 * 1024;
const INPUT_LIMIT: u64 = 128 * 1024 * 1024;

fn invalid<T>(_: T) -> StagingError {
    StagingError::InvalidSource
}
fn invalid_input<T>(_: T) -> StagingError {
    StagingError::InvalidInput
}

fn deadline(milliseconds: u64) -> Result<Instant, StagingError> {
    deadline_after(Instant::now(), milliseconds)
}

fn deadline_after(start: Instant, milliseconds: u64) -> Result<Instant, StagingError> {
    if milliseconds == 0 {
        return Err(StagingError::Expired);
    }
    start
        .checked_add(Duration::from_millis(milliseconds))
        .ok_or(StagingError::Expired)
}

fn remaining(until: Instant) -> Result<Duration, StagingError> {
    until
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(StagingError::Expired)
}

struct TransferDeadlines {
    initial: Instant,
    transport: Option<Instant>,
}

impl TransferDeadlines {
    fn new(stream: &UnixStream, control_milliseconds: u64) -> Result<Self, StagingError> {
        deadline(control_milliseconds).and_then(|initial| {
            stream
                .read_timeout()
                .and_then(|read| {
                    stream
                        .write_timeout()
                        .map(|write| read.into_iter().chain(write).min())
                })
                .map_err(StagingError::from)
                .and_then(|timeout| {
                    timeout
                        .map(|timeout| {
                            Instant::now()
                                .checked_add(timeout)
                                .ok_or(StagingError::Expired)
                        })
                        .transpose()
                })
                .map(|transport| Self {
                    initial: transport.map_or(initial, |until| initial.min(until)),
                    transport,
                })
        })
    }

    fn input(&self, spx_completed: Instant, milliseconds: u64) -> Result<Instant, StagingError> {
        deadline_after(spx_completed, milliseconds)
            .map(|input| self.transport.map_or(input, |until| input.min(until)))
    }
}

fn connection(stream: &UnixStream) -> Result<ConnectionIdentity, StagingError> {
    rustix::fs::fstat(stream)
        .map_err(io::Error::from)
        .map_err(StagingError::from)
        .map(|metadata| ConnectionIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        })
}

fn require_grant_turn(stream: &UnixStream) -> Result<(), StagingError> {
    use rustix::net::{recv, RecvFlags};
    match recv(
        stream,
        &mut [0_u8; 1],
        RecvFlags::PEEK | RecvFlags::DONTWAIT,
    ) {
        Err(rustix::io::Errno::AGAIN) => Ok(()),
        Ok(_) => Err(StagingError::InvalidSource),
        Err(error) => Err(StagingError::Io(io::Error::from(error))),
    }
}

struct TimedStream<'a> {
    stream: &'a mut UnixStream,
    until: Instant,
}

impl Read for TimedStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        remaining(self.until)
            .map_err(io::Error::other)
            .and_then(|left| {
                self.stream
                    .set_read_timeout(Some(left))
                    .and_then(|()| self.stream.read(bytes))
            })
    }
}

impl Write for TimedStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        remaining(self.until)
            .map_err(io::Error::other)
            .and_then(|left| {
                self.stream
                    .set_write_timeout(Some(left))
                    .and_then(|()| self.stream.write(bytes))
            })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Debug)]
pub(super) struct RetainedControl {
    bytes: Vec<u8>,
    // Drop the buffer before releasing its shared byte reservation.
    _charge: StagingCharge,
}

fn frame(reader: &mut impl Read, ledger: &StagingLedger) -> Result<RetainedControl, StagingError> {
    let mut prefix = [0; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(StagingError::from)
        .and_then(|()| usize::try_from(u32::from_be_bytes(prefix)).map_err(invalid))
        .and_then(|length| {
            if length == 0 || length > FRAME_LIMIT {
                return Err(StagingError::InvalidSource);
            }
            ledger
                .reserve_storage(length as u64)
                .map(|charge| RetainedControl {
                    bytes: vec![0; length],
                    _charge: charge,
                })
        })
        .and_then(|mut record| {
            reader
                .read_exact(&mut record.bytes)
                .map_err(StagingError::from)
                .map(|()| record)
        })
}

fn installed_provider() -> Result<AdmittedSelectorProvider, StagingError> {
    InstalledSelectorState::open()
        .and_then(InstalledSelectorState::authenticate_bootstrap)
        .and_then(AuthenticatedSelectorBootstrap::admit_provider)
        .map_err(StagingError::from)
}

pub(super) fn receive(
    stream: &mut UnixStream,
    ledger: &StagingLedger,
) -> Result<PreparedProviderExecution, StagingError> {
    if rustix::net::sockopt::socket_peercred(stream.as_fd())
        .map_err(io::Error::from)?
        .uid
        .as_raw()
        != 0
    {
        return Err(StagingError::UnauthenticatedPeer);
    }
    let identity = connection(stream)?;
    let admitted = installed_provider()?;
    let bhc = admitted.provider().broker_hard_caps();
    let deadlines = TransferDeadlines::new(stream, bhc[16].value)?;
    let initial_deadline = deadlines.initial;
    let control = ledger.control(bhc[13].value)?;
    let mut reader = TimedStream {
        stream,
        until: initial_deadline,
    };
    let evaluation_record = frame(&mut reader, ledger)?;
    let evaluation =
        EvaluationRequest::from_canonical_cbor(&evaluation_record.bytes).map_err(invalid)?;
    let request_record = frame(&mut reader, ledger)?;
    let spx_completed = Instant::now();
    let request =
        SandboxExecuteRequest::from_canonical_cbor(&request_record.bytes).map_err(invalid)?;
    require_grant_turn(reader.stream)?;
    let ordinal = u16::from_be_bytes([
        request.request.request_id[14],
        request.request.request_id[15],
    ]);
    let resolved = admitted
        .bootstrap()
        .resolve_installed_case(&evaluation, ordinal)?;
    let input = input_descriptor(resolved.attempt())?;
    let case_bytes = case_buffer_bytes(resolved.attempt());
    let expected = execute_request_for_case(
        &admitted,
        &evaluation,
        &resolved,
        input,
        ordinal,
        request.request.nonce,
    )
    .map_err(StagingError::from)
    .and_then(|expected_request| {
        if expected_request != request {
            return Err(StagingError::InvalidSource);
        }
        ledger
            .reserve_storage(case_bytes)
            .map(|charge| RetainedCase {
                attempt: resolved.into_attempt(),
                _charge: charge,
            })
    })?;
    let snapshot = ProviderImageSnapshot::from_admitted(admitted, request, SystemTime::now)?;
    let commitment = snapshot
        .admitted
        .provider()
        .derive_selector_grant_commitment(
            snapshot.image(),
            snapshot.launch_policy(),
            &evaluation,
            &expected.attempt,
            &[],
        )
        .map_err(invalid)?;
    let policy = ProviderExecutionPolicy {
        request_digest: snapshot.request().request_digest,
        input: snapshot.request().adapter_input.clone(),
        commitment,
    };
    let authority = snapshot.admit_held_image()?.authority();
    remaining(initial_deadline)?;
    let input_deadline = deadlines.input(spx_completed, policy.limit(16))?;
    remaining(input_deadline)?;
    require_grant_turn(reader.stream)?;
    let (slot, input) = ledger.prepare(authority, &policy)?;
    drop(control);
    Ok(PreparedProviderExecution {
        source: Arc::new(ExecutionSource {
            snapshot,
            expected,
            policy,
            _records: [evaluation_record, request_record],
        }),
        slot,
        input,
        ledger: ledger.clone(),
        connection: identity,
        initial_deadline,
        input_deadline,
        grant: GrantState::Prepared,
    })
}

struct DigestWriter {
    hasher: blake3::Hasher,
    length: u64,
}

// Called only after the bounded canonical writer validated the complete case;
// its buffers are strictly smaller than that at-most-128-MiB representation.
fn case_buffer_bytes(attempt: &crate::evaluator::CaseAttempt) -> u64 {
    attempt.case_id.len() as u64
        + attempt.schema.bytes.len() as u64
        + attempt.payload.bytes.len() as u64
        + attempt
            .auxiliary
            .iter()
            .map(|artifact| artifact.bytes.len() as u64)
            .sum::<u64>()
        + attempt
            .capability_ids
            .iter()
            .map(|id| id.len() as u64)
            .sum::<u64>()
}

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .length
            .checked_add(bytes.len() as u64)
            .filter(|length| *length <= INPUT_LIMIT)
            .ok_or_else(|| io::Error::other("input exceeds protocol ceiling"))?;
        self.hasher.update(bytes);
        self.length = length;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn input_descriptor(
    expected: &crate::evaluator::CaseAttempt,
) -> Result<PayloadDescriptor, StagingError> {
    let mut writer = DigestWriter {
        hasher: blake3::Hasher::new(),
        length: 0,
    };
    writer.hasher.update(b"PiglorOS.SandboxInputBytes.v1\0");
    write_attempt(&mut writer, expected)
        .map_err(invalid)
        .map(|()| PayloadDescriptor {
            byte_length: writer.length,
            digest: *writer.hasher.finalize().as_bytes(),
        })
}

impl PreparedProviderExecution {
    /// Independently derived policy; no caller can replace its values.
    #[must_use]
    pub fn policy(&self) -> &ProviderExecutionPolicy {
        &self.source.policy
    }

    /// Canonical source identity for this exchange.
    #[must_use]
    pub fn request(&self) -> &SandboxExecuteRequest {
        self.source.snapshot.request()
    }

    /// Shared byte ownership for the private staging file's unlink lifetime.
    #[must_use]
    pub fn staging_charge(&self) -> StagingCharge {
        self.input.clone()
    }

    fn check_connection(&self, stream: &UnixStream) -> Result<(), StagingError> {
        connection(stream).and_then(|identity| {
            if identity == self.connection {
                Ok(())
            } else {
                Err(StagingError::ConnectionChanged)
            }
        })
    }

    /// Sign and send AGR1 solely from this policy on its original connection.
    ///
    /// # Errors
    /// Refuses reuse, expiry, authority changes, a foreign connection or key.
    /// A partially written grant consumes this exchange; it cannot be retried.
    pub fn send_grant(
        &mut self,
        stream: &mut UnixStream,
        sign: impl FnOnce(&[u8]) -> Result<[u8; 64], io::Error>,
    ) -> Result<(), StagingError> {
        if self.grant != GrantState::Prepared {
            return Err(StagingError::GrantAlreadyIssued);
        }
        self.check_connection(stream)?;
        remaining(self.initial_deadline)?;
        let snapshot = &self.source.snapshot;
        let authority = snapshot.admit_held_image()?.authority();
        self.slot.recheck(authority)?;
        let request = snapshot.request();
        let a = &request.authority;
        let grant = AdmissionGrant {
            request_id: request.request.request_id,
            attempt_id: request.attempt_id,
            authority: AdmissionAuthority {
                evr1_digest: a.evr1_digest,
                fixture_contract_digest: a.fixture_contract_digest,
                fixture_digest: a.fixture_digest,
                execution_profile_digest: a.execution_profile_digest,
                lps1_digest: a.lps1_digest,
                sim1_digest: a.sim1_digest,
                apt1_digest: a.apt1_digest,
                trs1_digest: a.trs1_digest,
                rvs1_digest: a.rvs1_digest,
                spm1_digest: a.spm1_digest,
                pcf1_digest: a.pcf1_digest,
                pcr1_digest: a.pcr1_digest,
                hcp1_digest: a.hcp1_digest,
            },
            trust_epoch: authority.trust_epoch,
            revocation_epoch: authority.revocation_epoch,
            policy_epoch: authority.policy_epoch,
            elm1_digest: self.policy().effective_limits_digest(),
            input_digest: self.policy().input.digest,
            exchange_plan_digests: Vec::new(),
            expected_launch_policy_digest: a.lps1_digest,
            expected_readback_set_digest: self.policy().expected_readback_digest(),
            runtime_attestation_key_id: snapshot.runtime_attestation_key_id().to_owned(),
            grant_digest: [0; 32],
            signature: [0; 64],
        }
        .sign_and_encode(sign)
        .map_err(|_| StagingError::InvalidSignature)?;
        snapshot
            .admitted
            .provider()
            .authenticate_grant(
                &grant,
                request,
                snapshot.image(),
                snapshot.launch_policy(),
                &self.policy().commitment,
            )
            .map_err(|_| StagingError::InvalidSignature)?;
        let length = u32::try_from(grant.len()).map_err(invalid)?;
        // A supplied signer may block while installation or the floor changes.
        snapshot
            .admit_held_image()
            .map_err(StagingError::from)
            .and_then(|image| self.slot.recheck(image.authority()))
            .and_then(|()| remaining(self.initial_deadline))
            .and_then(|_| remaining(self.input_deadline))
            .and_then(|_| require_grant_turn(stream))
            .and_then(|()| {
                // Grant output starts here. Later peer bytes can only be input;
                // they cannot reopen the independently validated source records.
                self.grant = GrantState::Writing;
                let mut writer = TimedStream {
                    stream,
                    until: self.initial_deadline.min(self.input_deadline),
                };
                writer
                    .write_all(&length.to_be_bytes())
                    .and_then(|()| writer.write_all(&grant))
                    .map_err(StagingError::from)
                    .and_then(|()| remaining(self.initial_deadline.min(self.input_deadline)))
                    .map(|_| self.grant = GrantState::Granted)
            })
    }

    /// Receive and verify complete SBC1/EAI1 into the retained private file.
    ///
    /// # Errors
    /// Refuses a missing grant, foreign connection, timeout, invalid framing,
    /// descriptor/case mismatch, extra input or a changed installed authority.
    pub(super) fn receive_input(
        self,
        stream: &mut UnixStream,
        file: &File,
    ) -> Result<AdmittedProviderExecution, StagingError> {
        if self.grant != GrantState::Granted {
            return Err(StagingError::GrantRequired);
        }
        self.check_connection(stream)?;
        let request = self.request();
        let mut validator = PayloadStreamValidator::new(
            request.request_digest,
            request.request.request_id,
            request.attempt_id,
            PayloadDirection::Input,
            self.policy().input.clone(),
        )
        .map_err(invalid_input)?;
        let mut reader = TimedStream {
            stream,
            until: self.input_deadline,
        };
        let mut offset = 0;
        while offset < self.policy().input.byte_length {
            let record = frame(&mut reader, &self.ledger)?;
            let chunk =
                SandboxPayloadChunk::from_canonical_cbor(&record.bytes).map_err(invalid_input)?;
            validator.accept(&chunk).map_err(invalid_input)?;
            file.write_all_at(&chunk.bytes, offset)?;
            offset += chunk.bytes.len() as u64;
            drop(record);
        }
        validator.finish().map_err(invalid_input)?;
        if reader.read(&mut [0; 1])? != 0 || file.metadata()?.len() != offset {
            return Err(StagingError::InvalidInput);
        }
        let _decoded_input = self
            .ledger
            .reserve_storage(case_buffer_bytes(&self.source.expected.attempt))?;
        let actual = read_attempt(PositionalReader::new(file)).map_err(invalid_input)?;
        if actual != self.source.expected.attempt {
            return Err(StagingError::InvalidInput);
        }
        remaining(self.input_deadline)?;
        let (root_image, proof, authority) = {
            let image = self.source.snapshot.admit_held_image()?;
            self.slot.recheck(image.authority())?;
            (
                image.root_image.try_clone()?,
                Arc::clone(&image.proof),
                image.authority(),
            )
        };
        let verified_input = file.try_clone()?;
        self.input.finish_input();
        Ok(AdmittedProviderExecution {
            source: self.source,
            slot: self.slot,
            _input: self.input,
            verified_input,
            root_image,
            proof,
            authority,
        })
    }
}

impl AdmittedProviderExecution {
    /// Exact independently reconstructed policy bound to these input bytes.
    #[must_use]
    pub fn policy(&self) -> &ProviderExecutionPolicy {
        &self.source.policy
    }

    /// Descriptor-bearing image admission retained from this input's context.
    #[must_use]
    pub fn image_admission(&self) -> HeldImageAdmission<'_> {
        HeldImageAdmission {
            snapshot: &self.source.snapshot,
            root_image: &self.root_image,
            proof: self.proof.clone(),
            authority: self.authority,
        }
    }

    /// Recheck current installation and the live provider control floor.
    ///
    /// # Errors
    /// Refuses stale or substituted authority and raised control floors.
    pub fn recheck(&self) -> Result<super::super::AdmittedAuthority, StagingError> {
        self.image_admission()
            .recheck_authority()
            .map_err(|_| StagingError::AuthorityChanged)
            .and_then(|authority| self.slot.recheck(authority).map(|()| authority))
    }

    /// Read exactly from the descriptor whose complete case was verified.
    ///
    /// # Errors
    /// Returns an I/O error for an invalid range or descriptor read failure.
    pub fn read_exact_at(&self, bytes: &mut [u8], offset: u64) -> io::Result<()> {
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.policy().input.byte_length)
        {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        self.verified_input.read_exact_at(bytes, offset)
    }

    /// Keep this attempt counted while staging one bounded terminal output.
    ///
    /// # Errors
    /// Refuses a second output, ID-8 violation or aggregate byte overflow.
    pub fn reserve_output(&self, bytes: u64) -> Result<StagingCharge, StagingError> {
        self.slot.output(self.policy(), bytes)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::evaluator_protocol::encode;
    use crate::provider_admission::test_support::StagedInstallation;
    use ciborium::value::Value;
    use std::io::Cursor;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn frames_validate_lengths_and_charge_before_allocating() -> TestResult {
        let ledger = StagingLedger::new(super::super::StagingLimits { aggregate_bytes: 3 });
        for length in [0, u32::MAX] {
            assert!(matches!(
                frame(&mut Cursor::new(length.to_be_bytes()), &ledger),
                Err(StagingError::InvalidSource)
            ));
        }
        assert!(matches!(
            frame(&mut Cursor::new(4_u32.to_be_bytes()), &ledger),
            Err(StagingError::AggregateExceeded)
        ));
        assert!(frame(&mut Cursor::new([0, 0, 0, 3, 1]), &ledger).is_err());
        assert_eq!(ledger.usage().reserved_bytes, 0);
        let record = frame(&mut Cursor::new([0, 0, 0, 3, 1, 2, 3]), &ledger)?;
        assert_eq!(record.bytes, [1, 2, 3]);
        assert_eq!(ledger.usage().reserved_bytes, 3);
        drop(record);
        assert_eq!(ledger.usage().reserved_bytes, 0);
        Ok(())
    }

    #[test]
    fn maximum_control_frame_is_admissible_without_enclosing_overhead() -> TestResult {
        let ledger = StagingLedger::new(super::super::StagingLimits {
            aggregate_bytes: FRAME_LIMIT as u64,
        });
        let mut bytes = u32::try_from(FRAME_LIMIT)?.to_be_bytes().to_vec();
        bytes.resize(FRAME_LIMIT + 4, 1);
        let record = frame(&mut Cursor::new(bytes), &ledger)?;
        assert_eq!(record.bytes.len(), FRAME_LIMIT);
        drop(record);
        assert_eq!(ledger.usage().reserved_bytes, 0);
        Ok(())
    }

    #[test]
    fn timed_reads_and_writes_keep_the_original_absolute_deadline() -> TestResult {
        assert!(matches!(deadline(0), Err(StagingError::Expired)));
        let expired = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("clock range")?;
        assert!(matches!(remaining(expired), Err(StagingError::Expired)));
        let (mut first, mut second) = UnixStream::pair()?;
        let mut timed = TimedStream {
            stream: &mut first,
            until: deadline(5_000)?,
        };
        timed.write_all(b"ab")?;
        timed.flush()?;
        let mut bytes = [0; 2];
        second.read_exact(&mut bytes)?;
        assert_eq!(bytes, *b"ab");
        second.write_all(b"cd")?;
        timed.read_exact(&mut bytes)?;
        assert_eq!(bytes, *b"cd");
        timed.until = expired;
        assert!(timed.read(&mut bytes).is_err());
        assert!(timed.write(b"e").is_err());
        assert_eq!(connection(&first)?, connection(&first.try_clone()?)?);
        assert_ne!(connection(&first)?, connection(&second)?);
        Ok(())
    }

    #[test]
    fn source_and_input_preserve_stricter_original_transport_bounds() -> TestResult {
        let (stream, _peer) = UnixStream::pair()?;
        let unrestricted = TransferDeadlines::new(&stream, 10_000)?;
        assert!(unrestricted.transport.is_none());
        assert!(unrestricted.input(Instant::now(), 1_000)? < unrestricted.initial);
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        stream.set_write_timeout(Some(Duration::from_millis(50)))?;
        let strict = TransferDeadlines::new(&stream, 10_000)?;
        let original = strict.transport.ok_or("missing original transport bound")?;
        assert_eq!(strict.initial, original);
        assert_eq!(strict.input(Instant::now(), 10_000)?, original);
        assert!(strict.input(Instant::now(), 1)? < original);
        assert!(TransferDeadlines::new(&stream, 0).is_err());
        assert!(strict.input(Instant::now(), 0).is_err());
        let spx_completed = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .ok_or("clock range")?;
        assert!(matches!(
            remaining(unrestricted.input(spx_completed, 1_000)?),
            Err(StagingError::Expired)
        ));
        Ok(())
    }

    #[test]
    fn source_turn_rejects_queued_extra_bytes_and_early_eof_without_consuming() -> TestResult {
        let (mut provider, mut selector) = UnixStream::pair()?;
        require_grant_turn(&provider)?;
        selector.write_all(b"x")?;
        assert!(matches!(
            require_grant_turn(&provider),
            Err(StagingError::InvalidSource)
        ));
        let mut byte = [0];
        provider.read_exact(&mut byte)?;
        assert_eq!(byte, *b"x");
        selector.shutdown(std::net::Shutdown::Write)?;
        assert!(matches!(
            require_grant_turn(&provider),
            Err(StagingError::InvalidSource)
        ));
        Ok(())
    }

    #[test]
    fn incremental_descriptor_matches_the_canonical_complete_case() -> TestResult {
        let (_, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let descriptor = input_descriptor(resolved.attempt())?;
        let mut bytes = Vec::new();
        write_attempt(&mut bytes, resolved.attempt())?;
        assert_eq!(descriptor.byte_length, bytes.len() as u64);
        let mut hash = blake3::Hasher::new();
        hash.update(b"PiglorOS.SandboxInputBytes.v1\0");
        hash.update(&bytes);
        assert_eq!(descriptor.digest, *hash.finalize().as_bytes());
        let mut changed = resolved.into_attempt();
        changed.watchdog_ms += 1;
        assert_ne!(descriptor, input_descriptor(&changed)?);
        let retained = case_buffer_bytes(&changed);
        let extra = b"aux";
        changed.auxiliary.push(crate::evaluator::AttemptArtifact {
            digest: *blake3::hash(extra).as_bytes(),
            bytes: extra.to_vec(),
        });
        assert_eq!(case_buffer_bytes(&changed), retained + 3);
        assert!(case_buffer_bytes(&changed) < input_descriptor(&changed)?.byte_length);
        let mut bounded = DigestWriter {
            hasher: blake3::Hasher::new(),
            length: INPUT_LIMIT,
        };
        assert!(bounded.write(b"x").is_err());
        bounded.length = u64::MAX;
        assert!(bounded.write(b"x").is_err());
        assert!(matches!(invalid(()), StagingError::InvalidSource));
        assert!(matches!(invalid_input(()), StagingError::InvalidInput));
        changed.watchdog_ms = 0;
        assert!(matches!(
            input_descriptor(&changed),
            Err(StagingError::InvalidSource)
        ));
        Ok(())
    }

    #[test]
    fn a_non_root_peer_is_refused_before_installation_or_source_reads() -> TestResult {
        if rustix::process::geteuid().as_raw() == 0 {
            return Ok(());
        }
        let (mut stream, _peer) = UnixStream::pair()?;
        let ledger = StagingLedger::new(super::super::StagingLimits { aggregate_bytes: 0 });
        assert!(matches!(
            PreparedProviderExecution::receive(&mut stream, &ledger),
            Err(StagingError::UnauthenticatedPeer)
        ));
        assert_eq!(ledger.usage(), super::super::StagingUsage::default());
        Ok(())
    }

    fn isolated(test: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
            assert_eq!(rustix::process::geteuid().as_raw(), 0);
            return Ok(true);
        }
        let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/run-isolated-test.sh");
        let output = std::process::Command::new(runner)
            .arg(std::env::current_exe()?)
            .arg(format!(
                "provider_admission::execution::source::tests::{test}"
            ))
            .output()?;
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(false)
    }

    fn prepared_pair(
        staged: &StagedInstallation,
        ledger: &StagingLedger,
    ) -> Result<(PreparedProviderExecution, UnixStream, UnixStream), Box<dyn std::error::Error>>
    {
        let (mut provider, mut selector) = UnixStream::pair()?;
        staged.write_source(&mut selector)?;
        let prepared = PreparedProviderExecution::receive(&mut provider, ledger)?;
        Ok((prepared, provider, selector))
    }

    fn send_grant(prepared: &mut PreparedProviderExecution, stream: &mut UnixStream) -> TestResult {
        prepared.send_grant(stream, |message| {
            Ok(StagedInstallation::sign_grant(message))
        })?;
        Ok(())
    }

    // A separate wire oracle deliberately does not call the validator under test.
    fn write_chunk(
        staged: &StagedInstallation,
        selector: &mut UnixStream,
        payload: &[u8],
        parent: [u8; 32],
    ) -> TestResult {
        let request = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        let unsigned = Value::Array(vec![
            Value::Text("SBC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(parent.to_vec()),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
            Value::Integer(0.into()),
            Value::Integer(0.into()),
            Value::Integer(0.into()),
            Value::Bytes(payload.to_vec()),
        ]);
        let mut hash = blake3::Hasher::new();
        hash.update(b"PiglorOS.SBC1.v1\0");
        hash.update(&encode(&unsigned)?);
        let bytes = encode(&Value::Array(vec![
            unsigned,
            Value::Bytes(hash.finalize().as_bytes().to_vec()),
        ]))?;
        selector.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
        selector.write_all(&bytes)?;
        selector.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    #[test]
    fn peer_reset_is_reported_before_grant_output_and_failed_writes_consume_the_grant() -> TestResult
    {
        if !isolated(
            "peer_reset_is_reported_before_grant_output_and_failed_writes_consume_the_grant",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let ledger = StagingLedger::new(super::super::StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        });
        let (mut prepared, mut provider, selector) = prepared_pair(&staged, &ledger)?;
        let mut outgoing = provider.try_clone()?;
        let result = prepared.send_grant(&mut provider, |message| {
            outgoing.write_all(b"unread")?;
            drop(selector);
            Ok(StagedInstallation::sign_grant(message))
        });
        assert!(
            matches!(result, Err(StagingError::Io(error)) if error.kind() == io::ErrorKind::ConnectionReset)
        );
        drop((prepared, provider, outgoing));
        assert_eq!(ledger.usage(), super::super::StagingUsage::default());

        let (mut prepared, mut provider, selector) = prepared_pair(&staged, &ledger)?;
        selector.shutdown(std::net::Shutdown::Read)?;
        assert!(
            matches!(send_grant(&mut prepared, &mut provider), Err(error) if error.downcast_ref::<StagingError>().is_some_and(|error| matches!(error, StagingError::Io(_))))
        );
        assert!(matches!(
            prepared.send_grant(&mut provider, |message| Ok(StagedInstallation::sign_grant(
                message
            ))),
            Err(StagingError::GrantAlreadyIssued)
        ));
        drop((prepared, provider, selector));
        assert_eq!(ledger.usage(), super::super::StagingUsage::default());
        Ok(())
    }

    #[test]
    fn verified_chunk_identity_digest_and_private_storage_fail_closed() -> TestResult {
        if !isolated("verified_chunk_identity_digest_and_private_storage_fail_closed")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        for fault in [
            "parent",
            "digest",
            "read-only",
            "overlong",
            "floor",
            "installation",
        ] {
            let ledger = StagingLedger::new(super::super::StagingLimits {
                aggregate_bytes: 512 * 1024 * 1024,
            });
            let (mut prepared, mut provider, mut selector) = prepared_pair(&staged, &ledger)?;
            send_grant(&mut prepared, &mut provider)?;
            let temporary = tempfile::NamedTempFile::new()?;
            let file = if fault == "read-only" {
                File::open(temporary.path())?
            } else {
                temporary.reopen()?
            };
            if fault == "overlong" {
                file.set_len(staged.input().len() as u64 + 1)?;
            }
            let mut payload = staged.input().to_vec();
            if fault == "digest" {
                payload[0] ^= 1;
            }
            let parent = if fault == "parent" {
                [0x71; 32]
            } else {
                prepared.request().request_digest
            };
            write_chunk(&staged, &mut selector, &payload, parent)?;
            if fault == "floor" {
                ledger.raise_floor(super::super::ControlFloor {
                    revocation_epoch: u64::MAX,
                    policy_epoch: u64::MAX,
                });
            }
            let manifest =
                std::path::Path::new(crate::selector::installation::SANDBOX_ARTIFACT_ROOT)
                    .join(crate::selector::installation::MANIFEST_NAME);
            let saved = if fault == "installation" {
                let bytes = std::fs::read(&manifest)?;
                std::fs::remove_file(&manifest)?;
                Some(bytes)
            } else {
                None
            };
            let result = prepared.receive_input(&mut provider, &file);
            if let Some(bytes) = saved {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::write(&manifest, bytes)?;
                std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o400))?;
            }
            assert!(
                match fault {
                    "read-only" => matches!(result, Err(StagingError::Io(_))),
                    "floor" => matches!(result, Err(StagingError::BelowControlFloor)),
                    "installation" => matches!(result, Err(StagingError::Source(_))),
                    _ => matches!(result, Err(StagingError::InvalidInput)),
                },
                "{fault}: {result:?}"
            );
            assert_eq!(ledger.usage().attempts, 0);
            assert_eq!(ledger.usage().reserved_bytes, 0);
        }
        Ok(())
    }

    #[test]
    fn independent_eai_decode_and_case_comparison_survive_crossed_private_facts() -> TestResult {
        if !isolated("independent_eai_decode_and_case_comparison_survive_crossed_private_facts")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        for fault in ["decode", "case", "decoded-budget"] {
            let ledger = StagingLedger::new(super::super::StagingLimits {
                aggregate_bytes: 1024 * 1024,
            });
            let (mut prepared, mut provider, mut selector) = prepared_pair(&staged, &ledger)?;
            send_grant(&mut prepared, &mut provider)?;
            let parent = prepared.request().request_digest;
            let mut payload = staged.input().to_vec();
            // These are impossible-state faults after the real authenticated
            // factory, scoped to private test access. They prove the final
            // decoder/comparison/reservation guards independently of the
            // already verified source descriptor, with no production bypass.
            let source = Arc::get_mut(&mut prepared.source).ok_or("shared fixture source")?;
            match fault {
                "decode" => {
                    payload.fill(0);
                    let mut hash = blake3::Hasher::new();
                    hash.update(b"PiglorOS.SandboxInputBytes.v1\0");
                    hash.update(&payload);
                    source.policy.input.digest = *hash.finalize().as_bytes();
                }
                "case" => source.expected.attempt.watchdog_ms += 1,
                _ => source.expected.attempt.schema.bytes.resize(1024 * 1024, 0),
            }
            write_chunk(&staged, &mut selector, &payload, parent)?;
            let file = tempfile::tempfile()?;
            let result = prepared.receive_input(&mut provider, &file);
            assert!(
                match fault {
                    "decoded-budget" => matches!(result, Err(StagingError::AggregateExceeded)),
                    _ => matches!(result, Err(StagingError::InvalidInput)),
                },
                "{fault}: {result:?}"
            );
            assert_eq!(ledger.usage(), super::super::StagingUsage::default());
        }
        Ok(())
    }

    #[test]
    fn prepared_deadlines_are_not_restarted_by_signing_and_authority_is_rechecked() -> TestResult {
        if !isolated("prepared_deadlines_are_not_restarted_by_signing_and_authority_is_rechecked")?
        {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        for fault in ["initial", "input", "floor", "installation"] {
            let ledger = StagingLedger::new(super::super::StagingLimits {
                aggregate_bytes: 512 * 1024 * 1024,
            });
            let (mut prepared, mut provider, mut selector) = prepared_pair(&staged, &ledger)?;
            let expired = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .ok_or("clock range")?;
            // Set only private clocks; no sleeps, clock reset, or alternate
            // admission constructor is introduced into the production path.
            if fault == "initial" {
                prepared.initial_deadline = expired;
            }
            if fault == "floor" {
                ledger.raise_floor(super::super::ControlFloor {
                    revocation_epoch: u64::MAX,
                    policy_epoch: u64::MAX,
                });
            }
            let manifest =
                std::path::Path::new(crate::selector::installation::SANDBOX_ARTIFACT_ROOT)
                    .join(crate::selector::installation::MANIFEST_NAME);
            let saved = if fault == "installation" {
                let bytes = std::fs::read(&manifest)?;
                std::fs::remove_file(&manifest)?;
                Some(bytes)
            } else {
                None
            };
            if fault == "input" {
                prepared.input_deadline = expired;
            }
            let result = prepared.send_grant(&mut provider, |message| {
                Ok(StagedInstallation::sign_grant(message))
            });
            if let Some(bytes) = saved {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::write(&manifest, bytes)?;
                std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o400))?;
            }
            assert!(
                match fault {
                    "floor" => matches!(result, Err(StagingError::BelowControlFloor)),
                    "installation" => matches!(result, Err(StagingError::Source(_))),
                    _ => matches!(result, Err(StagingError::Expired)),
                },
                "{fault}: {result:?}"
            );
            drop((prepared, provider));
            assert_eq!(selector.read(&mut [0])?, 0);
            assert_eq!(ledger.usage().attempts, 0);
            assert_eq!(ledger.usage().reserved_bytes, 0);
        }
        Ok(())
    }

    #[test]
    fn source_failure_releases_control_and_reconstructed_case_reservations() -> TestResult {
        if !isolated("source_failure_releases_control_and_reconstructed_case_reservations")? {
            return Ok(());
        }
        let ledger = StagingLedger::new(super::super::StagingLimits {
            aggregate_bytes: 512 * 1024 * 1024,
        });
        let (mut provider, _selector) = UnixStream::pair()?;
        assert!(matches!(
            PreparedProviderExecution::receive(&mut provider, &ledger),
            Err(StagingError::Source(_))
        ));
        assert_eq!(ledger.usage(), super::super::StagingUsage::default());
        let staged = StagedInstallation::stage_execution()?;
        let controls = (0..256)
            .map(|_| ledger.control(256))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            matches!(prepared_pair(&staged, &ledger), Err(error) if error.downcast_ref::<StagingError>().is_some_and(|error| matches!(error, StagingError::ControlSlotsExhausted)))
        );
        drop(controls);
        assert_eq!(ledger.usage(), super::super::StagingUsage::default());
        let case = read_attempt(staged.input())?;
        let source_bytes = staged.evaluation().len() as u64 + staged.request().len() as u64;
        let short = StagingLedger::new(super::super::StagingLimits {
            aggregate_bytes: source_bytes + case_buffer_bytes(&case) - 1,
        });
        assert!(
            matches!(prepared_pair(&staged, &short), Err(error) if error.downcast_ref::<StagingError>().is_some_and(|error| matches!(error, StagingError::AggregateExceeded)))
        );
        assert_eq!(short.usage(), super::super::StagingUsage::default());
        let request = staged.changed_request(|request| {
            request.request.request_id[14..].copy_from_slice(&u16::MAX.to_be_bytes());
            request.attempt_id[14..].copy_from_slice(&0x7fff_u16.to_be_bytes());
        })?;
        let (mut provider, mut selector) = UnixStream::pair()?;
        for record in [staged.evaluation(), request.as_slice()] {
            selector.write_all(&u32::try_from(record.len())?.to_be_bytes())?;
            selector.write_all(record)?;
        }
        assert!(matches!(
            PreparedProviderExecution::receive(&mut provider, &ledger),
            Err(StagingError::Source(_))
        ));
        assert_eq!(ledger.usage(), super::super::StagingUsage::default());
        Ok(())
    }
}
