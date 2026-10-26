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
    selector::installation::{InstallationObjectKind, InstalledSelectorState, PositionalReader},
    selector_protocol::execute_request_for_case,
};

use super::super::{HeldImageAdmission, ProviderImageSnapshot};
use super::{
    AdmittedProviderExecution, ConnectionIdentity, ExecutionSource, GrantState,
    PreparedProviderExecution, ProviderExecutionPolicy, StagingCharge, StagingError, StagingLedger,
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
        let initial = deadline(control_milliseconds)?;
        let timeout = stream
            .read_timeout()?
            .into_iter()
            .chain(stream.write_timeout()?)
            .min();
        let transport = timeout
            .map(|timeout| {
                Instant::now()
                    .checked_add(timeout)
                    .ok_or(StagingError::Expired)
            })
            .transpose()?;
        Ok(Self {
            initial: transport.map_or(initial, |until| initial.min(until)),
            transport,
        })
    }

    fn input(&self, spx_completed: Instant, milliseconds: u64) -> Result<Instant, StagingError> {
        let input = deadline_after(spx_completed, milliseconds)?;
        Ok(self.transport.map_or(input, |until| input.min(until)))
    }
}

fn connection(stream: &UnixStream) -> Result<ConnectionIdentity, StagingError> {
    let metadata = rustix::fs::fstat(stream).map_err(io::Error::from)?;
    Ok(ConnectionIdentity {
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
        let left = remaining(self.until).map_err(io::Error::other)?;
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(bytes)
    }
}

impl Write for TimedStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let left = remaining(self.until).map_err(io::Error::other)?;
        self.stream.set_write_timeout(Some(left))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn frame(
    reader: &mut impl Read,
    ledger: &StagingLedger,
) -> Result<(Vec<u8>, StagingCharge), StagingError> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(invalid)?;
    if length == 0 || length > FRAME_LIMIT {
        return Err(StagingError::InvalidSource);
    }
    let charge = ledger.reserve_storage(length as u64)?;
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok((bytes, charge))
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
    let admitted = InstalledSelectorState::open()?
        .authenticate_bootstrap()?
        .admit_provider()?;
    let bhc = admitted.provider().broker_hard_caps();
    let deadlines = TransferDeadlines::new(stream, bhc[16].value)?;
    let initial_deadline = deadlines.initial;
    let control = ledger.control(bhc[13].value)?;
    let mut reader = TimedStream {
        stream,
        until: initial_deadline,
    };
    let (evaluation_bytes, evaluation_charge) = frame(&mut reader, ledger)?;
    let evaluation = EvaluationRequest::from_canonical_cbor(&evaluation_bytes).map_err(invalid)?;
    let (request_bytes, request_charge) = frame(&mut reader, ledger)?;
    let spx_completed = Instant::now();
    let request = SandboxExecuteRequest::from_canonical_cbor(&request_bytes).map_err(invalid)?;
    require_grant_turn(reader.stream)?;
    let ordinal = u16::from_be_bytes([
        request.request.request_id[14],
        request.request.request_id[15],
    ]);
    // Reserve retained source closure before reconstruction materializes it.
    let installed = admitted.bootstrap().installed();
    let mut source_charges = vec![evaluation_charge, request_charge];
    for (code, digest) in [
        (14, evaluation.fixture_bundle_digest),
        (15, evaluation.trust_policy_snapshot_digest),
    ] {
        let kind = InstallationObjectKind::from_code(code).map_err(invalid)?;
        source_charges.push(
            ledger.reserve_storage(installed.artifact(kind, digest)?.object().byte_length())?,
        );
    }
    let resolved = admitted
        .bootstrap()
        .resolve_installed_case(&evaluation, ordinal)?;
    let input = input_descriptor(resolved.attempt())?;
    source_charges.push(ledger.reserve_storage(input.byte_length)?);
    let expected_request = execute_request_for_case(
        &admitted,
        &evaluation,
        &resolved,
        input,
        ordinal,
        request.request.nonce,
    )?;
    if expected_request != request {
        return Err(StagingError::InvalidSource);
    }
    let expected = resolved.into_attempt();
    let snapshot = ProviderImageSnapshot::from_admitted(admitted, request, SystemTime::now)?;
    let commitment = snapshot
        .admitted
        .provider()
        .derive_selector_grant_commitment(
            snapshot.image(),
            snapshot.launch_policy(),
            &evaluation,
            &expected,
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
            _source_charges: source_charges,
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
    write_attempt(&mut writer, expected).map_err(invalid)?;
    Ok(PayloadDescriptor {
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
        if connection(stream)? != self.connection {
            return Err(StagingError::ConnectionChanged);
        }
        Ok(())
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
        self.slot
            .recheck(snapshot.admit_held_image()?.authority())?;
        remaining(self.initial_deadline)?;
        remaining(self.input_deadline)?;
        require_grant_turn(stream)?;
        self.grant = GrantState::Writing;
        let mut writer = TimedStream {
            stream,
            until: self.initial_deadline.min(self.input_deadline),
        };
        writer.write_all(&length.to_be_bytes())?;
        writer.write_all(&grant)?;
        remaining(self.initial_deadline.min(self.input_deadline))?;
        self.grant = GrantState::Granted;
        Ok(())
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
            let (bytes, charge) = frame(&mut reader, &self.ledger)?;
            let chunk = SandboxPayloadChunk::from_canonical_cbor(&bytes).map_err(invalid_input)?;
            validator.accept(&chunk).map_err(invalid_input)?;
            file.write_all_at(&chunk.bytes, offset)?;
            offset += chunk.bytes.len() as u64;
            drop(charge);
        }
        validator.finish().map_err(invalid_input)?;
        if reader.read(&mut [0; 1])? != 0 || file.metadata()?.len() != offset {
            return Err(StagingError::InvalidInput);
        }
        let _decoded_input = self
            .ledger
            .reserve_storage(self.policy().input.byte_length)?;
        let actual = read_attempt(PositionalReader::new(file)).map_err(invalid_input)?;
        if actual != self.source.expected {
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
        let authority = self
            .image_admission()
            .recheck_authority()
            .map_err(|_| StagingError::AuthorityChanged)?;
        self.slot.recheck(authority)?;
        Ok(authority)
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
        let (bytes, charge) = frame(&mut Cursor::new([0, 0, 0, 3, 1, 2, 3]), &ledger)?;
        assert_eq!(bytes, [1, 2, 3]);
        assert_eq!(charge.bytes(), 3);
        assert_eq!(ledger.usage().reserved_bytes, 3);
        drop(charge);
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
        let (received, charge) = frame(&mut Cursor::new(bytes), &ledger)?;
        assert_eq!(received.len(), FRAME_LIMIT);
        drop(charge);
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
        let mut bounded = DigestWriter {
            hasher: blake3::Hasher::new(),
            length: INPUT_LIMIT,
        };
        assert!(bounded.write(b"x").is_err());
        bounded.length = u64::MAX;
        assert!(bounded.write(b"x").is_err());
        assert!(matches!(invalid(()), StagingError::InvalidSource));
        assert!(matches!(invalid_input(()), StagingError::InvalidInput));
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
}
