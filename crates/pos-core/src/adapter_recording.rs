//! Durable per-run adapter call recording transitions.
//!
//! This module records what the local invocation seam observed. Its records
//! are not owner admission, `PublicRecord` provenance, or Replay authority.

use crate::{
    AdapterAdmissionV1, AdapterInvocationV1, AdapterTranscriptV1, Hash, PluginId,
    WorldReplayHandleV1,
};

/// Closed failures from the durable adapter recorder.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterRecordingStoreErrorV1 {
    /// One owner/run key already has different immutable session facts.
    #[error("adapter recording session conflicts with retained facts")]
    Conflict,
    /// The session is absent, closed, or aborted for the requested transition.
    #[error("adapter recording session state does not permit this operation")]
    InvalidState,
    /// The call is not the next contiguous call or differs from its reservation.
    #[error("adapter recording call does not match its reservation")]
    InvalidCall,
    /// Persisted recorder state is malformed or inconsistent.
    #[error("adapter recording state is corrupt")]
    CorruptState,
    /// The store cannot commit or determine the transition.
    #[error("adapter recording storage operation failed")]
    StorageFailure,
}

/// Immutable identity and contract for one local recording session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterRecordingSessionV1 {
    owner_reference: Hash,
    world_handle: WorldReplayHandleV1,
    run_operation_id: Hash,
    admission: AdapterAdmissionV1,
}

impl AdapterRecordingSessionV1 {
    /// Validate one session against its owner key and complete MAA1 record.
    ///
    /// # Errors
    /// Rejects a zero identity or a World/admission owner mismatch.
    pub fn new(
        owner_reference: Hash,
        world_handle: WorldReplayHandleV1,
        run_operation_id: Hash,
        admission: AdapterAdmissionV1,
    ) -> Result<Self, AdapterRecordingStoreErrorV1> {
        if owner_reference == Hash::zero()
            || run_operation_id == Hash::zero()
            || world_handle.as_input().owner_reference != owner_reference
            || admission.as_input().owner_reference != owner_reference
        {
            return Err(AdapterRecordingStoreErrorV1::InvalidCall);
        }
        Ok(Self {
            owner_reference,
            world_handle,
            run_operation_id,
            admission,
        })
    }

    /// Return the canonical owner reference.
    #[must_use]
    pub const fn owner_reference(&self) -> Hash {
        self.owner_reference
    }

    /// Return the exact selected World handle.
    #[must_use]
    pub const fn world_handle(&self) -> WorldReplayHandleV1 {
        self.world_handle
    }

    /// Return the unique operation identity for this run.
    #[must_use]
    pub const fn run_operation_id(&self) -> Hash {
        self.run_operation_id
    }

    /// Return the exact admitted adapter contract.
    #[must_use]
    pub const fn admission(&self) -> &AdapterAdmissionV1 {
        &self.admission
    }
}

/// One exact invocation reserved before calling an adapter provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterCallReservationV1 {
    plugin_id: PluginId,
    per_plugin_call_index: u64,
    invocation: AdapterInvocationV1,
    idempotency_key: Hash,
    reserved_at_micros: u64,
}

impl AdapterCallReservationV1 {
    /// Validate an exact call reservation.
    ///
    /// # Errors
    /// Rejects a zero idempotency key.
    pub fn new(
        plugin_id: PluginId,
        per_plugin_call_index: u64,
        invocation: AdapterInvocationV1,
        idempotency_key: Hash,
        reserved_at_micros: u64,
    ) -> Result<Self, AdapterRecordingStoreErrorV1> {
        if idempotency_key == Hash::zero() {
            return Err(AdapterRecordingStoreErrorV1::InvalidCall);
        }
        Ok(Self {
            plugin_id,
            per_plugin_call_index,
            invocation,
            idempotency_key,
            reserved_at_micros,
        })
    }

    /// Return the actual calling Plugin.
    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    /// Return the Plugin-local call ordinal.
    #[must_use]
    pub const fn per_plugin_call_index(&self) -> u64 {
        self.per_plugin_call_index
    }

    /// Borrow the exact AIR1 invocation.
    #[must_use]
    pub const fn invocation(&self) -> &AdapterInvocationV1 {
        &self.invocation
    }

    /// Return the provider idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Hash {
        self.idempotency_key
    }

    /// Return the time first reserved by the owner store.
    #[must_use]
    pub const fn reserved_at_micros(&self) -> u64 {
        self.reserved_at_micros
    }
}

/// Result of reserving or resuming one exact provider call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterCallReservationOutcomeV1 {
    /// The provider may run with the retained idempotency key.
    Reserved {
        /// The timestamp from the first durable reservation.
        reserved_at_micros: u64,
    },
    /// A previous attempt committed this exact response before exposing it.
    Completed {
        /// Exact committed response bytes.
        output_bytes: Vec<u8>,
        /// Timestamp from the original reservation.
        reserved_at_micros: u64,
    },
}

/// Durable state machine for one local adapter-recording session.
pub trait AdapterRecordingStoreV1: Send {
    /// Open a session or resume the same still-open owner/run identity.
    ///
    /// # Errors
    /// Rejects conflicting retained identity or a closed/aborted session.
    fn open_adapter_recording_session(
        &mut self,
        session: AdapterRecordingSessionV1,
    ) -> Result<(), AdapterRecordingStoreErrorV1>;

    /// Persist a call reservation before any provider effect.
    ///
    /// # Errors
    /// Rejects noncontiguous ordinals, changed retries, and closed sessions.
    fn reserve_adapter_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        reservation: AdapterCallReservationV1,
    ) -> Result<AdapterCallReservationOutcomeV1, AdapterRecordingStoreErrorV1>;

    /// Persist the exact response before it can be returned to the Plugin.
    ///
    /// # Errors
    /// Rejects a missing or different reservation/response.
    fn complete_adapter_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        global_call_index: u64,
        output_bytes: Vec<u8>,
    ) -> Result<(), AdapterRecordingStoreErrorV1>;

    /// Close a complete session and return exact canonical MAT1 bytes.
    ///
    /// An empty transcript is valid only when the opened durable session has
    /// no reservations. Repeating Close returns the same retained bytes.
    ///
    /// # Errors
    /// Rejects a pending call, invalid order, or non-open session.
    fn close_adapter_recording_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Vec<u8>, AdapterRecordingStoreErrorV1>;

    /// Read the exact MAT1 from a previously closed session.
    ///
    /// # Errors
    /// Returns a storage error when the retained state is corrupt.
    fn read_closed_adapter_recording_session(
        &self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Option<Vec<u8>>, AdapterRecordingStoreErrorV1>;

    /// Abort an open session. It cannot become a MAT1 after this transition.
    ///
    /// # Errors
    /// Rejects absent, closed, or otherwise invalid state.
    fn abort_adapter_recording_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<(), AdapterRecordingStoreErrorV1>;
}

/// Validate and decode exact closed recorder bytes.
///
/// # Errors
/// Rejects malformed MAT1 bytes or a transcript different from its session.
pub fn validate_closed_adapter_recording_v1(
    session: &AdapterRecordingSessionV1,
    transcript_bytes: &[u8],
) -> Result<AdapterTranscriptV1, AdapterRecordingStoreErrorV1> {
    let transcript = AdapterTranscriptV1::from_canonical_cbor(transcript_bytes)
        .map_err(|_| AdapterRecordingStoreErrorV1::CorruptState)?;
    let input = transcript.as_input();
    if input.owner_reference != session.owner_reference
        || input.world_handle != session.world_handle
        || input.run_operation_id != session.run_operation_id
        || input.adapter_admission_digest != session.admission.digest()
    {
        return Err(AdapterRecordingStoreErrorV1::CorruptState);
    }
    transcript
        .compare_call_contracts(&session.admission)
        .map_err(|_| AdapterRecordingStoreErrorV1::CorruptState)?;
    Ok(transcript)
}

/// Construct a transcript only from the exact completed rows returned by a
/// durable session store.
///
/// # Errors
/// Returns `CorruptState` if the calls do not form the closed session's exact
/// admitted transcript.
pub fn close_adapter_recording_v1(
    session: &AdapterRecordingSessionV1,
    calls: Vec<crate::AdapterTranscriptCallV1>,
) -> Result<Vec<u8>, AdapterRecordingStoreErrorV1> {
    let transcript = AdapterTranscriptV1::new(crate::AdapterTranscriptInputV1 {
        owner_reference: session.owner_reference,
        world_handle: session.world_handle,
        run_operation_id: session.run_operation_id,
        adapter_admission_digest: session.admission.digest(),
        calls,
    })
    .map_err(|_| AdapterRecordingStoreErrorV1::CorruptState)?;
    transcript
        .compare_call_contracts(&session.admission)
        .map_err(|_| AdapterRecordingStoreErrorV1::CorruptState)?;
    Ok(transcript.to_canonical_cbor())
}

/// Build one typed completed call from exact persisted call facts.
#[must_use]
pub fn completed_adapter_call_v1(
    reservation: AdapterCallReservationV1,
    output_bytes: Vec<u8>,
) -> crate::AdapterTranscriptCallV1 {
    crate::AdapterTranscriptCallV1 {
        plugin_id: reservation.plugin_id,
        per_plugin_call_index: reservation.per_plugin_call_index,
        input: reservation.invocation,
        exact_output_bytes: output_bytes,
        recorded_wall_time_micros: reservation.reserved_at_micros,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter_configuration_digest_v1, public_adapter_schema_digest_v1, AdapterAdmissionEntryV1,
        AdapterAdmissionInputV1, AdapterDataClassV1, AdapterEffectModeV1, AdapterInvocationInputV1,
        TimelineId, WorldReplayHandleInputV1,
    };

    fn recording_fixture() -> (AdapterRecordingSessionV1, PluginId, AdapterInvocationV1) {
        let owner_reference = Hash::from_bytes([61; 32]);
        let plugin_id = PluginId::new();
        let configuration = b"recording-test-config".to_vec();
        let schema_digest = public_adapter_schema_digest_v1();
        let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            owner_reference,
            configuration_generation: 1,
            scope_digest: Hash::from_bytes([62; 32]),
            entries: vec![AdapterAdmissionEntryV1 {
                plugin_id,
                adapter_id: "weather.client".to_owned(),
                provider_id: "fixture.provider".to_owned(),
                operation_id: "read-current".to_owned(),
                protocol_version: 1,
                request_schema_digest: schema_digest,
                response_schema_digest: schema_digest,
                configuration_digest: adapter_configuration_digest_v1(&configuration),
                exact_configuration_bytes: configuration,
                input_data_class: AdapterDataClassV1::PublicRecord,
                output_data_class: AdapterDataClassV1::PublicRecord,
                effect_mode: AdapterEffectModeV1::ReadOnly,
            }],
        })
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let world_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
            owner_reference,
            timeline_id: TimelineId::new(),
            cut_id: 1,
            commit_receipt_digest: Hash::from_bytes([63; 32]),
            recording_receipt_digest: Hash::from_bytes([64; 32]),
            logical_head: 0,
            stitched_head_hash: Hash::from_bytes([65; 32]),
        })
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let session = AdapterRecordingSessionV1::new(
            owner_reference,
            world_handle,
            Hash::from_bytes([66; 32]),
            admission,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let invocation = AdapterInvocationV1::new(AdapterInvocationInputV1 {
            adapter_id: "weather.client".to_owned(),
            provider_id: "fixture.provider".to_owned(),
            operation_id: "read-current".to_owned(),
            protocol_version: 1,
            request_schema_digest: schema_digest,
            response_schema_digest: schema_digest,
            configuration_digest: adapter_configuration_digest_v1(b"recording-test-config"),
            global_call_index: 0,
            exact_request_payload: b"exact request".to_vec(),
        })
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        (session, plugin_id, invocation)
    }

    #[test]
    fn closed_adapter_recording_bytes_are_checked_against_session_identity() {
        let (session, plugin_id, invocation) = recording_fixture();
        let reservation = AdapterCallReservationV1::new(
            plugin_id,
            0,
            invocation,
            Hash::from_bytes([67; 32]),
            123,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let call = completed_adapter_call_v1(reservation, b"exact response".to_vec());
        let transcript_bytes = close_adapter_recording_v1(&session, vec![call])
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let transcript = validate_closed_adapter_recording_v1(&session, &transcript_bytes)
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(transcript.as_input().calls.len(), 1);
        assert_eq!(
            transcript.as_input().calls[0].exact_output_bytes.as_slice(),
            b"exact response"
        );

        assert_eq!(
            validate_closed_adapter_recording_v1(&session, b"not MAT1"),
            Err(AdapterRecordingStoreErrorV1::CorruptState)
        );
        let other_session = AdapterRecordingSessionV1::new(
            session.owner_reference(),
            session.world_handle(),
            Hash::from_bytes([68; 32]),
            session.admission().clone(),
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            validate_closed_adapter_recording_v1(&other_session, &transcript_bytes),
            Err(AdapterRecordingStoreErrorV1::CorruptState)
        );
    }

    #[test]
    fn adapter_recording_session_rejects_zero_owner_or_operation_identity() {
        let (session, _, _) = recording_fixture();
        assert_eq!(
            AdapterRecordingSessionV1::new(
                Hash::zero(),
                session.world_handle(),
                session.run_operation_id(),
                session.admission().clone(),
            ),
            Err(AdapterRecordingStoreErrorV1::InvalidCall)
        );
        assert_eq!(
            AdapterRecordingSessionV1::new(
                session.owner_reference(),
                session.world_handle(),
                Hash::zero(),
                session.admission().clone(),
            ),
            Err(AdapterRecordingStoreErrorV1::InvalidCall)
        );
    }
}
