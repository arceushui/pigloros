//! In-process ADR-101 adapter admission and closed call recording.

use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    time::SystemTime,
};

use pos_core::{
    validate_closed_adapter_recording_v1, AdapterAdmissionEntryV1, AdapterAdmissionInputV1,
    AdapterAdmissionV1, AdapterCallReservationOutcomeV1, AdapterCallReservationV1,
    AdapterInvocationInputV1, AdapterInvocationV1, AdapterRecordingSessionV1,
    AdapterRecordingStoreV1, AdapterTranscriptCallV1, AdapterTranscriptV1, Hash,
    PluginId, WorldReplayHandleV1, MAX_ADAPTER_CALL_BYTES_V1, MAX_ADAPTER_TRANSCRIPT_BYTES_V1,
    MAX_ADAPTER_TRANSCRIPT_CALLS_V1,
};

use super::{PluginEntry, PluginRegistry};
use crate::{
    composition::{
        AdmittedCompositionV1, DomainImplementationKindV1, PluginAvailabilityV1,
        PluginExecutionModeV1, PluginIsolationV1,
    },
    recorder::RunMode,
};

/// Closed failures from local adapter registration or invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalAdapterErrorV1 {
    #[error("local adapters require a live local PluginRegistry")]
    RegistryState,
    #[error("local adapter registration is already sealed")]
    ManifestSealed,
    #[error("local adapter Plugin is missing or not available")]
    PluginUnavailable,
    #[error("local adapter contract is invalid or duplicated")]
    InvalidContract,
    #[error("local adapter registry admission is stale or incomplete")]
    StaleAdmission,
    #[error("local adapter call does not match an admitted provider")]
    UnknownAdapter,
    #[error("local adapter invocation is outside the accepted call bound")]
    CallBoundExceeded,
    #[error("local adapter provider rejected the invocation")]
    ProviderRejected,
    #[error("local adapter session was aborted")]
    SessionAborted,
    #[error("local adapter clock could not produce a valid timestamp")]
    ClockUnavailable,
    #[error("local adapter transcript does not match its admission")]
    TranscriptInvalid,
    #[error("local adapter recorder could not durably commit the call")]
    RecordingFailed,
}

/// Actual in-process adapter callback selected by a local owner.
///
/// Implementations receive a deterministic idempotency key for every call.
/// A provider admitted with `ExternallyIdempotent` must enforce that key at
/// the remote side effect boundary. The runtime retains only the exact public
/// request and response bytes returned through this callback.
pub trait LocalAdapterProviderV1: Send + Sync {
    /// Invoke the selected provider with one exact AIR1 request.
    ///
    /// # Errors
    /// Returns `ProviderRejected` when the provider cannot complete the call.
    fn invoke(
        &mut self,
        invocation: &AdapterInvocationV1,
        idempotency_key: Hash,
    ) -> Result<Vec<u8>, LocalAdapterErrorV1>;
}

pub(super) struct RegisteredLocalAdapterV1 {
    entry: AdapterAdmissionEntryV1,
    provider: Box<dyn LocalAdapterProviderV1>,
}

/// Exact registry-derived MAA1 and locally recorded MAT1 bytes.
///
/// These records do not establish native owner admission or WorldCut provenance.
pub struct ClosedAdapterTranscriptV1 {
    admission: AdapterAdmissionV1,
    transcript: AdapterTranscriptV1,
}

impl ClosedAdapterTranscriptV1 {
    /// Borrow the exact MAA1 record derived from the sealed local registry.
    #[must_use]
    pub const fn admission(&self) -> &AdapterAdmissionV1 {
        &self.admission
    }

    /// Borrow the exact transcript built from provider calls made in this session.
    #[must_use]
    pub const fn transcript(&self) -> &AdapterTranscriptV1 {
        &self.transcript
    }

    /// Encode the exact canonical MAA1 bytes.
    #[must_use]
    pub fn admission_bytes(&self) -> Vec<u8> {
        self.admission.to_canonical_cbor()
    }

    /// Encode the exact canonical MAT1 bytes.
    #[must_use]
    pub fn transcript_bytes(&self) -> Vec<u8> {
        self.transcript.to_canonical_cbor()
    }
}

/// One consumable local adapter run. An unclosed or failed run yields no MAT1.
pub struct LocalAdapterSessionV1<'registry, 'composition, 'store> {
    registry: &'registry mut PluginRegistry,
    admitted: &'composition AdmittedCompositionV1,
    recorder: &'store mut dyn AdapterRecordingStoreV1,
    recording_session: AdapterRecordingSessionV1,
    admission: AdapterAdmissionV1,
    world_handle: WorldReplayHandleV1,
    run_operation_id: Hash,
    calls: Vec<AdapterTranscriptCallV1>,
    encoded_call_bytes: usize,
    next_per_plugin_call: BTreeMap<PluginId, u64>,
    failed: bool,
}

impl LocalAdapterSessionV1<'_, '_, '_> {
    /// Invoke one locally admitted adapter and record its exact public bytes.
    ///
    /// The request and response are retained only inside this consuming
    /// session. The provider receives a run-scoped idempotency key before any
    /// external effect occurs.
    ///
    /// # Errors
    /// Rejects an unknown contract, a stale registry, excess calls or bytes,
    /// provider failure, and any call after an earlier failure.
    pub fn invoke(
        &mut self,
        plugin_id: PluginId,
        adapter_id: &str,
        provider_id: &str,
        operation_id: &str,
        protocol_version: u64,
        exact_request_payload: Vec<u8>,
    ) -> Result<Vec<u8>, LocalAdapterErrorV1> {
        if self.failed {
            return Err(LocalAdapterErrorV1::SessionAborted);
        }
        if !self
            .registry
            .is_admitted_composition_current_for_generation(
                self.admitted,
                self.admitted.catalog().as_input().configuration_generation,
            )
        {
            self.failed = true;
            return Err(LocalAdapterErrorV1::StaleAdmission);
        }
        let Some(adapter_index) = self.registry.local_adapters.iter().position(|adapter| {
            adapter.entry.plugin_id == plugin_id
                && adapter.entry.adapter_id == adapter_id
                && adapter.entry.provider_id == provider_id
                && adapter.entry.operation_id == operation_id
                && adapter.entry.protocol_version == protocol_version
        }) else {
            self.failed = true;
            return Err(LocalAdapterErrorV1::UnknownAdapter);
        };
        let entry = self.registry.local_adapters[adapter_index].entry.clone();
        let global_call_index = match u64::try_from(self.calls.len()) {
            Ok(index) if self.calls.len() < MAX_ADAPTER_TRANSCRIPT_CALLS_V1 => index,
            _ => {
                self.failed = true;
                return Err(LocalAdapterErrorV1::CallBoundExceeded);
            }
        };
        let invocation = match AdapterInvocationV1::new(AdapterInvocationInputV1 {
            adapter_id: entry.adapter_id.clone(),
            provider_id: entry.provider_id.clone(),
            operation_id: entry.operation_id.clone(),
            protocol_version: entry.protocol_version,
            request_schema_digest: entry.request_schema_digest,
            response_schema_digest: entry.response_schema_digest,
            configuration_digest: entry.configuration_digest,
            global_call_index,
            exact_request_payload,
        }) {
            Ok(invocation) => invocation,
            Err(_) => {
                self.failed = true;
                return Err(LocalAdapterErrorV1::CallBoundExceeded);
            }
        };
        let recorded_wall_time_micros = match SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_micros()).ok())
        {
            Some(value) => value,
            None => {
                self.failed = true;
                return Err(LocalAdapterErrorV1::ClockUnavailable);
            }
        };
        let per_plugin_call_index = self
            .next_per_plugin_call
            .get(&plugin_id)
            .copied()
            .unwrap_or_default();
        let maximum_call_size = transcript_call_size(
            per_plugin_call_index,
            invocation.to_canonical_cbor().len(),
            MAX_ADAPTER_CALL_BYTES_V1,
            u64::MAX,
        );
        let maximum_transcript_size = transcript_base_size(self.world_handle)
            .saturating_add(cbor_head_size(self.calls.len().saturating_add(1)))
            .saturating_add(self.encoded_call_bytes)
            .saturating_add(maximum_call_size);
        if maximum_transcript_size > MAX_ADAPTER_TRANSCRIPT_BYTES_V1 {
            self.failed = true;
            return Err(LocalAdapterErrorV1::CallBoundExceeded);
        }
        let idempotency_key = adapter_idempotency_key(
            self.admission.as_input().owner_reference,
            self.admission.digest(),
            self.run_operation_id,
            plugin_id,
            invocation.digest(),
        );
        let reservation = AdapterCallReservationV1::new(
            plugin_id,
            per_plugin_call_index,
            invocation.clone(),
            idempotency_key,
            recorded_wall_time_micros,
        )
        .map_err(|_| LocalAdapterErrorV1::RecordingFailed)?;
        let output = match self.recorder.reserve_adapter_call(
            self.recording_session.owner_reference(),
            self.recording_session.run_operation_id(),
            reservation.clone(),
        ) {
            Ok(AdapterCallReservationOutcomeV1::Completed {
                output_bytes,
                reserved_at_micros,
            }) => (output_bytes, reserved_at_micros),
            Ok(AdapterCallReservationOutcomeV1::Reserved { reserved_at_micros }) => {
                let output = match catch_unwind(AssertUnwindSafe(|| {
                    self.registry.local_adapters[adapter_index]
                        .provider
                        .invoke(&invocation, idempotency_key)
                })) {
                    Ok(Ok(output)) if output.len() <= MAX_ADAPTER_CALL_BYTES_V1 => output,
                    Ok(Ok(_)) => {
                        self.failed = true;
                        return Err(LocalAdapterErrorV1::CallBoundExceeded);
                    }
                    Ok(Err(_)) | Err(_) => {
                        self.failed = true;
                        return Err(LocalAdapterErrorV1::ProviderRejected);
                    }
                };
                if self
                    .recorder
                    .complete_adapter_call(
                        self.recording_session.owner_reference(),
                        self.recording_session.run_operation_id(),
                        global_call_index,
                        output.clone(),
                    )
                    .is_err()
                {
                    self.failed = true;
                    return Err(LocalAdapterErrorV1::RecordingFailed);
                }
                (output, reserved_at_micros)
            }
            Err(_) => {
                self.failed = true;
                return Err(LocalAdapterErrorV1::RecordingFailed);
            }
        };
        if output.0.len() > MAX_ADAPTER_CALL_BYTES_V1 {
            self.failed = true;
            return Err(LocalAdapterErrorV1::CallBoundExceeded);
        }
        let call_size = transcript_call_size(
            per_plugin_call_index,
            invocation.to_canonical_cbor().len(),
            output.0.len(),
            output.1,
        );
        let transcript_size = transcript_base_size(self.world_handle)
            .saturating_add(cbor_head_size(self.calls.len().saturating_add(1)))
            .saturating_add(self.encoded_call_bytes)
            .saturating_add(call_size);
        if transcript_size > MAX_ADAPTER_TRANSCRIPT_BYTES_V1 {
            self.failed = true;
            return Err(LocalAdapterErrorV1::CallBoundExceeded);
        }
        self.calls.push(AdapterTranscriptCallV1 {
            plugin_id,
            per_plugin_call_index,
            input: invocation,
            exact_output_bytes: output.0.clone(),
            recorded_wall_time_micros: output.1,
        });
        self.encoded_call_bytes = self.encoded_call_bytes.saturating_add(call_size);
        self.next_per_plugin_call
            .insert(plugin_id, per_plugin_call_index.saturating_add(1));
        Ok(output.0)
    }

    /// Close the session and return its exact MAA1 and MAT1 records.
    ///
    /// Closing a zero-call session records an explicit empty transcript.
    /// Dropping or aborting the session returns no transcript capability.
    ///
    /// # Errors
    /// Rejects an aborted/stale session or any transcript that does not match
    /// the registry-derived admission.
    pub fn finish(self) -> Result<ClosedAdapterTranscriptV1, LocalAdapterErrorV1> {
        if self.failed
            || !self
                .registry
                .is_admitted_composition_current_for_generation(
                    self.admitted,
                    self.admitted.catalog().as_input().configuration_generation,
                )
        {
            return Err(LocalAdapterErrorV1::SessionAborted);
        }
        let bytes = self
            .recorder
            .close_adapter_recording_session(
                self.recording_session.owner_reference(),
                self.recording_session.run_operation_id(),
            )
            .map_err(|_| LocalAdapterErrorV1::RecordingFailed)?;
        let transcript = validate_closed_adapter_recording_v1(&self.recording_session, &bytes)
            .map_err(|_| LocalAdapterErrorV1::TranscriptInvalid)?;
        Ok(ClosedAdapterTranscriptV1 {
            admission: self.admission,
            transcript,
        })
    }

    /// Abort this run so its incomplete recorder state can never produce MAT1.
    ///
    /// # Errors
    /// Returns `RecordingFailed` when the store cannot durably mark the run
    /// aborted.
    pub fn abort(self) -> Result<(), LocalAdapterErrorV1> {
        self.recorder
            .abort_adapter_recording_session(
                self.recording_session.owner_reference(),
                self.recording_session.run_operation_id(),
            )
            .map_err(|_| LocalAdapterErrorV1::RecordingFailed)
    }
}

impl PluginRegistry {
    /// Register one local adapter callback before the Plugin roster is sealed.
    ///
    /// Its exact MAA1 contract is later derived from this private registry row.
    /// A caller cannot insert an adapter for another Plugin or reuse a contract
    /// identity already selected by this owner.
    ///
    /// # Errors
    /// Rejects an unavailable Plugin, incompatible registry mode, duplicate or
    /// invalid contract, and registration after composition admission.
    pub fn register_local_adapter(
        &mut self,
        entry: AdapterAdmissionEntryV1,
        provider: Box<dyn LocalAdapterProviderV1>,
    ) -> Result<(), LocalAdapterErrorV1> {
        if self.run_mode != RunMode::Live || self.composition_mode != PluginExecutionModeV1::Local {
            return Err(LocalAdapterErrorV1::RegistryState);
        }
        if self.manifest_batch.is_some() {
            return Err(LocalAdapterErrorV1::ManifestSealed);
        }
        let plugin = self
            .plugins
            .get(&entry.plugin_id)
            .ok_or(LocalAdapterErrorV1::PluginUnavailable)?;
        validate_local_adapter_plugin(plugin)?;
        if self.local_adapters.iter().any(|adapter| {
            adapter.entry.plugin_id == entry.plugin_id
                && adapter.entry.adapter_id == entry.adapter_id
                && adapter.entry.provider_id == entry.provider_id
                && adapter.entry.operation_id == entry.operation_id
                && adapter.entry.protocol_version == entry.protocol_version
        }) {
            return Err(LocalAdapterErrorV1::InvalidContract);
        }
        let mut entries: Vec<_> = self
            .local_adapters
            .iter()
            .map(|adapter| adapter.entry.clone())
            .collect();
        entries.push(entry.clone());
        sort_admission_entries(&mut entries);
        AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            owner_reference: Hash::from_bytes([1; 32]),
            configuration_generation: 1,
            scope_digest: Hash::from_bytes([2; 32]),
            entries,
        })
        .map_err(|_| LocalAdapterErrorV1::InvalidContract)?;
        self.local_adapters
            .push(RegisteredLocalAdapterV1 { entry, provider });
        self.registration_revision += 1;
        Ok(())
    }

    /// Start a closed recorder session for the exact currently admitted roster.
    ///
    /// # Errors
    /// Rejects a stale composition, zero run operation, or mismatched World
    /// handle owner reference. The local registry checks WRH1 structure and
    /// owner identity only; it does not look up or authenticate a native cut.
    pub fn begin_local_adapter_session<'registry, 'composition, 'store>(
        &'registry mut self,
        admitted: &'composition AdmittedCompositionV1,
        world_handle: WorldReplayHandleV1,
        run_operation_id: Hash,
        recorder: &'store mut dyn AdapterRecordingStoreV1,
    ) -> Result<LocalAdapterSessionV1<'registry, 'composition, 'store>, LocalAdapterErrorV1> {
        let generation = admitted.catalog().as_input().configuration_generation;
        if run_operation_id == Hash::zero()
            || !self.is_admitted_composition_current_for_generation(admitted, generation)
            || world_handle.as_input().owner_reference
                != admitted.adapter_admission().as_input().owner_reference
        {
            return Err(LocalAdapterErrorV1::StaleAdmission);
        }
        let recording_session = AdapterRecordingSessionV1::new(
            admitted.adapter_admission().as_input().owner_reference,
            world_handle,
            run_operation_id,
            admitted.adapter_admission().clone(),
        )
        .map_err(|_| LocalAdapterErrorV1::StaleAdmission)?;
        recorder
            .open_adapter_recording_session(recording_session.clone())
            .map_err(|_| LocalAdapterErrorV1::RecordingFailed)?;
        Ok(LocalAdapterSessionV1 {
            registry: self,
            admitted,
            recorder,
            recording_session,
            admission: admitted.adapter_admission().clone(),
            world_handle,
            run_operation_id,
            calls: Vec::new(),
            encoded_call_bytes: 0,
            next_per_plugin_call: BTreeMap::new(),
            failed: false,
        })
    }

    pub(super) fn adapter_admission_for_catalog(
        &self,
        catalog: &pos_core::ManifestAdmissionCatalogV1,
    ) -> Result<AdapterAdmissionV1, LocalAdapterErrorV1> {
        let registered_plugins: Vec<_> = catalog
            .as_input()
            .rows
            .iter()
            .map(|row| row.plugin_id)
            .collect();
        let mut entries: Vec<_> = self
            .local_adapters
            .iter()
            .map(|adapter| adapter.entry.clone())
            .collect();
        if entries
            .iter()
            .any(|entry| !registered_plugins.contains(&entry.plugin_id))
        {
            return Err(LocalAdapterErrorV1::StaleAdmission);
        }
        sort_admission_entries(&mut entries);
        AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            owner_reference: Hash::from_bytes(catalog.as_input().owner_id),
            configuration_generation: catalog.as_input().configuration_generation,
            scope_digest: catalog.digest(),
            entries,
        })
        .map_err(|_| LocalAdapterErrorV1::InvalidContract)
    }
}

fn validate_local_adapter_plugin(plugin: &PluginEntry) -> Result<(), LocalAdapterErrorV1> {
    let registration = plugin
        .registration
        .as_ref()
        .ok_or(LocalAdapterErrorV1::PluginUnavailable)?;
    let admission = plugin
        .output_admission
        .as_ref()
        .ok_or(LocalAdapterErrorV1::PluginUnavailable)?;
    if registration.availability() != PluginAvailabilityV1::Available
        || registration.pin().implementation_kind() != DomainImplementationKindV1::Plugin
        || registration.pin().isolation() != PluginIsolationV1::OperatorTrustedNative
        || registration.pin().configuration_digest() != admission.policy_digest()
        || admission.closure().is_none()
    {
        return Err(LocalAdapterErrorV1::PluginUnavailable);
    }
    Ok(())
}

fn sort_admission_entries(entries: &mut [AdapterAdmissionEntryV1]) {
    entries.sort_unstable_by(|left, right| {
        (
            left.plugin_id,
            left.adapter_id.as_str(),
            left.provider_id.as_str(),
            left.operation_id.as_str(),
            left.protocol_version,
        )
            .cmp(&(
                right.plugin_id,
                right.adapter_id.as_str(),
                right.provider_id.as_str(),
                right.operation_id.as_str(),
                right.protocol_version,
            ))
    });
}

fn transcript_base_size(world_handle: WorldReplayHandleV1) -> usize {
    7_usize
        .saturating_add(34)
        .saturating_add(cbor_bytes_size(world_handle.to_canonical_cbor().len()))
        .saturating_add(34)
        .saturating_add(34)
}

fn transcript_call_size(
    per_plugin_call_index: u64,
    invocation_bytes: usize,
    output_bytes: usize,
    recorded_wall_time_micros: u64,
) -> usize {
    1_usize
        .saturating_add(cbor_bytes_size(16))
        .saturating_add(cbor_uint_size(per_plugin_call_index))
        .saturating_add(cbor_bytes_size(invocation_bytes))
        .saturating_add(34)
        .saturating_add(cbor_bytes_size(output_bytes))
        .saturating_add(34)
        .saturating_add(cbor_uint_size(recorded_wall_time_micros))
}

fn cbor_bytes_size(length: usize) -> usize {
    cbor_uint_size(u64::try_from(length).unwrap_or(u64::MAX)).saturating_add(length)
}

fn cbor_head_size(length: usize) -> usize {
    cbor_uint_size(u64::try_from(length).unwrap_or(u64::MAX))
}

fn cbor_uint_size(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn adapter_idempotency_key(
    owner_reference: Hash,
    adapter_admission_digest: Hash,
    run_operation_id: Hash,
    plugin_id: PluginId,
    input_digest: Hash,
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.repro.adapter-idempotency.v1\0");
    hasher.update(owner_reference.as_bytes());
    hasher.update(adapter_admission_digest.as_bytes());
    hasher.update(run_operation_id.as_bytes());
    hasher.update(&plugin_id.inner().to_bytes());
    hasher.update(input_digest.as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
