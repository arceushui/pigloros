//! In-process ADR-101 adapter admission and closed call recording.

use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    time::SystemTime,
};

use pos_core::{
    validate_closed_adapter_recording_v1, AdapterAdmissionEntryV1, AdapterAdmissionInputV1,
    AdapterAdmissionV1, AdapterCallReservationOutcomeV1, AdapterCallReservationV1,
    AdapterEffectModeV1, AdapterInvocationInputV1, AdapterInvocationV1, AdapterRecordingSessionV1,
    AdapterRecordingStoreV1, AdapterTranscriptCallV1, AdapterTranscriptV1, Hash, PluginId,
    WorldReplayHandleV1, MAX_ADAPTER_CALL_BYTES_V1, MAX_ADAPTER_TRANSCRIPT_BYTES_V1,
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
    #[error("externally idempotent adapter has no provider-enforced deduplication guarantee")]
    IdempotencyUnavailable,
    #[error("externally idempotent provider did not acknowledge the exact run call key")]
    ProviderIdempotencyUnacknowledged,
    #[error("local adapter session was aborted")]
    SessionAborted,
    #[error("local adapter clock could not produce a valid timestamp")]
    ClockUnavailable,
    #[error("local adapter transcript does not match its admission")]
    TranscriptInvalid,
    #[error("local adapter recorder could not durably commit the call")]
    RecordingFailed,
}

/// ADR-101 key supplied to an externally idempotent provider for one run call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAdapterIdempotencyKeyV1 {
    owner_reference: Hash,
    run_operation_id: Hash,
    global_call_index: u64,
}

impl LocalAdapterIdempotencyKeyV1 {
    const fn new(owner_reference: Hash, run_operation_id: Hash, global_call_index: u64) -> Self {
        Self {
            owner_reference,
            run_operation_id,
            global_call_index,
        }
    }

    /// Return the native local owner reference for this run.
    #[must_use]
    pub const fn owner_reference(self) -> Hash {
        self.owner_reference
    }

    /// Return the idempotent run operation identity.
    #[must_use]
    pub const fn run_operation_id(self) -> Hash {
        self.run_operation_id
    }

    /// Return the zero-based global call ordinal in the run.
    #[must_use]
    pub const fn global_call_index(self) -> u64 {
        self.global_call_index
    }
}

/// Exact provider output and optional acknowledgement of its idempotency key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAdapterProviderResponseV1 {
    output_bytes: Vec<u8>,
    idempotency_acknowledgement: Option<LocalAdapterIdempotencyKeyV1>,
}

impl LocalAdapterProviderResponseV1 {
    /// Return a response without an idempotency acknowledgement.
    #[must_use]
    pub const fn unacknowledged(output_bytes: Vec<u8>) -> Self {
        Self {
            output_bytes,
            idempotency_acknowledgement: None,
        }
    }

    /// Return a response acknowledging the exact supplied run call key.
    #[must_use]
    pub const fn acknowledged(
        output_bytes: Vec<u8>,
        idempotency_key: LocalAdapterIdempotencyKeyV1,
    ) -> Self {
        Self {
            output_bytes,
            idempotency_acknowledgement: Some(idempotency_key),
        }
    }
}

/// Actual in-process adapter callback selected by a local owner.
///
/// A provider admitted with `ExternallyIdempotent` must guarantee deduplication
/// at its side-effect boundary for the owner/run/global-call key, then return
/// that same key in its response. The runtime retains only the exact public
/// request and response bytes returned through this callback. The containing
/// registry is shared with Gateway callers and sent to its store-owner thread,
/// so providers must support both transfers even though each session serializes
/// invocation through mutable access.
pub trait LocalAdapterProviderV1: Send + Sync {
    /// Assert that this provider enforces deduplication for every supplied key.
    ///
    /// The default denies externally idempotent registration. Implementations
    /// must return `true` only when retries with the same key cannot repeat the
    /// external effect.
    fn guarantees_external_idempotency(&self) -> bool {
        false
    }

    /// Invoke the selected provider with one exact AIR1 request.
    ///
    /// # Errors
    /// Returns `ProviderRejected` when the provider cannot complete the call.
    fn invoke(
        &mut self,
        invocation: &AdapterInvocationV1,
        idempotency_key: LocalAdapterIdempotencyKeyV1,
    ) -> Result<LocalAdapterProviderResponseV1, LocalAdapterErrorV1>;
}

pub(super) struct RegisteredLocalAdapterV1 {
    entry: AdapterAdmissionEntryV1,
    provider: Box<dyn LocalAdapterProviderV1>,
}

/// Exact registry-derived MAA1 and locally recorded MAT1 bytes.
///
/// These records do not establish native owner admission or `WorldCut` provenance.
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
        let adapter_index = self.find_adapter_index(
            plugin_id,
            adapter_id,
            provider_id,
            operation_id,
            protocol_version,
        )?;
        let entry = self.registry.local_adapters[adapter_index].entry.clone();
        let (global_call_index, invocation) =
            self.build_invocation(&entry, exact_request_payload)?;
        let per_plugin_call_index = self
            .next_per_plugin_call
            .get(&plugin_id)
            .copied()
            .unwrap_or_default();
        self.ensure_call_fits_transcript(per_plugin_call_index, &invocation)?;
        let (output_bytes, recorded_wall_time_micros) = self.record_call(
            adapter_index,
            plugin_id,
            per_plugin_call_index,
            global_call_index,
            &invocation,
        )?;
        self.retain_call(
            plugin_id,
            per_plugin_call_index,
            invocation,
            output_bytes.clone(),
            recorded_wall_time_micros,
        )?;
        Ok(output_bytes)
    }

    fn find_adapter_index(
        &mut self,
        plugin_id: PluginId,
        adapter_id: &str,
        provider_id: &str,
        operation_id: &str,
        protocol_version: u64,
    ) -> Result<usize, LocalAdapterErrorV1> {
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
        Ok(adapter_index)
    }

    fn build_invocation(
        &mut self,
        entry: &AdapterAdmissionEntryV1,
        exact_request_payload: Vec<u8>,
    ) -> Result<(u64, AdapterInvocationV1), LocalAdapterErrorV1> {
        let Ok(global_call_index) = u64::try_from(self.calls.len()) else {
            self.failed = true;
            return Err(LocalAdapterErrorV1::CallBoundExceeded);
        };
        if self.calls.len() >= MAX_ADAPTER_TRANSCRIPT_CALLS_V1 {
            self.failed = true;
            return Err(LocalAdapterErrorV1::CallBoundExceeded);
        }
        let Ok(invocation) = AdapterInvocationV1::new(AdapterInvocationInputV1 {
            adapter_id: entry.adapter_id.clone(),
            provider_id: entry.provider_id.clone(),
            operation_id: entry.operation_id.clone(),
            protocol_version: entry.protocol_version,
            request_schema_digest: entry.request_schema_digest,
            response_schema_digest: entry.response_schema_digest,
            configuration_digest: entry.configuration_digest,
            global_call_index,
            exact_request_payload,
        }) else {
            self.failed = true;
            return Err(LocalAdapterErrorV1::CallBoundExceeded);
        };
        Ok((global_call_index, invocation))
    }

    fn ensure_call_fits_transcript(
        &mut self,
        per_plugin_call_index: u64,
        invocation: &AdapterInvocationV1,
    ) -> Result<(), LocalAdapterErrorV1> {
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
        Ok(())
    }

    fn record_call(
        &mut self,
        adapter_index: usize,
        plugin_id: PluginId,
        per_plugin_call_index: u64,
        global_call_index: u64,
        invocation: &AdapterInvocationV1,
    ) -> Result<(Vec<u8>, u64), LocalAdapterErrorV1> {
        let Some(recorded_wall_time_micros) = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_micros()).ok())
        else {
            self.failed = true;
            return Err(LocalAdapterErrorV1::ClockUnavailable);
        };
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
            (*invocation).clone(),
            idempotency_key,
            recorded_wall_time_micros,
        )
        .map_err(|_| LocalAdapterErrorV1::RecordingFailed)?;
        let output = match self.recorder.reserve_adapter_call(
            self.recording_session.owner_reference(),
            self.recording_session.run_operation_id(),
            reservation,
        ) {
            Ok(AdapterCallReservationOutcomeV1::Completed {
                output_bytes,
                reserved_at_micros,
            }) => (output_bytes, reserved_at_micros),
            Ok(AdapterCallReservationOutcomeV1::Reserved { reserved_at_micros }) => {
                let provider_key = LocalAdapterIdempotencyKeyV1::new(
                    self.recording_session.owner_reference(),
                    self.recording_session.run_operation_id(),
                    global_call_index,
                );
                let effect_mode = self.registry.local_adapters[adapter_index]
                    .entry
                    .effect_mode;
                let output = match catch_unwind(AssertUnwindSafe(|| {
                    self.registry.local_adapters[adapter_index]
                        .provider
                        .invoke(invocation, provider_key)
                })) {
                    Ok(Ok(response))
                        if response.output_bytes.len() <= MAX_ADAPTER_CALL_BYTES_V1 =>
                    {
                        if effect_mode == AdapterEffectModeV1::ExternallyIdempotent
                            && response.idempotency_acknowledgement != Some(provider_key)
                        {
                            self.failed = true;
                            return Err(LocalAdapterErrorV1::ProviderIdempotencyUnacknowledged);
                        }
                        response.output_bytes
                    }
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
        Ok(output)
    }

    fn retain_call(
        &mut self,
        plugin_id: PluginId,
        per_plugin_call_index: u64,
        invocation: AdapterInvocationV1,
        output_bytes: Vec<u8>,
        recorded_wall_time_micros: u64,
    ) -> Result<(), LocalAdapterErrorV1> {
        if output_bytes.len() > MAX_ADAPTER_CALL_BYTES_V1 {
            self.failed = true;
            return Err(LocalAdapterErrorV1::CallBoundExceeded);
        }
        let call_size = transcript_call_size(
            per_plugin_call_index,
            invocation.to_canonical_cbor().len(),
            output_bytes.len(),
            recorded_wall_time_micros,
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
            exact_output_bytes: output_bytes,
            recorded_wall_time_micros,
        });
        self.encoded_call_bytes = self.encoded_call_bytes.saturating_add(call_size);
        self.next_per_plugin_call
            .insert(plugin_id, per_plugin_call_index.saturating_add(1));
        Ok(())
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
        if entry.effect_mode == AdapterEffectModeV1::ExternallyIdempotent
            && !provider.guarantees_external_idempotency()
        {
            return Err(LocalAdapterErrorV1::IdempotencyUnavailable);
        }
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

const fn cbor_uint_size(value: u64) -> usize {
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
