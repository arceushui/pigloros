//! Host-owned admission of Plugin output against one recorded policy identity.

use pos_core::{
    event::EventDraft,
    output_policy::{OutputFidelityV1, OutputPolicyV1},
    ExecutableBudgetPolicyV1, Hash, PluginId,
};
use std::sync::Mutex;

/// Closed failures returned by the production output gate.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OutputAdmissionErrorV1 {
    #[error("output policy Plugin identity does not match the registered Plugin")]
    PluginMismatch,
    #[error("output policy Plugin version does not match the registered Plugin")]
    PluginVersionMismatch,
    #[error("output policy executable profile identity does not match the supplied budget")]
    PolicyIdentityMismatch,
    #[error("Plugin output has no declared policy entry for event type '{event_type}'")]
    MissingDeclaration { event_type: String },
    #[error("Plugin output '{event_type}' exceeds its declared byte limit")]
    EventBytesExceeded {
        event_type: String,
        requested: usize,
        limit: u32,
    },
    #[error("Plugin output exceeds the executable event-count budget")]
    EventCountExceeded {
        level: u8,
        requested: u64,
        limit: u32,
    },
    #[error("Plugin output exceeds the executable byte budget")]
    BatchBytesExceeded {
        level: u8,
        requested: u64,
        limit: u64,
    },
    #[error("Plugin output exceeds the executable CPU budget")]
    CpuExceeded {
        level: u8,
        requested: u64,
        limit: u32,
    },
    #[error("executable budget has no CPU reservation for the registered Plugin")]
    MissingCpuReservation,
}

/// Deterministic, host-side validation of one Plugin's complete output batch.
///
/// The validator is intentionally immutable: a rejected staged step cannot
/// consume budget. The host invokes it before append and exposes the policy
/// digest to the surrounding evidence pipeline.
#[derive(Debug)]
pub struct OutputAdmissionV1 {
    plugin_id: PluginId,
    policy_digest: Hash,
    policy: OutputPolicyV1,
    budget: ExecutableBudgetPolicyV1,
    cpu_reservations_us: [u32; 3],
    usage: Mutex<AdmissionUsage>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AdmissionUsage {
    events: [u64; 3],
    bytes: [u64; 3],
}

impl Clone for OutputAdmissionV1 {
    fn clone(&self) -> Self {
        Self {
            plugin_id: self.plugin_id,
            policy_digest: self.policy_digest,
            policy: self.policy.clone(),
            budget: self.budget.clone(),
            cpu_reservations_us: self.cpu_reservations_us,
            usage: Mutex::new(
                *self
                    .usage
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
        }
    }
}

impl OutputAdmissionV1 {
    /// Bind a structural output policy to its exact executable budget identity.
    ///
    /// # Errors
    /// Returns an identity or budget error when the policy does not describe
    /// the registered Plugin and its executable reservation.
    pub fn try_new(
        plugin_id: PluginId,
        plugin_version: &str,
        policy: OutputPolicyV1,
        budget: ExecutableBudgetPolicyV1,
    ) -> Result<Self, OutputAdmissionErrorV1> {
        if policy.fields().plugin_id != plugin_id {
            return Err(OutputAdmissionErrorV1::PluginMismatch);
        }
        if policy.fields().plugin_version != plugin_version {
            return Err(OutputAdmissionErrorV1::PluginVersionMismatch);
        }
        if policy.fields().executable_profile_hash != budget.digest() {
            return Err(OutputAdmissionErrorV1::PolicyIdentityMismatch);
        }
        let Some(cpu_reservations_us) = budget
            .fields()
            .plugin_cpu_reservations
            .iter()
            .find(|row| row.plugin_id == plugin_id)
            .map(|row| row.cpu_reservations_us)
        else {
            return Err(OutputAdmissionErrorV1::MissingCpuReservation);
        };
        Ok(Self {
            plugin_id,
            policy_digest: policy.digest(),
            policy,
            budget,
            cpu_reservations_us,
            usage: Mutex::new(AdmissionUsage::default()),
        })
    }

    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    #[must_use]
    pub const fn policy_digest(&self) -> Hash {
        self.policy_digest
    }

    #[must_use]
    pub const fn policy(&self) -> &OutputPolicyV1 {
        &self.policy
    }

    #[must_use]
    pub const fn budget(&self) -> &ExecutableBudgetPolicyV1 {
        &self.budget
    }

    pub(crate) fn reset_usage(&self) {
        *self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = AdmissionUsage::default();
    }

    /// Validate every draft against declarations and the complete step budget.
    ///
    /// # Errors
    /// Returns a declaration or resource-limit error when any draft exceeds
    /// the bound policy.
    pub fn validate_batch(&self, drafts: &[EventDraft]) -> Result<(), OutputAdmissionErrorV1> {
        let previous = *self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut counts = previous.events;
        let mut bytes = previous.bytes;
        for draft in drafts {
            let Some(declaration) = self
                .policy
                .fields()
                .output_declarations
                .iter()
                .find(|declaration| declaration.event_type() == draft.event_type.as_str())
            else {
                return Err(OutputAdmissionErrorV1::MissingDeclaration {
                    event_type: draft.event_type.as_str().to_owned(),
                });
            };
            let payload_bytes = draft.payload.len();
            let event_limit = declaration
                .max_bytes()
                .min(self.budget.fields().max_event_bytes);
            if payload_bytes > event_limit as usize {
                return Err(OutputAdmissionErrorV1::EventBytesExceeded {
                    event_type: draft.event_type.as_str().to_owned(),
                    requested: payload_bytes,
                    limit: event_limit,
                });
            }
            let level = match declaration.fidelity() {
                OutputFidelityV1::L0 => 0,
                OutputFidelityV1::L1 => 1,
                OutputFidelityV1::L2 => 2,
            };
            counts[level] = counts[level].saturating_add(1);
            bytes[level] = bytes[level].saturating_add(payload_bytes as u64);
        }

        for (level_index, budget) in self.budget.fields().fidelity_budgets.iter().enumerate() {
            let level: u8 = match level_index {
                0 => 0,
                1 => 1,
                _ => 2,
            };
            if counts[level_index] > u64::from(budget.max_events) {
                return Err(OutputAdmissionErrorV1::EventCountExceeded {
                    level,
                    requested: counts[level_index],
                    limit: budget.max_events,
                });
            }
            if bytes[level_index] > budget.max_bytes {
                return Err(OutputAdmissionErrorV1::BatchBytesExceeded {
                    level,
                    requested: bytes[level_index],
                    limit: budget.max_bytes,
                });
            }
            let cpu = counts[level_index]
                .saturating_mul(u64::from(self.cpu_reservations_us[level_index]));
            if cpu > u64::from(budget.max_cpu_us) {
                return Err(OutputAdmissionErrorV1::CpuExceeded {
                    level,
                    requested: cpu,
                    limit: budget.max_cpu_us,
                });
            }
        }
        *self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = AdmissionUsage {
            events: counts,
            bytes,
        };
        Ok(())
    }
}
