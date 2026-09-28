//! Shared structural adapter identity used by MAA1 and AIR1/MAT1.

use crate::PluginId;

/// One admitted Plugin operation, before any owner-authority claim.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct AdapterContractKey<'a> {
    pub plugin_id: PluginId,
    pub adapter_id: &'a str,
    pub provider_id: &'a str,
    pub operation_id: &'a str,
    pub protocol_version: u64,
}

pub(super) fn valid_adapter_identity(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
