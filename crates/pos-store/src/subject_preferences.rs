//! Fresh-append privacy policy for ADR-097 revision 4 B4.

use pos_core::{CoreError, EntityId, KeyRegistryStateV1, KeyRoleV1};

/// Check against the adapter's current validated registry, never a cached
/// subject classification. Records include every lifecycle state and are
/// retained permanently; validation also requires a record for each epoch
/// high-water entry.
pub(crate) fn ensure_plaintext_preference_allowed(
    registry: Option<&KeyRegistryStateV1>,
    entity: EntityId,
    event_type: &str,
) -> Result<(), CoreError> {
    if event_type != "persona.preference" {
        return Ok(());
    }
    let owner = format!(
        "subject:{:032x}",
        u128::from_be_bytes(entity.inner().to_bytes())
    );
    let subject = registry.is_some_and(|registry| {
        registry.key_records().any(|record| {
            record.identity.role == KeyRoleV1::SubjectDataEncryption
                && record.identity.owner_id.as_str() == owner
        })
    });
    if subject {
        Err(CoreError::SubjectPlaintextPreferenceRefused)
    } else {
        Ok(())
    }
}
