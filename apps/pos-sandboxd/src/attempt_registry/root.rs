//! The bounded private activation-intent stage committed before unit start.
//!
//! PAI3 extends PAI2 with twelve little-endian u64 facts, the exact 68-byte
//! attempt root path, a 129-byte mapper UUID slot and a 16-byte loop-name slot.
//! Text slots are NUL-terminated and zero-padded. These are retained claims,
//! never fresh kernel evidence or ADR-069's separate lifecycle binding.

use super::{
    directory::{PreparedAttemptDirectory, DIRECTORY_RECORD_SIZE},
    PlannedAttemptIntent, SystemdAttemptRegistryError,
};
use crate::{transient_unit::attempt_root_path, RootResourceIdentity};

const VALUES_END: usize = DIRECTORY_RECORD_SIZE + 12 * 8;
const PATH_END: usize = VALUES_END + 68;
const UUID_END: usize = PATH_END + 129;
pub(super) const ROOT_RECORD_SIZE: usize = UUID_END + 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RootRecord([u8; ROOT_RECORD_SIZE]);

impl RootRecord {
    pub(super) fn new(
        directory: &PreparedAttemptDirectory,
        identity: &RootResourceIdentity,
    ) -> Result<Self, SystemdAttemptRegistryError> {
        let mut bytes = [0; ROOT_RECORD_SIZE];
        bytes[..DIRECTORY_RECORD_SIZE].copy_from_slice(&directory.directory_bytes());
        bytes[..4].copy_from_slice(b"PAI3");
        let (root_device, root_inode) = identity.root_identity();
        let (image_device, image_inode) = identity.image_identity();
        let (mapper, mapper_sequence) = identity.mapper_generation();
        let (loop_device, loop_sequence) = identity.loop_generation();
        for (slot, value) in bytes[DIRECTORY_RECORD_SIZE..VALUES_END]
            .chunks_exact_mut(8)
            .zip([
                identity.mount_id(),
                u64::from(root_device.0),
                u64::from(root_device.1),
                root_inode,
                image_device,
                image_inode,
                u64::from(mapper.0),
                u64::from(mapper.1),
                mapper_sequence,
                u64::from(loop_device.0),
                u64::from(loop_device.1),
                loop_sequence,
            ])
        {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        // VerifiedRootMount supplies only the fixed path for this attempt.
        bytes[VALUES_END..PATH_END].copy_from_slice(identity.root_directory().as_str().as_bytes());
        write_text(&mut bytes[PATH_END..UUID_END], identity.mapper_uuid())
            .and_then(|()| write_text(&mut bytes[UUID_END..], identity.loop_name()))
            .and_then(|()| Self::decode(bytes, directory.intent()))
    }

    /// The caller has already checked the PAI3 stage, length and planned prefix.
    pub(super) fn decode(
        bytes: [u8; ROOT_RECORD_SIZE],
        intent: &PlannedAttemptIntent,
    ) -> Result<Self, SystemdAttemptRegistryError> {
        let mut values = [0; 12];
        for (value, chunk) in values
            .iter_mut()
            .zip(bytes[DIRECTORY_RECORD_SIZE..VALUES_END].chunks_exact(8))
        {
            let mut word = [0; 8];
            word.copy_from_slice(chunk);
            *value = u64::from_le_bytes(word);
        }
        let root = attempt_root_path(intent.unit_name().attempt_component());
        if [0, 3, 5, 8, 11].iter().any(|index| values[*index] == 0)
            || [1, 2, 6, 7, 9, 10]
                .iter()
                .any(|index| values[*index] > u64::from(u32::MAX))
            || values[1..3] != values[6..8]
            || bytes[VALUES_END..PATH_END] != *root.as_bytes()
            || read_text(&bytes[PATH_END..UUID_END]).is_none()
            || read_text(&bytes[UUID_END..]).is_none()
        {
            return Err(SystemdAttemptRegistryError::InvalidIntent);
        }
        Ok(Self(bytes))
    }

    pub(super) const fn bytes(&self) -> &[u8; ROOT_RECORD_SIZE] {
        &self.0
    }
}

fn write_text(slot: &mut [u8], value: &str) -> Result<(), SystemdAttemptRegistryError> {
    if value.len() >= slot.len() || value.as_bytes().contains(&0) {
        return Err(SystemdAttemptRegistryError::InvalidIntent);
    }
    slot[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

fn read_text(slot: &[u8]) -> Option<&str> {
    slot.iter()
        .position(|byte| *byte == 0)
        .filter(|end| *end > 0 && slot[*end..].iter().all(|byte| *byte == 0))
        .and_then(|end| std::str::from_utf8(&slot[..end]).ok())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn text_slots_accept_the_exact_capacity_and_refuse_overflow_or_nul() {
        for capacity in [16, 129] {
            let text = "x".repeat(capacity - 1);
            let mut slot = vec![0; capacity];
            assert!(write_text(&mut slot, &text).is_ok());
            assert_eq!(read_text(&slot), Some(text.as_str()));
            assert!(write_text(&mut vec![0; capacity], &"x".repeat(capacity)).is_err());
            assert!(write_text(&mut vec![0; capacity], "a\0b").is_err());
        }
    }
}
