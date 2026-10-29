//! Fresh sysfs observations of the original boot-local device generations.
//! No block-device descriptor is opened: it could delay deferred removal.

use std::{fs, io::ErrorKind};

use super::{block_identity, BlockIdentity, HostKernel};
use crate::ImageActivationError;

impl HostKernel {
    pub(super) fn device_absent(
        &self,
        expected: BlockIdentity,
    ) -> Result<bool, ImageActivationError> {
        let rejected = ImageActivationError::ResourceAbsenceUnverified;
        let index = self.sys.join("dev/block");
        let path = index.join(format!("{}:{}", expected.device.0, expected.device.1));
        let first = block_identity(&path);
        let second = block_identity(&path);
        match (first, second) {
            (Some(first), Some(second))
                if first.device == expected.device && second.device == expected.device =>
            {
                // Incoherent valid samples may be a removal/reuse in progress.
                // Retry within the caller's original deadline. A generation
                // going backwards is contradictory, never absence.
                if first.diskseq < expected.diskseq || second.diskseq < expected.diskseq {
                    return Err(rejected);
                }
                Ok(first == second && second.diskseq > expected.diskseq)
            }
            _ => {
                // An absent attribute is not an absent device. Removal can
                // race either sample, so perform a fresh whole-device lookup.
                // Do not interpret an unavailable sysfs index as disappearance.
                match fs::metadata(&path) {
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        fs::read_dir(index).map(|_| true).map_err(|_| rejected)
                    }
                    _ => Err(rejected),
                }
            }
        }
    }
}
