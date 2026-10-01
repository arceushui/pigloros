//! Stream image content checks from the selector's retained SIC1 descriptors.

use std::fs::File;
use std::os::unix::fs::FileExt as _;

use super::{AdmittedSandboxImage, AdmittedSandboxProvider, SandboxAdmissionError};

impl AdmittedSandboxProvider {
    /// Uses positional reads so concurrent admissions cannot move each other's
    /// file cursors. SIC1 owns the immutable files and their retention lifetime.
    pub(crate) fn admit_image_files(
        &self,
        manifest_bytes: &[u8],
        root_image: &File,
        executable: &File,
        executable_length: u64,
    ) -> Result<AdmittedSandboxImage, SandboxAdmissionError> {
        self.admit_image_by(manifest_bytes, |image| {
            super::image_gpt::verify(root_image, image)?;
            verify_file(
                root_image,
                image.root_image_length,
                image.root_image_blake3_digest,
            )?;
            verify_file(
                executable,
                executable_length,
                image.executable_blake3_digest,
            )
        })
    }
}

fn verify_file(
    file: &File,
    expected_length: u64,
    expected_digest: [u8; 32],
) -> Result<(), SandboxAdmissionError> {
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0;
    loop {
        let read = file
            .read_at(&mut buffer, offset)
            .map_err(|_| SandboxAdmissionError::ArtifactMismatch)?;
        if read == 0 {
            if offset != expected_length || hasher.finalize().as_bytes() != &expected_digest {
                return Err(SandboxAdmissionError::ArtifactMismatch);
            }
            return Ok(());
        }
        offset += read as u64;
        if offset > expected_length {
            return Err(SandboxAdmissionError::ArtifactMismatch);
        }
        hasher.update(&buffer[..read]);
    }
}
