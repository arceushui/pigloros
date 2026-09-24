//! Host measurement of the running, statically linked process image.

use crate::WorldInstallationErrorV1;

/// A process-image digest minted only by the installed runtime host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasuredProcessImageV1 {
    digest: [u8; 32],
}

impl MeasuredProcessImageV1 {
    /// Measure the executable associated with this running Linux process.
    ///
    /// # Errors
    /// Fails closed when the host cannot read a stable, nonempty process image.
    pub fn capture() -> Result<Self, WorldInstallationErrorV1> {
        #[cfg(target_os = "linux")]
        {
            Self::capture_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(WorldInstallationErrorV1::UnsupportedPlatform)
        }
    }

    /// The BLAKE3-256 digest of the measured executable bytes.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    #[cfg(target_os = "linux")]
    fn capture_linux() -> Result<Self, WorldInstallationErrorV1> {
        use std::fs::File;
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;

        let mut image = File::open("/proc/self/exe")
            .map_err(|_| WorldInstallationErrorV1::MeasurementOpenFailed)?;
        let before = image
            .metadata()
            .map_err(|_| WorldInstallationErrorV1::MeasurementMetadataFailed)?;
        if before.len() == 0 {
            return Err(WorldInstallationErrorV1::MeasurementEmpty);
        }
        let mut hasher = blake3::Hasher::new();
        let mut read_count = 0_u64;
        let mut chunk = [0_u8; 64 * 1024];
        loop {
            let len = image
                .read(&mut chunk)
                .map_err(|_| WorldInstallationErrorV1::MeasurementReadFailed)?;
            if len == 0 {
                break;
            }
            read_count = read_count
                .checked_add(u64::try_from(len).unwrap_or(u64::MAX))
                .ok_or(WorldInstallationErrorV1::MeasurementChanged)?;
            hasher.update(&chunk[..len]);
        }
        let after = image
            .metadata()
            .map_err(|_| WorldInstallationErrorV1::MeasurementMetadataFailed)?;
        if read_count != before.len()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(WorldInstallationErrorV1::MeasurementChanged);
        }
        Ok(Self {
            digest: *hasher.finalize().as_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn process_image_digest_matches_independent_executable_read() {
        let measured = MeasuredProcessImageV1::capture().expect("running executable measured");
        let bytes = std::fs::read("/proc/self/exe").expect("running executable read");
        assert!(!bytes.is_empty());
        assert_eq!(measured.digest(), *blake3::hash(&bytes).as_bytes());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_live_measurement_fails_closed() {
        assert_eq!(
            MeasuredProcessImageV1::capture(),
            Err(WorldInstallationErrorV1::UnsupportedPlatform)
        );
    }
}
