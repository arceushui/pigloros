//! Host measurement of the running, statically linked process image.

use crate::WorldInstallationErrorV1;

#[cfg(target_os = "linux")]
use std::io::{self, Read};

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ImageStamp {
    len: u64,
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(target_os = "linux")]
trait ImageReader: Read {
    fn stamp(&self) -> io::Result<ImageStamp>;
}

#[cfg(target_os = "linux")]
impl ImageReader for std::fs::File {
    fn stamp(&self) -> io::Result<ImageStamp> {
        use std::os::unix::fs::MetadataExt;

        let metadata = self.metadata()?;
        Ok(ImageStamp {
            len: metadata.len(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        })
    }
}

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
        Self::capture_from(|| std::fs::File::open("/proc/self/exe"), 0)
    }

    #[cfg(target_os = "linux")]
    fn capture_from<I: ImageReader>(
        open: impl FnOnce() -> io::Result<I>,
        initial_read_count: u64,
    ) -> Result<Self, WorldInstallationErrorV1> {
        let mut image = open().map_err(|_| WorldInstallationErrorV1::MeasurementOpenFailed)?;
        let before = image
            .stamp()
            .map_err(|_| WorldInstallationErrorV1::MeasurementMetadataFailed)?;
        if before.len() == 0 {
            return Err(WorldInstallationErrorV1::MeasurementEmpty);
        }
        let mut hasher = blake3::Hasher::new();
        let mut read_count = initial_read_count;
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            let len = image
                .read(&mut chunk)
                .map_err(|_| WorldInstallationErrorV1::MeasurementReadFailed)?;
            if len == 0 {
                break;
            }
            read_count = read_count
                .checked_add(len as u64)
                .ok_or(WorldInstallationErrorV1::MeasurementChanged)?;
            hasher.update(&chunk[..len]);
        }
        let after = image
            .stamp()
            .map_err(|_| WorldInstallationErrorV1::MeasurementMetadataFailed)?;
        if read_count != before.len || before != after {
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
    struct FakeImage {
        bytes: io::Cursor<Vec<u8>>,
        before: ImageStamp,
        after: ImageStamp,
        stamp_calls: std::cell::Cell<usize>,
        fail_stamp: Option<usize>,
        fail_read: bool,
    }

    #[cfg(target_os = "linux")]
    impl FakeImage {
        fn new(bytes: &[u8]) -> Self {
            let stamp = ImageStamp {
                len: bytes.len() as u64,
                dev: 1,
                ino: 2,
                mtime: 3,
                mtime_nsec: 4,
                ctime: 5,
                ctime_nsec: 6,
            };
            Self {
                bytes: io::Cursor::new(bytes.to_vec()),
                before: stamp,
                after: stamp,
                stamp_calls: std::cell::Cell::new(0),
                fail_stamp: None,
                fail_read: false,
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Read for FakeImage {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.fail_read {
                Err(io::Error::other("injected read failure"))
            } else {
                self.bytes.read(buf)
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl ImageReader for FakeImage {
        fn stamp(&self) -> io::Result<ImageStamp> {
            let call = self.stamp_calls.get() + 1;
            self.stamp_calls.set(call);
            if self.fail_stamp == Some(call) {
                Err(io::Error::other("injected metadata failure"))
            } else if call == 1 {
                Ok(self.before)
            } else {
                Ok(self.after)
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_image_measurement_rejects_incomplete_or_changed_reads() {
        assert_eq!(
            MeasuredProcessImageV1::capture_from(
                || -> io::Result<FakeImage> { Err(io::Error::other("open failed")) },
                0,
            ),
            Err(WorldInstallationErrorV1::MeasurementOpenFailed)
        );
        for call in [1, 2] {
            let mut image = FakeImage::new(b"image");
            image.fail_stamp = Some(call);
            assert_eq!(
                MeasuredProcessImageV1::capture_from(|| Ok(image), 0),
                Err(WorldInstallationErrorV1::MeasurementMetadataFailed)
            );
        }
        assert_eq!(
            MeasuredProcessImageV1::capture_from(|| Ok(FakeImage::new(b"")), 0),
            Err(WorldInstallationErrorV1::MeasurementEmpty)
        );
        let mut image = FakeImage::new(b"image");
        image.fail_read = true;
        assert_eq!(
            MeasuredProcessImageV1::capture_from(|| Ok(image), 0),
            Err(WorldInstallationErrorV1::MeasurementReadFailed)
        );
        assert_eq!(
            MeasuredProcessImageV1::capture_from(|| Ok(FakeImage::new(b"image")), u64::MAX),
            Err(WorldInstallationErrorV1::MeasurementChanged)
        );
        let mut image = FakeImage::new(b"image");
        image.before.len += 1;
        assert_eq!(
            MeasuredProcessImageV1::capture_from(|| Ok(image), 0),
            Err(WorldInstallationErrorV1::MeasurementChanged)
        );
        let mut image = FakeImage::new(b"image");
        image.after.ino += 1;
        assert_eq!(
            MeasuredProcessImageV1::capture_from(|| Ok(image), 0),
            Err(WorldInstallationErrorV1::MeasurementChanged)
        );
        assert_eq!(
            MeasuredProcessImageV1::capture_from(|| Ok(FakeImage::new(b"image")), 0)
                .map(MeasuredProcessImageV1::digest),
            Ok(*blake3::hash(b"image").as_bytes())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_image_digest_matches_independent_executable_read(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let measured = MeasuredProcessImageV1::capture()?;
        let bytes = std::fs::read("/proc/self/exe")?;
        assert!(!bytes.is_empty());
        assert_eq!(measured.digest(), *blake3::hash(&bytes).as_bytes());
        Ok(())
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
