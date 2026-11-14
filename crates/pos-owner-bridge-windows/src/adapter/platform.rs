#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge::{BridgeError, UnavailableCode};

/// Admission for the minimal owner executable selected by ADR-110 §1a.
///
/// # Errors
///
/// The accepted E16 profile refuses Windows owner operations until #741;
/// #399 supplies the actual owner adapter. This gate starts no ceremony.
pub const fn owner_startup() -> Result<(), BridgeError> {
    pos_owner_bridge::encryptor_lock::nonce_ledger_support(
        pos_owner_bridge::encryptor_lock::HOST_TARGET_OS,
    )
}

/// CPU capabilities required by the first Windows owner profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuFeatures {
    /// The processor reports the AES instruction extension.
    pub aes_ni: bool,
    /// The processor reports carry-less multiplication support.
    pub pclmulqdq: bool,
}

impl CpuFeatures {
    /// Observe the current processor through the standard library.
    #[must_use]
    pub fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                aes_ni: std::arch::is_x86_feature_detected!("aes"),
                pclmulqdq: std::arch::is_x86_feature_detected!("pclmulqdq"),
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self {
                aes_ni: false,
                pclmulqdq: false,
            }
        }
    }
}

/// Apply the accepted CPU requirement without making a hardware-qualification claim.
///
/// # Errors
///
/// Returns `CpuFeatures` when either required extension is absent.
pub const fn cpu_requirements(features: CpuFeatures) -> Result<(), UnavailableCode> {
    if features.aes_ni && features.pclmulqdq {
        Ok(())
    } else {
        Err(UnavailableCode::CpuFeatures)
    }
}

/// Refuse a platform outside the first Windows desktop owner profile.
///
/// # Errors
///
/// Requires x64, a workstation OS with build 26100 or later, and both CPU
/// capabilities. Failed OS inspection returns `InterfaceUnavailable`.
#[cfg(target_arch = "x86_64")]
pub fn require_windows_profile() -> Result<(), BridgeError> {
    admit_observation(crate::Native::os_profile(), CpuFeatures::current())
}

/// Refuse architectures outside the selected x64 adapter profile.
///
/// # Errors
///
/// Always returns `Unavailable(PlatformUnsupported)`.
#[cfg(not(target_arch = "x86_64"))]
pub const fn require_windows_profile() -> Result<(), BridgeError> {
    Err(BridgeError::Unavailable(
        UnavailableCode::PlatformUnsupported,
    ))
}

#[cfg(any(target_arch = "x86_64", test))]
fn admit_observation(
    profile: Result<(String, String), ()>,
    cpu: CpuFeatures,
) -> Result<(), BridgeError> {
    let (build, product) =
        profile.map_err(|()| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))?;
    admit(&build, &product, cpu)
}

#[cfg(any(target_arch = "x86_64", test))]
fn admit(build: &str, product: &str, cpu: CpuFeatures) -> Result<(), BridgeError> {
    let build = build
        .parse::<u32>()
        .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))?;
    if build < 26_100 || !product.eq_ignore_ascii_case("WinNT") {
        return Err(BridgeError::Unavailable(
            UnavailableCode::PlatformUnsupported,
        ));
    }
    cpu_requirements(cpu).map_err(BridgeError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_admission_is_capability_based_and_fails_closed() {
        assert_eq!(
            owner_startup(),
            Err(BridgeError::Unavailable(
                UnavailableCode::PlatformUnsupported
            ))
        );
        let available = CpuFeatures {
            aes_ni: true,
            pclmulqdq: true,
        };
        assert_eq!(
            admit_observation(Err(()), available),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        assert_eq!(
            admit_observation(Ok(("26100".into(), "WinNT".into())), available),
            Ok(())
        );
        for build in ["26100", "26200", "4294967295"] {
            assert_eq!(admit(build, "WinNT", available), Ok(()));
        }
        for (build, product) in [
            ("26099", "WinNT"),
            ("26100", "ServerNT"),
            ("26100", "LanmanNT"),
        ] {
            assert_eq!(
                admit(build, product, available),
                Err(BridgeError::Unavailable(
                    UnavailableCode::PlatformUnsupported
                ))
            );
        }
        assert_eq!(
            admit("invalid", "WinNT", available),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        assert_eq!(
            admit(
                "26100",
                "WinNT",
                CpuFeatures {
                    aes_ni: false,
                    pclmulqdq: true
                }
            ),
            Err(BridgeError::Unavailable(UnavailableCode::CpuFeatures))
        );
    }
}
