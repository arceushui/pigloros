//! Process startup helpers shared by every Gateway serve path.
//!
//! The binary's plain serve path and the local Fork-admission serve path open
//! their one erasure host, announce the TCP listener, and stop a partially
//! started Gateway after a bind failure in exactly the same way.

use std::{
    io::{self, Write as _},
    net::SocketAddr,
};

use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::StoreConfig;

use crate::Gateway;

/// Which Gateway store capability the recovered host must provide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayHostStoreV1 {
    /// The standard erasure host store.
    Standard,
    /// A store that also admits authenticated local `OwnTracks` ingress.
    OwnTracks,
}

/// Open and recover the one erasure host of `config` with `composition`.
///
/// # Errors
/// Returns a payload-free recovery error that carries only the closed host
/// error code.
pub fn open_recovered_erasure_host(
    config: StoreConfig,
    store: GatewayHostStoreV1,
    composition: &ErasureCoordinatorCompositionV1,
) -> io::Result<ErasureExecutionHostV1> {
    let limits = pos_core::ErasureRecoveryLimitsV1::compiled_maximum();
    let host = match store {
        GatewayHostStoreV1::Standard => {
            ErasureExecutionHostV1::open_with_authority(config, composition, limits)
        }
        GatewayHostStoreV1::OwnTracks => {
            ErasureExecutionHostV1::open_gateway_with_authority(config, composition, limits)
        }
    };
    host.map_err(|error| {
        io::Error::other(format!("erasure host recovery failed ({})", error.code()))
    })
}

/// Announce the bound HTTP listener on standard error.
pub fn announce_listening(addr: SocketAddr) {
    let mut output = io::stderr().lock();
    drop(writeln!(
        output,
        "piglor-gateway listening on http://{addr}"
    ));
}

/// Stop what a failed bind left started, then report the bind failure.
///
/// # Errors
/// Always returns `error`; a failed executor shutdown is not reported over it.
pub async fn stop_after_bind_failure(
    gateway: &Gateway,
    error: io::Error,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    drop(gateway.shutdown().await);
    Err(Box::new(error))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn startup_recovery_error_is_payload_free() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let unopenable = directory
            .path()
            .to_str()
            .ok_or("temporary directory path is not UTF-8")?
            .to_owned();
        for store in [GatewayHostStoreV1::Standard, GatewayHostStoreV1::OwnTracks] {
            let error = open_recovered_erasure_host(
                StoreConfig::Sqlite {
                    path: unopenable.clone(),
                },
                store,
                &ErasureCoordinatorCompositionV1::closed(),
            )
            .err()
            .ok_or("an unopenable store recovered")?;
            assert!(error
                .to_string()
                .starts_with("erasure host recovery failed ("));
        }
        Ok(())
    }
}
