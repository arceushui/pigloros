#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::ceremony::plan::Verified;
use pos_owner_bridge::{BridgeError, QuarantineKeeper};

use super::readiness;
use crate::adapter::{loopback::SharedLoopback, store::WindowsCleanupStore, surface::Surface};

pub(super) fn retire(
    surface: &mut Surface,
    loopback: &mut SharedLoopback,
    store: &mut WindowsCleanupStore,
    driver: CeremonyDriver,
    result: Result<Verified, BridgeError>,
    mut observe: impl FnMut(&Surface, &CeremonyDriver, &SharedLoopback),
) -> bool {
    let mut keeper = QuarantineKeeper::new();
    let reply = keeper.finish(driver, result);
    let was_quarantined = reply.driver.is_none();
    let mut quarantined = was_quarantined;
    surface.abandon_opening();
    while quarantined || !surface.idle() {
        if quarantined {
            quarantined = keeper
                .poll(|driver| {
                    observe(surface, driver, loopback);
                    driver.poll_cleanup(&mut readiness::env(surface, loopback, store))
                })
                .remaining;
        } else {
            let _retired_or_retained = surface.poll_failed_open();
        }
        if quarantined || !surface.idle() {
            readiness::pump_retaining(surface);
        }
    }
    was_quarantined
}
