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
    let mut returned = reply.driver;
    let mut quarantined = was_quarantined;
    surface.abandon_opening();
    while quarantined || !surface.idle() {
        if quarantined {
            let polled = keeper.poll(|driver| {
                observe(surface, driver, loopback);
                driver.poll_cleanup(&mut readiness::env(surface, loopback, store))
            });
            quarantined = polled.remaining;
            if let Some(driver) = polled.driver {
                returned = Some(driver);
            }
        } else {
            let _retired_or_retained = surface.poll_failed_open();
        }
        if quarantined || !surface.idle() {
            readiness::pump_retaining(surface);
        }
    }
    // Consumption releases the plan's Zeroizing fields at the same boundary
    // used by the owner bridge, after the native Surface has retired.
    if let Some(driver) = returned {
        drop(driver.into_slots());
    }
    was_quarantined
}
