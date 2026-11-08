#![cfg(windows)]
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;

use crate::adapter::surface::Surface;

pub(super) struct Trace {
    case: u64,
    started: Instant,
    reported: Instant,
    previous: String,
}

impl Trace {
    pub(super) fn new(case: u64, started: Instant) -> Self {
        Self {
            case,
            started,
            reported: started,
            previous: String::new(),
        }
    }

    pub(super) fn update(&mut self, stage: &str, surface: &Surface, driver: &CeremonyDriver) {
        let progress = format!(
            "stage={stage} posts={} request_clear={} {}",
            driver.posts(),
            driver.request_clear(),
            surface.fixture_progress(),
        );
        let now = Instant::now();
        if progress != self.previous || now.duration_since(self.reported) >= Duration::from_secs(5)
        {
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "NATIVE_PROGRESS case={} elapsed={:?} {progress}",
                self.case,
                now.duration_since(self.started),
            );
            self.previous = progress;
            self.reported = now;
        }
    }
}
