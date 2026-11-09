#![cfg(windows)]
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::LoopbackPort as _;

use crate::adapter::loopback::SharedLoopback;
use crate::adapter::surface::Surface;

pub(super) fn worker_stage(worker: usize, stage: &str) {
    let _logged_or_unavailable = writeln!(
        std::io::stderr(),
        "NATIVE_WORKER_RETIRE worker={worker} stage={stage}",
    );
}

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

    pub(super) fn update(
        &mut self,
        stage: &str,
        surface: &Surface,
        driver: &CeremonyDriver,
        loopback: &SharedLoopback,
    ) {
        let served = loopback.served();
        let progress = format!(
            "stage={stage} posts={} request_clear={} receipt={:?} reads={:?} served={} integrity={} {}",
            driver.posts(),
            driver.request_clear(),
            driver
                .first_receipt_at()
                .map(|at| at.saturating_duration_since(self.started)),
            loopback.received_request_count(),
            served.count,
            served.integrity_ok,
            surface.fixture_progress(),
        );
        self.report(progress, Some(loopback));
    }

    pub(super) fn queued(&mut self, surface: &Surface) {
        self.report(
            format!("stage=before-plan {}", surface.fixture_progress()),
            None,
        );
    }

    fn report(&mut self, progress: String, loopback: Option<&SharedLoopback>) {
        let now = Instant::now();
        if progress != self.previous || now.duration_since(self.reported) >= Duration::from_secs(5)
        {
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "NATIVE_PROGRESS case={} elapsed={:?} {progress} listener={:?}",
                self.case,
                now.duration_since(self.started),
                loopback.map(SharedLoopback::observation),
            );
            self.previous = progress;
            self.reported = now;
        }
    }
}
