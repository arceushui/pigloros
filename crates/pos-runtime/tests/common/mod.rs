// Staged-executor test helpers shared by the `staged_executor` and
// `staged_executor_quarantine` binaries, which both use every item here.
//
// Each binary `include!`s this file, so the helpers are private items at its
// crate root: a `mod common;` would need `pub` or `pub(super)` items, which
// `unreachable_pub` and `clippy::redundant_pub_crate` reject in a test crate.
// Paths are fully qualified so the including file's imports never clash.

/// Threads of this process named as the staged-fold worker. Other test
/// threads start and end concurrently, so only the worker's name counts.
///
/// The worker names itself as it starts, which can trail `acquire` under a
/// sanitizer, so this waits up to about 5 s for exactly one to appear.
fn worker_threads() -> usize {
    let mut seen = named_worker_threads();
    let mut polls = 0;
    while seen != 1 && polls < 1_000 {
        std::thread::sleep(std::time::Duration::from_millis(5));
        seen = named_worker_threads();
        polls += 1;
    }
    seen
}

/// Linux-only: reads `/proc/self/task`, and reports 0 where it is absent.
fn named_worker_threads() -> usize {
    std::fs::read_dir("/proc/self/task").map_or(0, |tasks| {
        tasks
            .filter_map(Result::ok)
            .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
            .filter(|name| name.trim_end() == pos_runtime::STAGED_FOLD_WORKER_NAME_V1)
            .count()
    })
}

/// Poll every 5 ms, at most `max_polls` times, until the process-global
/// executor health is `expected`. The caller asserts the final health.
fn await_health(expected: pos_runtime::ExecutorHealthV1, max_polls: u32) {
    let mut polls = 0;
    while pos_runtime::ExecutorHealthV1::current() != expected && polls < max_polls {
        std::thread::sleep(std::time::Duration::from_millis(5));
        polls += 1;
    }
}
