use pos_sandboxd::AttemptLimitEventSource;

#[test]
fn limit_event_sources_expose_exact_kernel_filenames() {
    assert_eq!(
        AttemptLimitEventSource::MemoryEventsLocal.file_name(),
        "memory.events.local"
    );
    assert_eq!(
        AttemptLimitEventSource::MemorySwapEvents.file_name(),
        "memory.swap.events"
    );
    assert_eq!(
        AttemptLimitEventSource::PidsEventsLocal.file_name(),
        "pids.events.local"
    );
    assert_eq!(AttemptLimitEventSource::CpuStat.file_name(), "cpu.stat");
}
