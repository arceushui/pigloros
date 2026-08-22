#![no_main]

use libfuzzer_sys::fuzz_target;
use piglor_gateway::{ActionRequest, CreateTimelineRequest, EventsQuery, SignalRequest};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<CreateTimelineRequest>(data);
    let _ = serde_json::from_slice::<ActionRequest>(data);
    let _ = serde_json::from_slice::<SignalRequest>(data);
    let _ = serde_json::from_slice::<EventsQuery>(data);
});
