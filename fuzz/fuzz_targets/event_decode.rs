#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _decoded: Result<pos_core::Event, _> = ciborium::from_reader(Cursor::new(data));
});
