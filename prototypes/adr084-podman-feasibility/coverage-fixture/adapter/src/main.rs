use std::env;
use std::fs;
use std::thread;
use std::time::Duration;

#[used]
#[unsafe(no_mangle)]
pub static __llvm_profile_filename: [u8; b"/work/adapter-%m%c.profraw\0".len()] =
    *b"/work/adapter-%m%c.profraw\0";

fn live_descriptors() -> Vec<i32> {
    let entries = fs::read_dir("/proc/self/fd")
        .expect("read descriptor directory")
        .map(|entry| {
            entry
                .expect("read descriptor entry")
                .file_name()
                .to_string_lossy()
                .parse::<i32>()
                .expect("numeric descriptor")
        })
        .collect::<Vec<_>>();
    let mut live = entries
        .into_iter()
        .filter(|descriptor| fs::read_link(format!("/proc/self/fd/{descriptor}")).is_ok())
        .collect::<Vec<_>>();
    live.sort_unstable();
    live
}

fn before_termination(mode: &str) -> u64 {
    if mode == "kill" { 73 } else { 29 }
}

#[inline(never)]
fn deliberately_uncovered_adapter_region() -> u64 {
    101
}

fn main() {
    let mode = env::args().nth(1).expect("clean or kill mode");
    assert!(mode == "clean" || mode == "kill");
    let environment = env::vars_os().collect::<Vec<_>>();
    assert!(
        environment.is_empty(),
        "adapter environment is not empty: {environment:?}"
    );
    assert_eq!(live_descriptors(), vec![0, 1, 2]);
    let mappings = fs::read_to_string("/proc/self/maps").expect("read adapter mappings");
    assert!(mappings.contains("/work/adapter-"));
    let token = before_termination(&mode);
    eprintln!("ADAPTER_READY mode={mode} token={token} fds=0,1,2");
    if mode == "clean" {
        return;
    }
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
