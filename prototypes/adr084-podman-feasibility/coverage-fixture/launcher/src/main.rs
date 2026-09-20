use std::env;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::fd::IntoRawFd;
use std::os::raw::{c_int, c_long};
use std::ptr;

#[used]
#[unsafe(no_mangle)]
pub static __llvm_profile_filename: [u8; b"/work/launcher-%m%c.profraw\0".len()] =
    *b"/work/launcher-%m%c.profraw\0";

unsafe extern "C" {
    fn clearenv() -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
}

const AT_EMPTY_PATH: c_int = 0x1000;
#[cfg(target_arch = "x86_64")]
const SYS_EXECVEAT: c_long = 322;
#[cfg(target_arch = "aarch64")]
const SYS_EXECVEAT: c_long = 281;

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

fn before_exec(mode: &str) -> u64 {
    if mode == "kill" { 41 } else { 17 }
}

#[inline(never)]
fn deliberately_uncovered_launcher_region() -> u64 {
    99
}

fn main() {
    let mode = env::args().nth(1).expect("clean or kill mode");
    assert!(mode == "clean" || mode == "kill");
    assert_eq!(unsafe { clearenv() }, 0);
    assert!(env::vars_os().next().is_none(), "launcher environment is not empty");
    let adapter = OpenOptions::new()
        .read(true)
        .open("/adapter")
        .expect("open held adapter")
        .into_raw_fd();
    assert_eq!(live_descriptors(), vec![0, 1, 2, adapter]);
    let mappings = fs::read_to_string("/proc/self/maps").expect("read launcher mappings");
    assert!(mappings.contains("/work/launcher-"));
    let token = before_exec(&mode);
    eprintln!("LAUNCHER_BEFORE_EXEC mode={mode} token={token} fds=0,1,2,{adapter}");

    let program = CString::new("coverage-adapter").expect("program argument");
    let mode_argument = CString::new(mode).expect("mode argument");
    let arguments = [program.as_ptr(), mode_argument.as_ptr(), ptr::null()];
    let environment = [ptr::null()];
    let empty_path = CString::new("").expect("empty execveat path");
    let result = unsafe {
        syscall(
            SYS_EXECVEAT,
            adapter,
            empty_path.as_ptr(),
            arguments.as_ptr(),
            environment.as_ptr(),
            AT_EMPTY_PATH,
        )
    };
    panic!("execveat failed with result {result}: {}", std::io::Error::last_os_error());
}
