//! The process hardening: non-dumpable and no core files.

use pos_owner_ctap::harden_process;
use rustix::process::{dumpable_behavior, getrlimit, DumpableBehavior, Resource, Rlimit};

#[test]
fn hardening_makes_the_process_non_dumpable_without_core_files() {
    assert_eq!(harden_process(), Ok(()));
    assert_eq!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable));
    assert_eq!(
        getrlimit(Resource::Core),
        Rlimit {
            current: Some(0),
            maximum: Some(0)
        }
    );
}
