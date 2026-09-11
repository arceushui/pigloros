//! Fixed ADR-069 root-selector executable.

fn main() -> Result<(), pos_reference::selector::SelectorBoundaryError> {
    pos_reference::run_fixed_root_selector()
}
