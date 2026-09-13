#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! Fixed ADR-069 root-selector executable.

fn main() -> Result<(), pos_reference::selector::SelectorBoundaryError> {
    pos_reference::run_fixed_root_selector()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #[test]
    fn fixed_binary_fails_closed_without_installed_root_state() {
        assert!(super::main().is_err());
    }
}
