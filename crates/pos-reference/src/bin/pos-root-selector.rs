//! Final root-owned sandbox selector process from ADR-069.

use pos_reference::root_selector::RootSelectorRuntime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    RootSelectorRuntime::activate()
        .and_then(RootSelectorRuntime::serve)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    #[test]
    fn entrypoint_fails_closed_without_the_fixed_root_installation() {
        assert!(super::main().is_err());
    }
}
