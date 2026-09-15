//! Final root-owned sandbox selector process from ADR-069.

use pos_reference::root_selector::RootSelectorRuntime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    RootSelectorRuntime::activate()?.serve()?;
    Ok(())
}
