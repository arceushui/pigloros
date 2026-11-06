//! Thin owner dispatcher; errors use the closed owner-bridge taxonomy.

// The integration test executes this real entry point. Libtest supplies its
// own main, so no unused second entry-point function is compiled into it.
#[cfg(not(test))]
fn main() -> Result<(), pos_owner_bridge::BridgeError> {
    piglor_owner::run()
}
