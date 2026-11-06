//! Thin owner dispatcher; errors use the closed owner-bridge taxonomy.

fn main() -> Result<(), pos_owner_bridge::BridgeError> {
    piglor_owner::run()
}
