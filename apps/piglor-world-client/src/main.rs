#[cfg(not(target_arch = "wasm32"))]
fn main() {
    if let Err(error) = piglor_world_client::run_native() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}
