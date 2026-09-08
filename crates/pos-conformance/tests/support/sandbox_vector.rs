use std::path::Path;

pub fn verify_and_materialize_vector(
    name: &str,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let filename = format!("{name}.cbor");
    if let Some(root) = std::env::var_os("SANDBOX_PROVIDER_VECTOR_OUTPUT") {
        std::fs::create_dir_all(&root)?;
        std::fs::write(Path::new(&root).join(&filename), bytes)?;
    }
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/sandbox-provider-v1")
        .join(filename);
    let existing = match std::fs::read(&committed) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("committed vector {} is missing", committed.display()).into());
        }
        Err(error) => {
            return Err(format!(
                "committed vector {} is unreadable: {error}",
                committed.display()
            )
            .into());
        }
    };
    if existing != bytes {
        return Err(format!("committed vector {} has drifted", committed.display()).into());
    }
    Ok(())
}
