//! anyhow-based error handling shared across the crate.

pub type Result<T> = anyhow::Result<T>;

/// Builds a configuration error while retaining a stable CLI prefix.
pub fn config_err(msg: impl Into<String>) -> anyhow::Error {
    anyhow::anyhow!("config error: {}", msg.into())
}

/// Builds a storage-full error.
pub fn storage_full() -> anyhow::Error {
    anyhow::anyhow!("storage is full")
}
