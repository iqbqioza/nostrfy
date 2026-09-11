//! anyhow-based error handling shared across the crate.
//!
//! Every fallible function returns `anyhow::Result`, so the `?` operator
//! carries I/O, JSON, database, crypto and hex failures with their sources
//! intact. Two sentinel types preserve the branches that used to match on
//! enum variants: [`ConfigError`] (CLI configuration failures) and
//! [`StorageFull`] (disk-full guards). Match on them with
//! `err.downcast_ref::<...>()` / `err.is::<...>()`, never on strings.

pub type Result<T> = anyhow::Result<T>;

/// A configuration failure. Displays with the historical `config error: `
/// prefix so CLI output stays unchanged.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// The storage backend is out of space: the free space on the filesystem
/// hosting the Blossom blobs (or the LMDB map) dropped below the
/// configured margin.
#[derive(Debug)]
pub struct StorageFull;

impl std::fmt::Display for StorageFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage is full")
    }
}

impl std::error::Error for StorageFull {}

/// Builds a [`ConfigError`] as an `anyhow::Error`.
pub fn config_err(msg: impl Into<String>) -> anyhow::Error {
    ConfigError(msg.into()).into()
}

/// Builds a [`StorageFull`] as an `anyhow::Error`.
pub fn storage_full() -> anyhow::Error {
    StorageFull.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinels_display_the_historical_messages() {
        assert_eq!(
            config_err("bad value").to_string(),
            "config error: bad value"
        );
        assert_eq!(storage_full().to_string(), "storage is full");
    }

    #[test]
    fn sentinels_downcast_back() {
        let e = config_err("bad value");
        assert_eq!(
            e.downcast_ref::<ConfigError>().map(|e| e.0.as_str()),
            Some("bad value")
        );
        let e = storage_full();
        assert!(e.is::<StorageFull>());
        let e = anyhow::anyhow!("plain failure");
        assert!(e.downcast_ref::<ConfigError>().is_none());
        assert!(!e.is::<StorageFull>());
    }
}
