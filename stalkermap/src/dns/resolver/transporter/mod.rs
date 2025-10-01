//! # DNS Transporter
//!
//! The `transporter` module manages the global list of DNS servers used for record
//! resolution by **stalkermap**. It exposes a sensible default list of public resolvers and allows
//! callers to replace it with a custom list at runtime.
//!
//! This layer acts as a lightweight transport backend for resolution logic: it
//! provides a concurrent, efficient way to read the active server list from many
//! threads while allowing occasional, safe updates.
//!
//! These servers are reliable, widely-used and independent of the user's ISP.
//!
//! //! ## Default servers
//!
//! By default, the following resolvers are used:
//!
//! - `8.8.8.8:53`  
//! - `8.8.4.4:53`  
//! - `[2001:4860:4860::8888]:53`  
//! - `[2001:4860:4860::8844]:53`  
//! - `1.1.1.1:53`  
//! - `1.0.0.1:53`  
//! - `9.9.9.9:53`  
//! - `149.112.112.112:53`
//!
//! ## Public API
//!
//! - `get_servers()`  
//!   Returns an `Arc<Vec<String>>` with the currently active servers. If a custom
//!   list has been set it is returned; otherwise the default list is returned.
//!
//! - `set_servers(list: Vec<&str>) -> Result<(), TransporterErrors>`  
//!   Replaces the active server list with `list`. Every entry must be a valid
//!   `SocketAddr` (e.g. `ip:port` or `[ipv6]:port`). Returns `Err` if any entry
//!   is invalid.
//!
//! - `reset_servers()`  
//!   Removes any custom list and restores the default servers.
//!
//! - `has_custom_servers() -> bool`  
//!   Returns `true` if a custom list is currently active, otherwise `false`.
//!
//! ## Example
//!
//! ```rust,no_run
//! use stalkermap::dns::resolver::transporter::{get_servers, set_servers, reset_servers, has_custom_servers};
//!
//! // Get the default list
//! let defaults = get_servers();
//! println!("Default servers: {:?}", defaults);
//! assert!(!has_custom_servers());
//!
//! // Set a custom list
//! set_servers(vec!["8.8.8.8:53", "1.1.1.1:53"]).expect("failed to set servers");
//! let custom = get_servers();
//! println!("Custom servers: {:?}", custom);
//! assert!(has_custom_servers());
//!
//! // Reset to defaults
//! reset_servers();
//! let again = get_servers();
//! println!("Servers after reset: {:?}", again);
//! assert!(!has_custom_servers());
//! ```
//!
//! ## Concurrency & performance
//!
//! - `get_servers()` is fast for the common case: it returns an
//!   `Arc` clone of the active list so thousands of concurrent readers are cheap.
//! - `set_servers()` / `reset_servers()` take a write lock briefly to swap the
//!   active list.
//!
//! This design is optimized for scanning workloads: many repeated read operations
//! (DNS queries) with at most occasional writes (changing the server list).
//!
//! ## Implementation notes
//!
//! - The module keeps a static slice with default servers and a `RwLock<Option<Arc<Vec<String>>>>`
//!   for an optional custom list.
//! - Validation of entries uses `SocketAddr` parsing to ensure correctness before
//!   swapping lists.
//! - The API returns owned `Arc<Vec<String>>` for easy, zero-copy sharing across
//!   worker threads.
//!
//! ## Usage guidance
//!
//! - If you require a different set of resolvers (e.g. private resolvers, VPN-specific),
//!   call `set_servers()` once at startup or when configuration changes.
//!
//! The module is intentionally minimal and focused: it does *not* perform network I/O.
//! It only supplies validated, shared server addresses for whatever transport layer
//! (UDP/TCP/DoT/DoH) you choose to implement separately.
use std::net::SocketAddr;
use std::sync::Arc;
use std::{error::Error, fmt::Display, sync::RwLock};

/// Static list of public DNS resolvers used as defaults.
static DEFAULT_SERVERS: &[&str] = &[
    "8.8.8.8:53",
    "8.8.4.4:53",
    "[2001:4860:4860::8888]:53",
    "[2001:4860:4860::8844]:53",
    "1.1.1.1:53",
    "1.0.0.1:53",
    "9.9.9.9:53",
    "149.112.112.112:53",
];

/// Global container for a custom DNS server list.
///
/// Uses a `RwLock` for safe concurrent access.
/// If `None`, the default list is used.
static CUSTOM_SERVERS: RwLock<Option<Arc<Vec<String>>>> = RwLock::new(None);

/// Returns the currently active list of DNS servers.
///
/// If a custom list has been set with [`set_servers`], that list is returned.
pub fn get_servers() -> Arc<Vec<String>> {
    let custom = CUSTOM_SERVERS.read().unwrap_or_else(|e| e.into_inner());
    if let Some(list) = &*custom {
        Arc::clone(list)
    } else {
        Arc::new(DEFAULT_SERVERS.iter().map(|s| s.to_string()).collect())
    }
}

/// Replaces the active server list with the given `list`.
///
/// Every entry must parse as a valid [`SocketAddr`] (e.g. `"ip:port"` or `"[ipv6]:port"`).
///
/// Returns:
/// - `Ok(())` if the list was successfully set.
/// - `Err(TransporterErrors::InvalidServer)` if any entry is invalid.
pub fn set_servers(list: Vec<&str>) -> Result<(), TransporterErrors> {
    for name in &list {
        if name.parse::<SocketAddr>().is_err() {
            return Err(TransporterErrors::InvalidServer(name.to_string()));
        }
    }
    let mut custom = CUSTOM_SERVERS.write().unwrap_or_else(|e| e.into_inner());
    *custom = Some(Arc::new(list.iter().map(|s| s.to_string()).collect()));
    Ok(())
}

/// Resets the server list to the built-in defaults.
///
/// This removes any previously set custom list.
pub fn reset_servers() {
    let mut custom = CUSTOM_SERVERS.write().unwrap_or_else(|e| e.into_inner());
    *custom = None;
}

/// Returns `true` if a custom list of servers is currently active.
///
/// Returns `false` if only the default list is in use.
pub fn has_custom_servers() -> bool {
    let custom = CUSTOM_SERVERS.read().unwrap_or_else(|e| e.into_inner());
    (*custom).is_some()
}

/// Errors that can occur when setting the server list.
#[derive(Debug)]
pub enum TransporterErrors {
    /// Raised when a provided server string could not be parsed into a valid [`SocketAddr`].
    InvalidServer(String),
}

impl Display for TransporterErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransporterErrors::InvalidServer(s) => write!(f, "The server {} is invalid", s),
        }
    }
}

impl Error for TransporterErrors {}
