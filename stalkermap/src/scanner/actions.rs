//! Defines the `Action` system used by the scanning engine.
//!
//! # Execution Flow
//! For each action in the task:
//!
//! - If `set_read_from_successfull_connection()` returns `false`, the action
//!   is called immediately after the TCP handshake via:
//!   [`execute_after_successfull_connection`](Action::execute_after_successfull_connection).
//!
//! - If it returns `true`, the engine performs a **single non-blocking read**
//!   on the socket and then calls:
//!   [`execute_after_successfull_connection_and_read`](Action::execute_after_successfull_connection_and_read),
//!   providing:
//!     - a slice containing the bytes successfully read,
//!     - the shared result map.
//!
//! This makes it easy to build actions for:
//! - simple port-state checks (like `IsPortOpen`),
//! - banner grabbing,
//! - protocol heuristics,
//! - service identification,
//! - custom user-defined logic.
//! # Example
//! ```rust,ignore
//! use stalkermap::actions::{Action, ActionIsPortOpen, actions};
//!
//! let todo = actions!(ActionIsPortOpen {}, YourCustomAction {});
//! ```
//!
//! The `actions!()` macro is provided for ergonomic construction of the
//! `Vec<Box<dyn Action>>` required by the scanning engine.
use std::collections::HashMap;

/// Creates a `Vec<Box<dyn Action>>` from a list of action expressions.
///
/// # Example
/// ```
/// let actions = actions!(
///     ActionIsPortOpen {},
///     MyCustomAction {},
/// );
/// ```
#[macro_export]
macro_rules! actions {
    ($($a:expr), * $(,)?) => {
        vec![$(Box::new($a) as Box<dyn Action>), *]
    }
}

/// Represents a single scanning action executed after a TCP connection.
///
/// Implementors provide:
/// - a unique [`name`](Action::name),
/// - whether the scanner should read data after connect,
/// - a handler for the “just connected” case,
/// - a handler for the “connected + read data” case.
///
/// # Threading
/// Actions must be:
/// - `Send` + `Sync`, so they can safely run inside asynchronous tasks,
/// - `'static`, because they are stored inside boxed trait objects.
///
/// All actions belonging to the same task share a single result map, which
/// allows actions to collaborate or reuse each other's output.
///
/// # Notes
/// - Actions should insert their results into `actions_results` under a key
///   matching `name()`.
/// - All actions in a task share the same result map.
pub trait Action: Send + Sync + 'static {
    /// Returns the static name of the action.
    ///
    /// This is used as the key when inserting values into
    /// `actions_results`.  
    /// Must be **unique** across all actions in a task.
    fn name(&self) -> &'static str;

    /// Indicates whether the engine should perform a non-blocking read
    /// immediately after a successful TCP connection.
    ///
    /// - If `false`, the engine will *not* read from the socket and will call
    ///   [`execute_after_successfull_connection`](Self::execute_after_successfull_connection).
    /// - If `true`, the engine performs a read and then calls
    ///   [`execute_after_successfull_connection_and_read`](Self::execute_after_successfull_connection_and_read).
    fn set_read_from_successfull_connection(&self) -> bool;

    /// Executed after a successful TCP connection **when the action does not
    /// require any socket data**.
    ///
    /// This is typically used for:
    /// - connectivity checks,
    /// - metadata actions,
    /// - timing or latency actions,
    /// - simple indicators where no read is required.
    fn execute_after_successfull_connection(
        &self,
        ctx: &ScanContext,
        actions_results: &mut HashMap<String, String>,
    );

    /// Executed after a successful TCP connection **when the action requested
    /// socket data to be read**.
    ///
    /// The engine supplies:
    /// - `ctx`: scan metadata (`target`, `port`, `task_id`),
    /// - `raw_data`: slice of the received bytes,
    /// - `actions_results`: shared mutable result map.
    ///
    /// Use this to implement:
    /// - banner grabbing,
    /// - protocol fingerprinting,
    /// - TLS/service detection,
    /// - any logic requiring access to initial server data.
    fn execute_after_successfull_connection_and_read(
        &self,
        ctx: &ScanContext,
        raw_data: &[u8],
        actions_results: &mut HashMap<String, String>,
    );
}

/// Basic action that simply reports whether the port is open.
///
/// This action does **not** request any socket read, because the successful
/// handshake itself is sufficient to confirm that the port is accepting
/// connections.
pub struct ActionIsPortOpen {}

impl Action for ActionIsPortOpen {
    fn name(&self) -> &'static str {
        "IsPortOpen"
    }
    fn set_read_from_successfull_connection(&self) -> bool {
        false
    }

    fn execute_after_successfull_connection(
        &self,
        ctx: &ScanContext,
        actions_results: &mut HashMap<String, String>,
    ) {
        actions_results.insert(self.name().to_string(), "open".to_string());
        actions_results.insert("target".to_string(), ctx.target_addr.to_string());
        actions_results.insert("port".to_string(), ctx.port.to_string());
    }

    fn execute_after_successfull_connection_and_read(
        &self,
        _ctx: &ScanContext,
        _raw_data: &[u8],
        _actions_results: &mut HashMap<String, String>,
    ) {
        // This action never performs a read, so this method is intentionally empty.
    }
}

/// Contextual information supplied to each action during execution.
///
/// The `ScanContext` describes:
/// - the target IP/hostname,
/// - the target port,
/// - the internal Tokio task ID responsible for this scan.
///
/// This allows actions to include metadata in their results, correlate logs,
pub struct ScanContext<'a> {
    /// Target address in string form (e.g. `"127.0.0.1"`).
    pub target_addr: &'a str,
    /// Target TCP port.
    pub port: u16,
    /// Identifier of the Tokio task handling this connection attempt.
    pub task_id: tokio::task::Id,
}
