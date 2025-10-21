//! # Scanner Engine
//!
//! This module implements a **concurrent scanning engine** based on a task queue model.
//!
//! It provides a trait [`Stalker`] that defines high-level scanning operations,
//! and a concrete implementation [`Scanner`] that manages tasks, logs, and configuration
//! in a thread-safe way.  
//!
//! The `Scanner` is designed as a *task orchestrator* for I/O-bound workloads,
//! such as network scans, port checks, or service discovery.
//!
//! ## Architecture
//!
//! ```text
//! +-----------------------------+
//! |        User Code            |
//! | (interacts via Stalker)     |
//! +-------------+---------------+
//!               |
//!               v
//! +-----------------------------+
//! |       BuiltScanner          |
//! |  (implements Stalker)       |
//! +-------------+---------------+
//!               |
//!               v
//! +-----------------------------+
//! |         Scanner             |
//! | (state, task queue, logger) |
//! +-----------------------------+
//! ```
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock, atomic::AtomicBool},
};
//use tokio::sync::Mutex;

use crate::utils::UrlParser;
use tokio::net::{self, TcpStream};

/// Defines the core scanning behavior that all scanners must implement.
///
/// The `Stalker` trait serves as a generic interface for interacting with a scanning engine.
/// It abstracts over task management, execution, and result collection.
pub trait Stalker: Send + Sync {
    /// Adds a single task to the scanning queue.
    fn add_task(&self, task: Vec<Actions>, target: UrlParser);

    /// Adds multiple pre-built tasks to the scanning queue.
    fn add_multiple_tasks(&self, tasks: Vec<Task>);

    /// Returns the total number of pending tasks.
    fn total_tasks(&self) -> usize;

    /// Executes all tasks currently in the queue.
    fn execute_tasks(&self);
}

/// Thread-safe queue of pending tasks.
type TaskPool = Arc<Mutex<VecDeque<Task>>>;
/// Thread-safe in-memory byte logger.
type Logger = Arc<Mutex<Vec<u8>>>;
/// Thread-safe map for associating log pointers or metadata.
type PointerMap = Arc<Mutex<HashMap<String, String>>>;

/// Represents a single scanning job.
///
/// A [`Task`] defines what actions should be executed (see [`Actions`])
/// and on which target (via [`UrlParser`]).
pub struct Task {
    /// Actions that define the workflow for this task.
    todo: Vec<Actions>,
    /// The target (host, URL, IP, etc.) to be scanned.
    target: UrlParser,
    /// Atomic flag marking whether this task has been queued or executed.
    queued: AtomicBool,
}

impl Task {
    /// Creates a new task for the given `target` with the specified `actions`.
    pub fn new(todo: Vec<Actions>, target: UrlParser) -> Self {
        Self {
            todo: todo,
            target: target,
            queued: AtomicBool::new(false),
        }
    }
}

/// Configuration options for a [`Scanner`].
#[derive(Clone, Debug)]
pub struct ScannerOptions {
    /// Maximum number of tasks processed in a single batch.
    pub batch_size: usize,
    /// Timeout for network operations, in milliseconds.
    pub timeout_ms: u64,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        Self {
            batch_size: 64,
            timeout_ms: 3_000,
        }
    }
}

/// Core scanner structure.
///
/// The [`Scanner`] stores all shared data and configuration required for scanning:
/// - the task queue,
/// - logs,
/// - pointer map,
/// - and runtime options.
///
/// It is **not** responsible for executing tasks directly;  
/// that responsibility belongs to [`BuiltScanner`], which implements [`Stalker`].
pub struct Scanner {
    /// Configuration options controlling runtime behavior.
    pub options: ScannerOptions,
    /// Shared queue of pending tasks.
    pub task_pool: TaskPool,
    /// Shared logging buffer.
    pub logger: Logger,
    pub pointer_logger_map: PointerMap,
}

/// Actions represent different scanning operations that can be performed
/// on a given target.
pub enum Actions {
    /// Check if a single port is open.
    PortIsOpen,
    /// Check if all ports are open.
    CheckAllPortsAreOpen,
    /// Identify the service running on a specific port.
    ServiceOnPort,
    /// Determine the version of a service running on a port.
    ServicePortVersion,
    /// Fallback strategy for failed scans or unknown states.
    FallBack,
}

/// Concrete implementation of [`Stalker`].
///
/// The [`BuiltScanner`] holds an `Arc` to a [`Scanner`]
/// and provides runtime behavior for the `Stalker` interface.
struct BuiltScanner(Arc<Scanner>);

impl Stalker for BuiltScanner {
    fn add_task(&self, task: Vec<Actions>, target: UrlParser) {
        let mut pool = self.0.task_pool.lock().unwrap();

        pool.push_back(Task {
            todo: task,
            target: target,
            queued: AtomicBool::new(false),
        });
    }

    fn total_tasks(&self) -> usize {
        self.0.task_pool.lock().unwrap().len()
    }

    fn execute_tasks(&self) {
        let mut pool = self.0.task_pool.lock().unwrap();

        loop {
            let task = pool.pop_front();

            match task {
                Some(t) => {
                    t.queued.swap(true, std::sync::atomic::Ordering::SeqCst);

                    if t.queued.load(std::sync::atomic::Ordering::SeqCst) {
                        todo!("run tasks");
                    }
                }
                None => {
                    //dd
                    break;
                }
            }
        }
    }

    fn add_multiple_tasks(&self, tasks: Vec<Task>) {
        let mut pool = self.0.task_pool.lock().unwrap();

        tasks.into_iter().for_each(|t| pool.push_back(t));
    }
}

impl Scanner {
    /// Creates a new [`Scanner`] with default configuration.
    pub fn new() -> Self {
        Self {
            options: ScannerOptions::default(),
            task_pool: Arc::new(Mutex::new(VecDeque::new())),
            logger: Arc::new(Mutex::new(Vec::new())),
            pointer_logger_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Builds a ready-to-use [`Stalker`] implementation using [`BuiltScanner`].
    ///
    /// This returns an [`Arc<dyn Stalker>`] that can safely be shared across threads.
    pub fn build(self) -> Arc<dyn Stalker> {
        Arc::new(BuiltScanner(Arc::new(self)))
    }

    /// Builds a custom [`Stalker`] implementation using a provided constructor function.
    pub fn build_with<T, F>(self, f: F) -> Arc<T>
    where
        T: Stalker + Send + Sync,
        F: FnOnce(Arc<Scanner>) -> T,
    {
        Arc::new(f(Arc::new(self)))
    }

    /// Sets custom configuration of the [`Scanner`].
    pub fn with_options(mut self, options: ScannerOptions) -> Self {
        self.options = options;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_build_scanner_default_and_custom_options() {
        let scanner = Scanner::new();
        let scanner_custom = Scanner::new().with_options(
            ScannerOptions {
                batch_size: 100,
                timeout_ms: 2_000,
            }
            .try_into()
            .unwrap(),
        );

        assert_eq!(scanner.options.batch_size, 64);
        assert_eq!(scanner.options.timeout_ms, 3_000);
        assert_eq!(scanner_custom.options.batch_size, 100);
        assert_eq!(scanner_custom.options.timeout_ms, 2_000);
    }

    #[test]
    fn test_scanner_add_task() {
        let scanner = Scanner::new().build();

        scanner.add_task(
            vec![Actions::PortIsOpen, Actions::ServiceOnPort],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        );
        scanner.add_task(
            vec![Actions::CheckAllPortsAreOpen, Actions::ServiceOnPort],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        );

        assert_eq!(scanner.total_tasks(), 2);
    }

    #[test]
    fn test_scanner_add_multiple_tasks() {
        let scanner = Scanner::new().build();

        let l = vec![
            Task::new(
                vec![Actions::PortIsOpen, Actions::ServiceOnPort],
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
            Task::new(
                vec![Actions::CheckAllPortsAreOpen, Actions::ServiceOnPort],
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
            Task::new(
                vec![Actions::PortIsOpen, Actions::ServiceOnPort],
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
        ];

        scanner.add_multiple_tasks(l);

        assert_eq!(scanner.total_tasks(), 3);
    }
}
