//! # Scanner Engine
//!
//! This module implements a **concurrent scanning engine** built on top of a lightweight asynchronous task queue.
//!
//! It exposes the [`Stalker`] trait for defining scanning operations,
//! and the [`Scanner`] struct, which manages task scheduling, configuration, and logging.
//!
//! It serves as a *task orchestrator* for I/O-bound workloads such as network scanning,
//! port probing, or service enumeration.
//!
//! Internally, it leverages asynchronous execution and a pluggable [`LogFormatter`] to support
//! flexible output formats (raw bytes, structured data, JSON, etc.).
//!
//! ## Architecture Overview
//!
//! The core architecture separates the scanning logic from orchestration and I/O formatting layers:
//!
//! ```text
//! +-----------------------------+
//! |        User Code            |
//! |   (interacts via Stalker)   |
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
//! |          Scanner            |
//! | (state, queue, formatter)   |
//! +-----------------------------+
//! ```
//!
//! ## Key Components
//!
//! - [`Scanner`]: Holds configuration, task queue, and log channel; does not execute tasks directly.
//! - [`Task`]: Represents a single scanning job (actions + target), with a flag to avoid duplicate execution.
//! - [`Actions`]: Defines what to perform (e.g., port checks, service detection).
//! - [`LogFormatter`]: Controls how scan results are serialized or formatted.
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use stalkermap::scanner::{Scanner, Stalker, Actions, JsonFormatter};
//! use tokio_stream::StreamExt;
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let scanner = Scanner::<JsonFormatter>::new().build();
//!
//!     scanner.add_task(
//!         vec![Actions::PortIsOpen, Actions::ServiceOnPort],
//!         "127.0.0.1:80".parse().unwrap(),
//!     );
//!
//!     scanner.execute_tasks().await;
//!
//!     let mut stream = scanner.get_logs_stream().await;
//!     while let Some(log) = stream.next().await {
//!         match log {
//!             Ok(log) => println!("{:?}", log),
//!             Err(_) => break
//!         }
//!     }
//! }
//! ```
//!
//! ## Design Notes
//!
//! - The engine ensures **thread-safe concurrency** for all shared components.
//! - `batch_size` in [`ScannerOptions`] limits **concurrent task execution** via a semaphore.
//! - Log output is **formatter-agnostic**, allowing custom implementations.
//! - Shutdown behavior is cooperative — consumers should drop receivers
//!   or invoke [`Stalker::shutdown`] when done.
//!
//! The engine is designed for composability and safety —
//! all concurrency is explicit, and shutdowns are cooperative.
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Debug,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};
//use tokio::sync::Mutex;
use crate::utils::UrlParser;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpStream,
    sync::{
        Semaphore,
        broadcast::{self},
    },
    time::{Timeout, timeout},
};
pub mod formatter;
pub use formatter::{JsonFormatter, LogFormatter, RawFormatter, StructuredFormatter};

/// Trait defining the core scanning operations.
///
/// The `Stalker` trait abstracts over a scanning engine, providing
/// methods for adding tasks, executing them asynchronously,
/// retrieving logs, and managing shutdown.
///
/// # Type Parameters
/// - `F`: The `LogFormatter` used to format scan results.
#[async_trait]
pub trait Stalker: Send + Sync + 'static {
    type F: LogFormatter;

    /// Adds a single task to the scanning queue.
    fn add_task(&self, task: Vec<Actions>, target: UrlParser);

    /// Adds multiple pre-built tasks to the scanning queue.
    fn add_multiple_tasks(&self, tasks: Vec<Task>);

    /// Returns the total number of pending tasks.
    fn total_tasks(&self) -> usize;

    /// Executes all tasks currently in the queue asynchronously.
    ///
    /// Tasks are executed concurrently up to the `batch_size` limit.
    /// Each task runs at most once, and log events are streamed via the configured formatter.
    async fn execute_tasks(&self);

    /// Returns a stream of log events produced during task execution.
    async fn get_logs_stream(
        &self,
    ) -> tokio_stream::wrappers::BroadcastStream<<Self::F as LogFormatter>::Output>;

    /// Signals the scanner to shut down and release resources.
    ///
    /// All running tasks will continue until completion, but no new tasks will be accepted.
    fn shutdown(&self);
}

/// Thread-safe queue of pending tasks.
type TaskPool = Arc<Mutex<VecDeque<Task>>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub header_response: LogHeader,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHeader {
    pub actions_results: HashMap<Actions, String>,
}

/// Represents a single scanning job.
///
/// A `Task` bundles the actions to perform on a target URL or host,
/// and tracks whether it has been queued.
pub struct Task {
    /// Actions that define the workflow for this task.
    todo: Vec<Actions>,
    /// The target (host, URL, IP, etc.) to be scanned.
    target: UrlParser,
    /// Flag indicating if the task has been queued.
    queued: AtomicBool,
}

impl Task {
    /// Creates a new task for the given `target` with the specified `actions`.
    pub fn new(todo: Vec<Actions>, target: UrlParser) -> Self {
        Self {
            todo,
            target,
            queued: AtomicBool::new(false),
        }
    }
}

/// Configuration options for the scanning engine.
///
/// Controls runtime behavior such as batch processing size
/// and network timeouts.
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

#[derive(Debug)]
pub enum ScannerState {
    Uninitialized,
    Initialized,
    Running,
    ShuttingDown,
    Stopped,
}

/// Core scanner structure.
///
/// The [`Scanner`] stores all shared data and configuration required for scanning:
/// - state
/// - the task queue,
/// - logs,
/// - pointer map,
/// - and runtime options.
///
/// It is **not** responsible for executing tasks directly;  
/// that responsibility belongs to `BuiltScanner`, which implements [`Stalker`].
#[derive(Clone)]
pub struct Scanner<F>
where
    F: LogFormatter,
{
    /// Current runtime state.
    pub state: Arc<Mutex<ScannerState>>,
    /// Configuration options controlling runtime behavior.
    pub options: ScannerOptions,
    /// Shared queue of pending tasks.
    pub task_pool: TaskPool,
    /// Broadcast channel for log events.
    pub logger_tx: Arc<Mutex<Option<broadcast::Sender<<F as LogFormatter>::Output>>>>,
    /// Formatter used to serialize log events.
    pub logger_format: Arc<F>,
}

/// Enumerates the possible scanning operations.
///
/// Each action defines a type of check or probe to perform on a target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash, Serialize, Deserialize)]
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

/// Internal concrete implementation of [`Stalker`].
///
/// Wraps a shared [`Scanner`] instance and provides runtime
/// behavior for task execution, logging, and shutdown.
struct BuiltScanner<F>(Arc<Scanner<F>>)
where
    F: LogFormatter;

#[async_trait]
impl<F> Stalker for BuiltScanner<F>
where
    F: LogFormatter,
{
    type F = F;

    fn add_task(&self, task: Vec<Actions>, target: UrlParser) {
        let mut pool = self.0.task_pool.lock().unwrap();

        pool.push_back(Task {
            todo: task,
            target,
            queued: AtomicBool::new(false),
        });
    }

    fn total_tasks(&self) -> usize {
        self.0.task_pool.lock().unwrap().len()
    }

    async fn execute_tasks(&self) {
        *self.0.state.lock().unwrap() = ScannerState::Running;
        let batch_size = Arc::new(Semaphore::new(self.0.options.batch_size));
        let timeout_t = self.0.options.timeout_ms;
        let logger_tx = self.0.logger_tx.clone();

        loop {
            let task = { self.0.task_pool.lock().unwrap().pop_front() };
            let Some(task) = task else {
                break;
            };

            if !task.queued.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let permit = match batch_size.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        break;
                    }
                };

                let actions: HashSet<Actions> = task.todo.into_iter().collect();
                let logs_tx = logger_tx.clone();
                let log_format = self.0.logger_format.clone();

                let target = task.target;
                let addr = format!(
                    "{}://{}{}",
                    target.scheme,
                    target.target,
                    match target.port {
                        0 => String::new(),
                        n => format!(":{}", n),
                    }
                );

                tokio::task::spawn(async move {
                    let raw_data: &[u8; 11] = b"hello world";

                    let con = timeout(Duration::from_millis(timeout_t), TcpStream::connect(addr))
                        .await
                        .unwrap()
                        .unwrap();

                    let actions_results: HashMap<Actions, String> = HashMap::new();
                    let log = log_format.format(actions_results, raw_data);

                    if let Some(logs_tx) = &*logs_tx.lock().unwrap() {
                        let _ = logs_tx.send(log);
                    }

                    drop(permit);
                });
            }
        }

        self.shutdown();
    }

    fn add_multiple_tasks(&self, tasks: Vec<Task>) {
        let mut pool = self.0.task_pool.lock().unwrap();

        tasks.into_iter().for_each(|t| pool.push_back(t));
    }

    async fn get_logs_stream(
        &self,
    ) -> tokio_stream::wrappers::BroadcastStream<<Self::F as LogFormatter>::Output> {
        use tokio_stream::wrappers::BroadcastStream;

        BroadcastStream::new(
            self.0
                .logger_tx
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .subscribe(),
        )
    }

    fn shutdown(&self) {
        *self.0.state.lock().unwrap() = ScannerState::ShuttingDown;

        if let Some(sender) = self.0.logger_tx.lock().unwrap().take() {
            drop(sender);
        }
        *self.0.state.lock().unwrap() = ScannerState::Stopped;
    }
}

impl<F> Scanner<F>
where
    F: LogFormatter + Default,
{
    /// Creates a new [`Scanner`] with default configuration.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel::<F::Output>(1024);

        Self {
            state: Arc::new(Mutex::new(ScannerState::Uninitialized)),
            options: ScannerOptions::default(),
            task_pool: Arc::new(Mutex::new(VecDeque::new())),
            logger_tx: Arc::new(Mutex::new(Some(sender))),
            logger_format: Arc::new(F::default()),
        }
    }

    /// Builds a ready-to-use [`Stalker`] implementation using `BuiltScanner`.
    ///
    /// This returns an [`Arc<dyn Stalker>`] that can safely be shared across threads.
    pub fn build(mut self) -> Arc<dyn Stalker<F = F> + Send + Sync + 'static> {
        self.state = Arc::new(Mutex::new(ScannerState::Initialized));
        Arc::new(BuiltScanner(Arc::new(self)))
    }

    /// Builds a custom [`Stalker`] implementation using a provided constructor function.
    pub fn build_with<T, FF>(mut self, f: FF) -> Arc<T>
    where
        T: Stalker + Send + Sync + 'static,
        FF: FnOnce(Arc<Scanner<F>>) -> T,
    {
        self.state = Arc::new(Mutex::new(ScannerState::Initialized));
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
    use tokio_stream::StreamExt;

    use super::*;

    #[test]
    fn test_build_scanner_default_and_custom_options() {
        let scanner = Scanner::<JsonFormatter>::new();
        let scanner_custom = Scanner::<JsonFormatter>::new().with_options(ScannerOptions {
            batch_size: 100,
            timeout_ms: 2_000,
        });

        assert_eq!(scanner.options.batch_size, 64);
        assert_eq!(scanner.options.timeout_ms, 3_000);
        assert_eq!(scanner_custom.options.batch_size, 100);
        assert_eq!(scanner_custom.options.timeout_ms, 2_000);
    }

    #[test]
    fn test_scanner_add_task() {
        let scanner = Scanner::<RawFormatter>::new().build();

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
        let scanner = Scanner::<StructuredFormatter>::new().build();

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

    #[tokio::test]
    async fn test_scanner_logger_stream() {
        let scanner = Scanner::<JsonFormatter>::new().build();

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

        let mut logs = scanner.get_logs_stream().await;

        scanner.execute_tasks().await;

        while let Some(log) = logs.next().await {
            match log {
                Ok(log) => println!("Log: {:?}", log),
                Err(_) => break,
            }
        }

        assert_eq!(scanner.total_tasks(), 0);
    }
}
