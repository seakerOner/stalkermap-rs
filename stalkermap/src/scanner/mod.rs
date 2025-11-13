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
//!     let mut stream = scanner.get_logs_stream().await.unwrap();
//!
//!     scanner.execute_tasks();
//!
//!     tokio::spawn(async move {
//!         while let Some(log) = stream.next().await {
//!             match log {
//!                 Ok(log) => println!("{:?}", log),
//!                 Err(_) => break
//!             }
//!         }
//!     });
//!
//!     scanner.shutdown_now().await;
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
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{
        Notify, Semaphore,
        broadcast::{self},
    },
    task::{JoinSet, yield_now},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub mod formatter;
pub use formatter::{JsonFormatter, LogFormatter, RawFormatter, StructuredFormatter};
pub mod buffer_pool;
use crate::{
    scanner::buffer_pool::{Buffer, BufferExt, BufferPool},
    utils::UrlParser,
};

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
    fn total_tasks_on_queue(&self) -> usize;

    /// Executes all tasks currently in the queue asynchronously.
    ///
    /// Tasks are executed concurrently up to the `batch_size` limit.
    /// Each task runs at most once, and log events are streamed via the configured formatter.
    fn execute_tasks(&self);

    /// Returns a stream of log events produced during task execution.
    async fn get_logs_stream(
        &self,
    ) -> Option<tokio_stream::wrappers::BroadcastStream<<Self::F as LogFormatter>::Output>>;

    /// Signals the scanner to shut down and release resources.
    ///
    /// All running tasks will continue until completion, but no new tasks will be accepted.
    async fn shutdown_graceful(&self);
    async fn await_idle(&self);
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
}

impl Task {
    /// Creates a new task for the given `target` with the specified `actions`.
    pub fn new(todo: Vec<Actions>, target: UrlParser) -> Self {
        Self { todo, target }
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
            batch_size: 100,
            timeout_ms: 500,
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
    /// Configuration options controlling runtime behavior.
    pub options: ScannerOptions,
    /// Shared queue of pending tasks.
    task_pool: TaskPool,
    pending_tasks: Arc<AtomicUsize>,
    active_tasks: Arc<AtomicUsize>,
    task_notify: Arc<Notify>,
    buffer_pool: Arc<BufferPool>,
    /// Broadcast channel for log events.
    logger_tx: Arc<Mutex<Option<broadcast::Sender<<F as LogFormatter>::Output>>>>,
    /// Formatter used to serialize log events.
    pub logger_format: Arc<F>,
    cancellation_token: Arc<CancellationToken>,
}

struct ActiveTasksGuard {
    active_tasks: Arc<AtomicUsize>,
}

impl Drop for ActiveTasksGuard {
    fn drop(&mut self) {
        self.active_tasks.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Enumerates the possible scanning operations.
///
/// Each action defines a type of check or probe to perform on a target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Actions {
    /// Check if a single port is open.
    PortIsOpen,
    /// Check status code on connection. (NOT IMPLEMENTED)
    StatusCode,
    /// Identify the service running on a specific port. (NOT IMPLEMENTED)
    ServiceOnPort,
    /// Determine the version of a service running on a port. (NOT IMPLEMENTED)
    ServicePortVersion,
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
        self.0.pending_tasks.fetch_add(1, Ordering::SeqCst);
        let mut pool = { self.0.task_pool.lock() };

        pool.push_back(Task { todo: task, target });
        self.0.task_notify.notify_one();
    }

    fn total_tasks(&self) -> usize {
        self.0.task_pool.lock().len()
    }

    fn total_tasks_on_queue(&self) -> usize {
        self.0.pending_tasks.load(Ordering::SeqCst) + self.0.active_tasks.load(Ordering::SeqCst)
    }
    fn execute_tasks(&self) {
        let batch_size = Arc::new(Semaphore::new(self.0.options.batch_size));
        let scanner = self.0.clone();

        tokio::task::spawn(async move {
            let mut set = JoinSet::new();

            loop {
                let timeout_t = scanner.options.timeout_ms;

                let maybe_task = { scanner.task_pool.lock().pop_front() };

                if maybe_task.is_none()
                    && scanner.active_tasks.load(Ordering::SeqCst) == 0
                    && scanner.pending_tasks.load(Ordering::SeqCst) == 0
                {
                    break;
                }

                if let Some(task) = maybe_task {
                    let permit = match batch_size.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            break;
                        }
                    };

                    let actions: HashSet<Actions> = task.todo.into_iter().collect();
                    let logs_tx = scanner.logger_tx.clone();
                    let log_format = scanner.logger_format.clone();

                    let target = task.target;
                    let addr = format!(
                        "{}:{}",
                        target.target,
                        if target.port == 0 { 80 } else { target.port }
                    );

                    let buffer_pool = scanner.buffer_pool.clone();
                    let cancel_token = scanner.cancellation_token.clone();

                    let active_tasks = scanner.active_tasks.clone();
                    let pending_tasks = scanner.pending_tasks.clone();
                    active_tasks.fetch_add(1, Ordering::SeqCst);
                    pending_tasks.fetch_sub(1, Ordering::SeqCst);

                    set.spawn(async move {
                        let _guard = ActiveTasksGuard {
                            active_tasks: active_tasks,
                        };

                        if cancel_token.is_cancelled() {
                            return;
                        }
                        let mut buf = buffer_pool.get();
                        let mut actions_results: HashMap<Actions, String> = HashMap::new();

                        let stream = match timeout(
                            Duration::from_millis(timeout_t),
                            TcpStream::connect(addr),
                        )
                        .await
                        {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                actions_results.insert(Actions::PortIsOpen, "closed".to_string());
                                let msg = (format!("connection error: {}", e)).into_bytes();
                                let log = log_format.format(actions_results, &msg);

                                if let Some(logs_tx) = logs_tx.lock().as_ref() {
                                    logs_tx.send(log).ok();
                                }

                                buffer_pool.put(buf as Buffer);
                                drop(permit);
                                return;
                            }
                            Err(e) => {
                                actions_results.insert(Actions::PortIsOpen, "timeout".to_string());
                                let msg = (format!("connection timed out: {}", e)).into_bytes();
                                let log = log_format.format(actions_results, &msg);

                                if let Some(logs_tx) = logs_tx.lock().as_ref() {
                                    logs_tx.send(log).ok();
                                }

                                buffer_pool.put(buf as Buffer);
                                drop(permit);
                                return;
                            }
                        };

                        // let len = if let Ok(_) = stream.readable().await {
                        //     match stream.try_read(buf.as_bytes_mut()) {
                        //         Ok(v) => v,
                        //         Err(_) => 0,
                        //     }
                        // } else {
                        //     0
                        // };
                        let len = 0;

                        // SAFETY: `try_read()` writes exactly `len` bytes into the provided buffer,
                        // and `len` is guaranteed to be <= buffer size. In case of any read error or
                        // failure, `len` is set to 0, ensuring no uninitialized memory is ever read.
                        // Therefore, the slice created here only covers initialized memory.
                        let raw_data = unsafe { buf.as_bytes(len) };

                        // Set Action Results
                        actions.iter().for_each(|a| match a {
                            Actions::PortIsOpen => {
                                if len > 0 {
                                    actions_results.insert(Actions::PortIsOpen, "open".to_string());
                                } else {
                                    actions_results
                                        .insert(Actions::PortIsOpen, "closed".to_string());
                                }
                            }
                            Actions::StatusCode => {}
                            Actions::ServiceOnPort => {}
                            Actions::ServicePortVersion => {}
                        });

                        let log = log_format.format(actions_results, &raw_data);

                        if let Some(logs_tx) = logs_tx.lock().as_ref() {
                            logs_tx.send(log).ok();
                        }

                        buffer_pool.put(buf as Buffer);
                        drop(permit);
                    });
                } else {
                    println!("execute_tasks yielded");
                    println!("active: {}", scanner.active_tasks.load(Ordering::SeqCst));
                    println!("pending: {}", scanner.pending_tasks.load(Ordering::SeqCst));

                    yield_now().await;
                }
            }
        });
    }

    fn add_multiple_tasks(&self, tasks: Vec<Task>) {
        self.0
            .pending_tasks
            .fetch_add(*&tasks.len(), Ordering::SeqCst);
        let mut pool = { self.0.task_pool.lock() };
        tasks.into_iter().for_each(|t| pool.push_back(t));
        self.0.task_notify.notify_waiters();
    }

    async fn get_logs_stream(
        &self,
    ) -> Option<tokio_stream::wrappers::BroadcastStream<<Self::F as LogFormatter>::Output>> {
        use tokio_stream::wrappers::BroadcastStream;

        if let Some(logs_tx) = self.0.logger_tx.lock().as_ref() {
            Some(BroadcastStream::new(logs_tx.subscribe()))
        } else {
            None
        }
    }

    async fn await_idle(&self) {
        loop {
            let active = self.0.active_tasks.load(Ordering::SeqCst);
            let pending = self.0.pending_tasks.load(Ordering::SeqCst);
            println!("pending: {}, active: {}", pending, active);
            if pending == 0 && active == 0 {
                break;
            }
        }
    }

    async fn shutdown_graceful(&self) {
        //self.0.cancellation_token.cancel();

        loop {
            let pending = self.0.pending_tasks.load(Ordering::SeqCst);
            let active = self.0.active_tasks.load(Ordering::SeqCst);
            println!("[GRACEFUL] pending: {}, active: {}", pending, active);
            if pending == 0 && active == 0 {
                break;
            }
        }

        if let Some(logs_tx) = self.0.logger_tx.lock().take() {
            drop(logs_tx);
        }
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
            options: ScannerOptions::default(),
            task_pool: Arc::new(Mutex::new(VecDeque::new())),
            pending_tasks: Arc::new(AtomicUsize::new(0)),
            active_tasks: Arc::new(AtomicUsize::new(0)),
            task_notify: Arc::new(Notify::new()),
            buffer_pool: Arc::new(BufferPool::new()),
            logger_tx: Arc::new(Mutex::new(Some(sender))),
            logger_format: Arc::new(F::default()),
            cancellation_token: Arc::new(CancellationToken::new()),
        }
    }

    /// Builds a ready-to-use [`Stalker`] implementation using `BuiltScanner`.
    ///
    /// This returns an [`Arc<dyn Stalker>`] that can safely be shared across threads.
    pub fn build(self) -> Arc<dyn Stalker<F = F> + Send + Sync + 'static> {
        Arc::new(BuiltScanner(Arc::new(self)))
    }

    /// Builds a custom [`Stalker`] implementation using a provided constructor function.
    pub fn build_with<T, FF>(self, f: FF) -> Arc<T>
    where
        T: Stalker + Send + Sync + 'static,
        FF: FnOnce(Arc<Scanner<F>>) -> T,
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
    use tokio_stream::StreamExt;

    use super::*;

    #[test]
    fn test_build_scanner_default_and_custom_options() {
        let scanner = Scanner::<JsonFormatter>::new();
        let scanner_custom = Scanner::<JsonFormatter>::new().with_options(ScannerOptions {
            batch_size: 100,
            timeout_ms: 2_000,
        });

        assert_eq!(scanner.options.batch_size, 100);
        assert_eq!(scanner.options.timeout_ms, 500);
        assert_eq!(scanner_custom.options.batch_size, 100);
        assert_eq!(scanner_custom.options.timeout_ms, 2_000);
    }

    #[tokio::test]
    async fn test_scanner_add_task() {
        let scanner = Scanner::<RawFormatter>::new().build();

        scanner.add_task(
            vec![Actions::PortIsOpen, Actions::ServiceOnPort],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        );
        scanner.add_task(
            vec![Actions::PortIsOpen, Actions::ServiceOnPort],
            UrlParser::from_str("https://127.0.0.1:120").unwrap(),
        );

        assert_eq!(scanner.total_tasks(), 2);
        scanner.shutdown_graceful().await;
    }

    #[tokio::test]
    async fn test_scanner_add_multiple_tasks() {
        let scanner = Scanner::<StructuredFormatter>::new().build();

        let l = vec![
            Task::new(
                vec![Actions::PortIsOpen, Actions::ServiceOnPort],
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
            Task::new(
                vec![Actions::PortIsOpen, Actions::ServiceOnPort],
                UrlParser::from_str("https://127.0.0.1:20").unwrap(),
            ),
            Task::new(
                vec![Actions::PortIsOpen, Actions::ServiceOnPort],
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
        ];

        scanner.add_multiple_tasks(l);

        assert_eq!(scanner.total_tasks(), 3);
        scanner.shutdown_graceful().await;
    }

    #[tokio::test]
    async fn test_scanner_logger_stream() {
        let scanner = Scanner::<JsonFormatter>::new().build();

        let l = vec![
            Task::new(
                vec![Actions::PortIsOpen],
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
            Task::new(
                vec![Actions::PortIsOpen],
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
            Task::new(
                vec![Actions::PortIsOpen],
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
        ];

        scanner.add_multiple_tasks(l);

        assert_eq!(scanner.total_tasks(), 3);

        let mut logs = scanner.get_logs_stream().await.unwrap();

        scanner.execute_tasks();

        tokio::spawn(async move {
            while let Some(Ok(log)) = logs.next().await {
                println!("Log: {:?}", log);
            }
        });

        scanner.shutdown_graceful().await;

        assert_eq!(scanner.total_tasks_on_queue(), 0);
    }
}
