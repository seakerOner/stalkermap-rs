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
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};
//use tokio::sync::Mutex;
use crate::utils::UrlParser;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{self, TcpStream},
    sync::{
        OwnedSemaphorePermit, Semaphore, SemaphorePermit,
        broadcast::{self, Receiver, Sender},
    },
};
use tokio_stream::wrappers::ReceiverStream;

/// Defines the core scanning behavior that all scanners must implement.
///
/// The `Stalker` trait serves as a generic interface for interacting with a scanning engine.
/// It abstracts over task management, execution, and result collection.
#[async_trait]
pub trait Stalker: Send + Sync + 'static {
    /// Adds a single task to the scanning queue.
    fn add_task(&self, task: Vec<Actions>, target: UrlParser);

    /// Adds multiple pre-built tasks to the scanning queue.
    fn add_multiple_tasks(&self, tasks: Vec<Task>);

    /// Returns the total number of pending tasks.
    fn total_tasks(&self) -> usize;

    /// Executes all tasks currently in the queue.
    async fn execute_tasks(&self);

    async fn get_logs_stream(&self) -> tokio_stream::wrappers::BroadcastStream<Vec<u8>>;
}

/// Thread-safe queue of pending tasks.
type TaskPool = Arc<Mutex<VecDeque<Task>>>;
/// Thread-safe in-memory byte logger.
type LoggerSender = broadcast::Sender<Vec<u8>>;

#[derive(Clone, Debug)]
pub enum LoggerType {
    Raw,
    Structured,
    Json,
}

pub trait LogFormatter: Send + Sync + 'static {
    fn format(&self, data: &[u8]);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub header_response: LogHeader,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHeader {}

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
    pub logger_tx: LoggerSender,
    pub logger_format: LoggerType,
}

/// Actions represent different scanning operations that can be performed
/// on a given target.
#[derive(PartialEq, Eq, PartialOrd, Hash)]
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

#[async_trait]
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

    async fn execute_tasks(&self) {
        let batch_size = Arc::new(Semaphore::new(self.0.options.batch_size));
        let timeout_t = self.0.options.timeout_ms;

        let logger_tx = self.0.logger_tx.clone();

        loop {
            let task = { self.0.task_pool.lock().unwrap().pop_front() };
            let Some(task) = task else {
                //TODO:Shutdown Engine
                break;
            };

            task.queued.swap(true, std::sync::atomic::Ordering::SeqCst);

            if task.queued.load(std::sync::atomic::Ordering::SeqCst) {
                let permit = match batch_size.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        //TODO:Shutdown Engine
                        break;
                    }
                };

                let actions: HashSet<Actions> = task.todo.into_iter().collect();
                let target = task.target;
                let logs = logger_tx.clone();

                tokio::task::spawn(async move {
                    let log = String::from("banana");

                    logs.send(log.into_bytes()).unwrap();

                    drop(permit);
                });
            }
        }
    }

    fn add_multiple_tasks(&self, tasks: Vec<Task>) {
        let mut pool = self.0.task_pool.lock().unwrap();

        tasks.into_iter().for_each(|t| pool.push_back(t));
    }

    async fn get_logs_stream(&self) -> tokio_stream::wrappers::BroadcastStream<Vec<u8>> {
        use tokio_stream::wrappers::BroadcastStream;

        BroadcastStream::new(self.0.logger_tx.subscribe())
    }
}

impl Scanner {
    /// Creates a new [`Scanner`] with default configuration.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel::<Vec<u8>>(1024);

        Self {
            options: ScannerOptions::default(),
            task_pool: Arc::new(Mutex::new(VecDeque::new())),
            logger_tx: sender,
            logger_format: LoggerType::Raw,
        }
    }

    pub fn with_logger(mut self, logger_type: LoggerType) -> Self {
        self.logger_format = logger_type;
        self
    }

    /// Builds a ready-to-use [`Stalker`] implementation using [`BuiltScanner`].
    ///
    /// This returns an [`Arc<dyn Stalker>`] that can safely be shared across threads.
    pub fn build(self) -> Arc<dyn Stalker + Send + Sync + 'static> {
        Arc::new(BuiltScanner(Arc::new(self)))
    }

    /// Builds a custom [`Stalker`] implementation using a provided constructor function.
    pub fn build_with<T, F>(self, f: F) -> Arc<T>
    where
        T: Stalker + Send + Sync + 'static,
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

    use tokio_stream::StreamExt;

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

    #[tokio::test]
    async fn test_scanner_logger_stream() {
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
        //TODO:finish logs stream
        //let logs = scanner.get_logs_stream().await;

        let mut logs = scanner.get_logs_stream().await;

        scanner.execute_tasks().await;

        while let Some(log) = logs.next().await {
            println!("Log: {:?}", String::from_utf8_lossy(&log.unwrap()));
        }

        assert_eq!(scanner.total_tasks(), 3);
    }
}
