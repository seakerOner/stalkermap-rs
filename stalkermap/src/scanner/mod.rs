//! # Scanner Engine
//!
//! This module implements a **concurrent asynchronous scanning engine**
//! designed for I/O-bound workloads such as:
//! - network probing
//! - port scanning
//! - service enumeration
//! - protocol fingerprinting
//!
//! The engine is built around three pillars:
//!
//! - [`Stalker`]: the high-level async API for issuing tasks and controlling the scanner  
//! - [`Scanner`]: the underlying shared state, task queue, and log channel  
//! - a pluggable [`LogFormatter`] for customizable output formats  
//! - The engine is extensible through a modular **Action system**
//!   (see [`actions`]).
//!
//! Actions allow each task to define arbitrary per-connection logic,
//! such as:
//! - port-state checking (e.g. [`ActionIsPortOpen`])
//! - banner grabbing
//! - protocol fingerprinting
//! - TLS/service probing
//! - completely custom user-defined behaviours
//!
//! Each task carries a list of Actions, and the scanner executes them
//! automatically after establishing the TCP connection (and optionally
//! after performing a socket read, depending on the action).
//!
//! It provides a **lightweight task scheduler** with bounded concurrency,
//! streaming logs via a `tokio::broadcast` channel, and cooperative idle/shutdown
//! behavior.
//!
//! ---
//!
//! ## Architecture Overview
//!
//! The scanner is composed of modular layers:
//!
//! ```text
//! +------------------------------------------------------+
//! |                     User Code                        |
//! |         (adds tasks, consumes logs, awaits idle)     |
//! +------------------------------+-----------------------+
//!                                |
//!                                v
//! +------------------------------------------------------+
//! |                     Stalker API                      |
//! |   - add_task, add_multiple_tasks                     |
//! |   - execute_tasks                                    |
//! |   - get_logs_stream                                  |
//! |   - await_idle, shutdown_graceful                    |
//! +------------------------------+-----------------------+
//!                                |
//!                                v
//! +------------------------------------------------------+
//! |                  BuiltScanner (runtime)              |
//! |   Implements async scheduling and task execution     |
//! +------------------------------+-----------------------+
//!                                |
//!                                v
//! +------------------------------------------------------+
//! |                    Scanner (state)                   |
//! | - task queue        - log broadcast sender           |
//! | - buffer pool       - formatter                      |
//! | - counters          - Notify (idle)                  |
//! +------------------------------------------------------+
//! ```
//!
//! The **Scanner** owns all shared state.  
//! **BuiltScanner** implements the logic.  
//! Users interact exclusively through the **Stalker** trait.
//!
//! Each executed task invokes its associated [`Action`]'s,
//! executed in order:
//! - After a successful TCP connection
//! - With optional non-blocking read depending on the action's configuration
//!
//! Action results are collected into a shared map and included in every log record.
//!
//! ---
//!
//! ## Actions and Concurrency Model
//!
//! Task execution is cooperative and bounded:
//!
//! - tasks are executed concurrently and independently  
//! - concurrency is limited by [`ScannerOptions::batch_size`]  
//! - tasks use a shared `BufferPool` for fast zero-alloc reads  
//! - log messages are broadcast to all subscribers  
//! - the system supports:
//!   - **real-time log streaming**
//!   - **idle detection**
//!   - **graceful shutdown**
//!
//! Idle events are emitted automatically via the formatter's  
//! [`LogFormatter::idle_output`] value.
//!
//! All actions inside a task run **sequentially within that task**, but
//! tasks themselves run concurrently up to the configured batch size.
//!
//! Each action receives a [`ScanContext`] containing:
//! - the target host
//! - the target port
//! - the Tokio task ID handling the connection
//!
//! All actions share a mutable `actions_results: HashMap<String, String>`,
//! allowing actions to:
//! - contribute results
//! - detect results from previous actions in the same task
//! - build multi-step or dependent workflows
//!
//! ---
//!
//! ## Log Streaming
//!
//! Logs are published with a `tokio::broadcast` channel.
//!
//! `scanner.get_logs_stream()` returns a [`TaskAwareStream`], which is a wrapper
//! around `BroadcastStream` that provides:
//!
//! - `.next()` — receive next log event  
//! - `.notify_when_new_tasks()` — wait until new tasks are added  
//!
//! This allows writing event loops that pause when the scanner is idle and
//! automatically resume when new tasks arrive.
//!
//! ---
//!
//! ## Idle Detection
//!
//! A scanner is considered **idle** when:
//!
//! ```text
//! pending_tasks == 0  AND  active_tasks == 0
//! ```
//!
//! This invariant is maintained by two atomic counters that are updated
//! deterministically even in the presence of cancellation or panics.
//!
//! When the scanner becomes idle, two events occur:
//!
//! 1. `await_idle()` returns  
//! 2. an **idle log event** is broadcast, using the formatter's
//!    [`LogFormatter::idle_output`] value  
//!
//! This provides a predictable and race-free way for consumers to know that:
//!
//! - all work has completed  
//! - the queue is empty  
//! - no tasks are currently running  
//!
//! ### Why idle events exist
//!
//! Idle messages enable a powerful pattern:
//!
//! ```text
//! read log → detect idle → pause yourself → wake when tasks are added
//! ```
//!
//! This is achieved with:
//!
//! - `Formatter.is_idle_signal(&log)`  
//! - `logs.notify_when_new_tasks().await`  
//!
//! The second method (`notify_when_new_tasks`) attaches a `Notify` behind the
//! stream, allowing listeners to sleep until new tasks are pushed into the queue.
//!
//! This avoids busy-waiting and enables very efficient background log loops.
//!
//! ---
//!
//! ## Graceful Shutdown
//!
//! `shutdown_graceful()` ensures that:
//!
//! - **no new tasks** will be accepted when `pending_tasks` + `active_tasks` = `0`
//! - **all already-running tasks** are allowed to finish  
//! - the log channel is closed only after the last task completes  
//!
//! The shutdown procedure waits for the same invariants used for idle detection:
//!
//! ```text
//! pending_tasks == 0
//! active_tasks == 0
//! ```
//!
//! Only after both conditions hold does the scanner:
//!
//! - drop the broadcast sender  
//! - unblock all remaining log stream consumers  
//! - allow the scanner to be reclaimed by the runtime  
//!
//! ### Why it works
//!
//! Because active task tracking is implemented with an RAII guard
//! (`ActiveTasksGuard`), the counters are always correct:
//! - incremented before a task begins  
//! - decremented automatically when a task ends  
//!
//! No future or asynchronous path can forget to decrement the counter,
//! even if a task returns early or fails.
//!
//! This makes shutdown and idle detection **fully deterministic**.
//!
//!
//! ---
//!
//! ## Putting it together
//!
//! Using idle detection + new-task notification, you can build fully
//! reactive systems:
//!
//! - log listeners that sleep when nothing is happening  
//! - controllers that automatically enqueue new work  
//! - UIs that reflect real-time activity  
//! - scanners that continuously run until the user stops them  
//!
//! Both mechanisms operate efficiently without busy-wait polling,
//! without creating extra channels per listener, and without requiring
//! additional manual synchronization beyond the engine's built-in atomics and notification primitives/
//!
//!
//! # Example: end-to-end usage
//!
//! ```rust,no_run
//! use stalkermap::scanner::*;
//! use stalkermap::actions;
//! use stalkermap::utils::UrlParser;
//! use tokio_stream::StreamExt;
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a scanner with JSON-formatted logs
//!     // You can also set custom options on your `Scanner`
//!     let scanner = Scanner::<StructuredFormatter>::new().build();
//!
//!     // Get the log stream
//!     let mut logs = scanner.get_logs_stream().await.unwrap();
//!
//!     // Add initial task
//!     scanner.add_task(
//!         actions!(ActionIsPortOpen {}), // Add your custom actions here!
//!         UrlParser::from_str("https://127.0.0.1:80").unwrap()
//!     );
//!
//!     // Start consuming logs in the background
//!     tokio::spawn(async move {
//!         loop {
//!             match logs.next().await {
//!                 Some(record) => {
//!                     println!("log event: {record:?}");
//!
//!                     // Pause until more tasks are added
//!                     if StructuredFormatter.is_idle_signal(&record) {
//!                         logs.notify_when_new_tasks().await;
//!                     }
//!                 }
//!                 None => break
//!             }
//!         }
//!     });
//!
//!     // Execute tasks
//!     scanner.execute_tasks();
//!
//!     // Wait for scanner to become idle
//!     scanner.await_idle().await;
//!
//!     // Add more tasks dynamically
//!     scanner.add_multiple_tasks(vec![
//!         Task::new(actions!(ActionIsPortOpen {}) , UrlParser::from_str("https://127.0.0.1:443").unwrap())
//!     ]);
//!
//!     // Shutdown gracefully
//!     scanner.shutdown_graceful().await;
//! }
//! ```
//!
//! ---
//!
//! ## Design Notes
//!
//! - Task execution is **at most once** — tasks are popped from the queue and never re-queued.  
//! - Buffer re-use dramatically reduces allocations during high-volume scanning.  
//! - Log formatting is fully user-defined via [`LogFormatter`].  
//! - Shutdown is **cooperative**: running tasks are allowed to finish.  
//! - `await_idle()` is deterministic and never races tasks due to internal counters.  
//!
//! The design emphasizes:
//!
//! - clarity over magic  
//! - explicit task management  
//! - safety through atomics and Notify  
//! - predictable async behavior under load  
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
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
    task::yield_now,
    time::timeout,
};
use tokio_stream::{StreamExt, wrappers::BroadcastStream};
use tokio_util::sync::CancellationToken;

pub mod actions;
pub use actions::{Action, ActionIsPortOpen, ScanContext};
pub mod formatter;
pub use formatter::{JsonFormatter, LogFormatter, RawFormatter, StructuredFormatter};
mod buffer_pool;
use crate::{
    scanner::buffer_pool::{Buffer, BufferExt, BufferPool},
    utils::UrlParser,
};

/// High-level asynchronous interface for the scanning engine.
///
/// A type implementing [`Stalker`] represents a fully operational scanner
/// instance. It exposes the public API for:
///
/// - adding tasks
/// - executing queued tasks
/// - consuming the log stream
/// - detecting idle states
/// - performing graceful shutdown
///
/// Users never interact with the internal engine (`BuiltScanner`);  
/// they only use a trait object returned from [`Scanner::build`].
///
/// # Type Parameters
/// - `F`: The [`LogFormatter`] implementation used to serialize log events.
///
/// # Concurrency
/// All methods are thread-safe and can be called from multiple tasks without
/// additional synchronization.
#[async_trait]
pub trait Stalker: Send + Sync + 'static {
    type F: LogFormatter;

    /// Adds a single task to the scanning queue.
    fn add_task(&self, task: Vec<Box<dyn Action>>, target: UrlParser);

    /// Adds multiple pre-built tasks to the scanning queue.
    fn add_multiple_tasks(&self, tasks: Vec<Task>);

    /// Returns the total number of tasks on the `TaskPool`.
    fn total_tasks(&self) -> usize;
    /// Returns the total number of pending tasks.
    fn total_tasks_on_queue(&self) -> usize;

    /// Executes all tasks currently in the queue asynchronously.
    ///
    /// Tasks are executed concurrently up to the `batch_size` limit.
    /// Each task runs at most once, and log events are streamed via the configured formatter.
    fn execute_tasks(&self);

    /// Returns a stream of log events produced during task execution.
    async fn get_logs_stream(&self) -> Option<TaskAwareStream<<Self::F as LogFormatter>::Output>>;

    /// Signals the scanner to shut down and release resources.
    ///
    /// All running tasks will continue until completion, but no new tasks will be accepted.
    async fn shutdown_graceful(&self);

    /// Signals the scanner to idle.
    ///
    /// All running tasks will continue until completion, new tasks will be accepted.
    async fn await_idle(&self);
}

/// Thread-safe queue of pending tasks.
type TaskPool = Arc<Mutex<VecDeque<Task>>>;

/// Structured representation of a scanner log entry.
///
/// Produced by [`StructuredFormatter`] and [`JsonFormatter`], and emitted
/// through the broadcast channel.
///
/// Contains:
/// - `header_response`: map of action → result
/// - `data`: raw or decoded bytes from the TCP probe
///
/// # Idle signal
/// Log consumers can use [`is_idle_signal`](LogFormatter::is_idle_signal) to detect
/// when the scanner becomes idle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogRecord {
    pub header_response: LogHeader,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogHeader {
    pub actions_results: HashMap<String, String>,
}

/// A unit of work to be executed by the scanning engine.
///
/// A `Task` contains:
/// - a list of `Actions` to execute
/// - a [`UrlParser`] target (host, IP, port, scheme, etc.)
///
/// Tasks run **at most once**, are placed in a FIFO queue, and
/// are consumed by [`execute_tasks`](Stalker::execute_tasks).
///
/// # Examples
/// ```rust,ignore
/// let task = Task::new(
///     actions!(ActionIsPortOpen {}),
///     UrlParser::from_str("https://127.0.0.1:443").unwrap(),
/// );
/// ```
pub struct Task {
    /// Actions that define the workflow for this task.
    todo: Vec<Box<dyn Action>>,
    /// The target (host, URL, IP, etc.) to be scanned.
    target: UrlParser,
}

impl Task {
    /// Creates a new task for the given `target` with the specified `actions`.
    pub fn new(todo: Vec<Box<dyn Action>>, target: UrlParser) -> Self {
        Self { todo, target }
    }
}

/// A log stream that is aware of scanner activity.
///
/// Returned by [`Stalker::get_logs_stream`], this stream wraps a
/// `BroadcastStream` and also holds a `Notify` handle that wakes
/// listeners when new tasks are added.
///
/// This enables an ergonomic pattern:
///
/// - process logs normally
/// - detect idle via the formatter
/// - wait until new tasks are added
///
/// # Methods
/// - [`next`](Self::next): receive next log event
/// - [`notify_when_new_tasks`](Self::notify_when_new_tasks): block until more tasks arrive
///
/// # Idle handling
/// When the scanner emits `idle_output()` via the formatter, the listener
/// can call `.notify_when_new_tasks()` to suspend its loop until more
/// tasks are queued.
pub struct TaskAwareStream<T> {
    inner: BroadcastStream<T>,
    notify: Arc<Notify>,
}

impl<T: Clone + Send + Sync + 'static> TaskAwareStream<T> {
    pub fn new(rx: broadcast::Receiver<T>, notify: Arc<Notify>) -> Self {
        Self {
            inner: BroadcastStream::new(rx),
            notify,
        }
    }

    pub async fn next(&mut self) -> Option<T> {
        while let Some(msg) = self.inner.next().await {
            match msg {
                Ok(val) => return Some(val),
                Err(_) => continue,
            }
        }
        None
    }

    pub async fn notify_when_new_tasks(&self) {
        self.notify.notified().await;
    }
}

/// Runtime configuration for the scanning engine.
///
/// Controls batching, timeouts and general operational constraints.
///
/// # Fields
/// - `batch_size`: maximum number of tasks allowed to run simultaneously
/// - `timeout_ms`: network timeout applied to connection attempts
///
/// # Defaults
/// ```rust,ignore
/// ScannerOptions {
///     batch_size: 100,
///     timeout_ms: 500,
/// }
/// ```
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

/// Core shared state for the scanning engine.
///
/// This type does **not** execute tasks.  
/// It stores all runtime components:
///
/// - the task queue (`TaskPool`)
/// - atomic counters for active/pending tasks
/// - a shared `BufferPool` for zero-allocation reading
/// - a broadcast logger (`logger_tx`)
/// - the log formatter
/// - the cancellation token
/// - idle notification mechanisms
///
/// A user never constructs this directly.  
/// Instead, call:
///
/// - [`Scanner::new`] to create a configured scanner
/// - [`Scanner::build`] to obtain an [`Arc<dyn Stalker>`]
///
/// The resulting trait object is the actual engine.
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
    buffer_pool: Arc<BufferPool>,
    /// Broadcast channel for log events.
    logger_tx: Arc<Mutex<Option<broadcast::Sender<<F as LogFormatter>::Output>>>>,
    /// Formatter used to serialize log events.
    pub logger_format: Arc<F>,
    cancellation_token: Arc<CancellationToken>,
    idle_notify: Arc<Notify>,
}

/// RAII guard for accurate active task counting.
///
/// When dropped, it decrements `active_tasks` and emits an idle notification
/// if no active or pending tasks remain.
///
/// This ensures:
/// - no race conditions
/// - deterministic idle detection
/// - correct behavior even under cancellation or panics
struct ActiveTasksGuard {
    active_tasks: Arc<AtomicUsize>,
    pending_tasks: Arc<AtomicUsize>,
    idle_notify: Arc<Notify>,
}

impl Drop for ActiveTasksGuard {
    fn drop(&mut self) {
        if self.active_tasks.fetch_sub(1, Ordering::SeqCst) == 1
            && self.pending_tasks.load(Ordering::SeqCst) == 0
        {
            self.idle_notify.notify_waiters();
        }
    }
}

/// Internal runtime implementing the [`Stalker`] trait.
///
/// This is the operational engine:
/// - pops tasks from the queue
/// - manages concurrency via a `Semaphore`
/// - executes async network probes
/// - sends formatted logs over `broadcast`
/// - implements idle detection and graceful shutdown
///
/// Users should **never reference** this type directly.
/// It is hidden behind `Arc<dyn Stalker>`.
struct BuiltScanner<F>(Arc<Scanner<F>>)
where
    F: LogFormatter;

#[async_trait]
impl<F> Stalker for BuiltScanner<F>
where
    F: LogFormatter,
{
    type F = F;

    fn add_task(&self, task: Vec<Box<dyn Action>>, target: UrlParser) {
        self.0.pending_tasks.fetch_add(1, Ordering::SeqCst);
        let mut pool = { self.0.task_pool.lock() };

        pool.push_back(Task { todo: task, target });
        self.0.idle_notify.notify_waiters();
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
            loop {
                let timeout_t = scanner.options.timeout_ms;

                let maybe_task = { scanner.task_pool.lock().pop_front() };

                if let Some(task) = maybe_task {
                    let permit = match batch_size.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            break;
                        }
                    };

                    let logs_tx = scanner.logger_tx.clone();
                    let log_format = scanner.logger_format.clone();

                    let addr = format!(
                        "{}:{}",
                        task.target.target,
                        if task.target.port == 0 {
                            80
                        } else {
                            task.target.port
                        }
                    );

                    let buffer_pool = scanner.buffer_pool.clone();
                    let cancel_token = scanner.cancellation_token.clone();

                    let active_tasks = scanner.active_tasks.clone();
                    let pending_tasks = scanner.pending_tasks.clone();
                    let idle_notify = scanner.idle_notify.clone();

                    active_tasks.fetch_add(1, Ordering::SeqCst);
                    pending_tasks.fetch_sub(1, Ordering::SeqCst);

                    tokio::task::spawn(async move {
                        let _guard = ActiveTasksGuard {
                            active_tasks,
                            pending_tasks,
                            idle_notify,
                        };

                        if cancel_token.is_cancelled() {
                            return;
                        }

                        let mut buf = buffer_pool.get();

                        let stream = match timeout(
                            Duration::from_millis(timeout_t),
                            TcpStream::connect(addr),
                        )
                        .await
                        {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                let mut actions_results: HashMap<String, String> = HashMap::new();
                                actions_results.insert(
                                    ActionIsPortOpen {}.name().to_string(),
                                    "closed".to_string(),
                                );
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
                                let mut actions_results: HashMap<String, String> = HashMap::new();
                                actions_results.insert(
                                    ActionIsPortOpen {}.name().to_string(),
                                    "timeout".to_string(),
                                );
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

                        let ctx = ScanContext {
                            target_addr: &task.target.target,
                            port: task.target.port,
                            task_id: tokio::task::id(),
                        };

                        let mut actions_results: HashMap<String, String> = HashMap::new();
                        let mut raw_data: &[u8] = &[];
                        for a in &task.todo {
                            match a.set_read_from_successfull_connection() {
                                true => {
                                    let len = match stream.try_read(buf.as_bytes_mut()) {
                                        Ok(n) => n,
                                        Err(ref e)
                                            if e.kind() == tokio::io::ErrorKind::WouldBlock =>
                                        {
                                            0
                                        }
                                        Err(_) => 0,
                                    };

                                    // SAFETY: `try_read()` writes exactly `len` bytes into the provided buffer,
                                    // and `len` is guaranteed to be <= buffer size. In case of any read error or
                                    // failure, `len` is set to 0, ensuring no uninitialized memory is ever read.
                                    // Therefore, the slice created here only covers initialized memory.
                                    raw_data = unsafe { buf.as_bytes(len) };

                                    // Set Action Results
                                    a.execute_after_successfull_connection_and_read(
                                        &ctx,
                                        raw_data,
                                        &mut actions_results,
                                    );
                                }
                                false => {
                                    a.execute_after_successfull_connection(
                                        &ctx,
                                        &mut actions_results,
                                    );
                                }
                            }
                        }

                        let log = log_format.format(actions_results, raw_data);

                        if let Some(logs_tx) = logs_tx.lock().as_ref() {
                            logs_tx.send(log).ok();
                        }
                        buffer_pool.put(buf as Buffer);
                        drop(permit);
                    });
                } else {
                    yield_now().await;
                }
            }
        });
    }

    fn add_multiple_tasks(&self, tasks: Vec<Task>) {
        self.0.idle_notify.notify_waiters();
        let mut pool = { self.0.task_pool.lock() };
        tasks.into_iter().for_each(|t| {
            self.0.pending_tasks.fetch_add(1, Ordering::SeqCst);
            pool.push_back(t)
        });
    }

    async fn get_logs_stream(&self) -> Option<TaskAwareStream<<Self::F as LogFormatter>::Output>> {
        self.0
            .logger_tx
            .lock()
            .as_ref()
            .map(|logs_tx| TaskAwareStream::new(logs_tx.subscribe(), self.0.idle_notify.clone()))
    }

    async fn await_idle(&self) {
        loop {
            let active = self.0.active_tasks.load(Ordering::SeqCst);
            let pending = self.0.pending_tasks.load(Ordering::SeqCst);

            if pending == 0 && active == 0 {
                let event = self.0.logger_format.idle_output();

                if let Some(logs_tx) = self.0.logger_tx.lock().as_ref() {
                    logs_tx.send(event).ok();
                }
                break;
            }
        }
    }

    async fn shutdown_graceful(&self) {
        self.await_idle().await;
        self.0.cancellation_token.cancel();

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
            buffer_pool: Arc::new(BufferPool::new()),
            logger_tx: Arc::new(Mutex::new(Some(sender))),
            logger_format: Arc::new(F::default()),
            cancellation_token: Arc::new(CancellationToken::new()),
            idle_notify: Arc::new(Notify::new()),
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
    use crate::actions;
    use crate::scanner::*;
    use crate::utils::*;
    use std::str::FromStr;

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
            actions!(ActionIsPortOpen {}),
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        );
        scanner.add_task(
            actions!(ActionIsPortOpen {}),
            UrlParser::from_str("https://127.0.0.1:120").unwrap(),
        );

        assert_eq!(scanner.total_tasks(), 2);
    }

    #[tokio::test]
    async fn test_scanner_add_multiple_tasks() {
        let scanner = Scanner::<StructuredFormatter>::new().build();

        let l = vec![
            Task::new(
                actions!(ActionIsPortOpen {}),
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
            Task::new(
                actions!(ActionIsPortOpen {}),
                UrlParser::from_str("https://127.0.0.1:20").unwrap(),
            ),
            Task::new(
                actions!(ActionIsPortOpen {}),
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
        ];

        scanner.add_multiple_tasks(l);

        assert_eq!(scanner.total_tasks(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_scanner_logger_stream() {
        let scanner = Scanner::<StructuredFormatter>::new().build();
        let mut logs = scanner.get_logs_stream().await.unwrap();

        let l = vec![
            Task::new(
                actions!(ActionIsPortOpen {}),
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
            Task::new(
                actions!(ActionIsPortOpen {}),
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
            Task::new(
                actions!(ActionIsPortOpen {}),
                UrlParser::from_str("https://127.0.0.1:80").unwrap(),
            ),
        ];

        scanner.add_multiple_tasks(l);

        assert_eq!(scanner.total_tasks(), 3);

        tokio::spawn(async move {
            while let Some(log) = logs.next().await {
                if StructuredFormatter.is_idle_signal(&log) {
                    logs.notify_when_new_tasks().await;
                } else {
                    println!("Log: {:#?}", log);
                }
            }
        });
        scanner.execute_tasks();

        scanner.shutdown_graceful().await;

        assert_eq!(scanner.total_tasks_on_queue(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_action_is_port_open_open_port() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let scanner = Scanner::<StructuredFormatter>::new().build();
        let mut logs = scanner.get_logs_stream().await.unwrap();

        scanner.add_task(
            actions!(ActionIsPortOpen {}),
            UrlParser::new(format!("http://127.0.0.1:{}", port).as_str()).unwrap(),
        );
        scanner.execute_tasks();

        let mut found = false;

        while let Some(record) = logs.next().await {
            if StructuredFormatter.is_idle_signal(&record) {
                break;
            }

            if let Some(v) = record.header_response.actions_results.get("IsPortOpen") {
                assert_eq!(v, "open");
                found = true;
            }
        }

        assert!(found);
    }
}
