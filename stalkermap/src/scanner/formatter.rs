//! Formatters for producing structured log output from scan results.
//!
//! A [`LogFormatter`] defines how the scanner converts raw network data and
//! action results into a concrete output type. This allows users to plug in
//! custom formatting logic or choose between the built-in implementations:
//!
//! - [`RawFormatter`] — returns raw bytes (`Vec<u8>`)
//! - [`StructuredFormatter`] — returns strongly-typed [`LogRecord`] structures
//! - [`JsonFormatter`] — returns JSON strings
//!
//! Formatters also define an *idle output* via [`LogFormatter::idle_output`],
//! which is used internally when the scanner enters an idle state (no tasks
//! remaining). Users may check for this value via [`LogRecord::is_idle_signal`]
//! or equivalent mechanisms.

use super::*;

/// Trait for formatting scan results.
///
/// A `LogFormatter` controls how:
///
/// - raw network bytes (`raw_data`)
/// - action results (`HashMap<Actions, String>`)
///
/// are converted into a user-facing output type.
///
/// Each formatter specifies its own [`Output`](LogFormatter::Output) type.  
/// The scanner remains fully generic over this associated type, allowing users
/// to plug in any formatter they choose.
///
/// ### Idle Values
///
/// Every formatter must also define an [`idle_output`](Self::idle_output),
/// which represents an “idle event” emitted by the log stream when the scanner
/// finishes all currently scheduled tasks.
///
/// This is used internally by:
///
/// - `Scanner::await_idle`
/// - log stream helpers such as `notify_when_new_tasks`
///
/// Users typically do **not** construct idle outputs manually; the scanner emits
/// them automatically.
///
/// # Examples
///
/// Using a built-in formatter:
///
/// ```rust,no_run
/// use stalkermap::scanner::Scanner;
/// use stalkermap::scanner::StructuredFormatter;
/// use stalkermap::scanner::LogFormatter;
///
/// #[tokio::main]
/// async fn main() {
///     use stalkermap::scanner::Scanner;
///     use stalkermap::scanner::StructuredFormatter;
///
///     let scanner = Scanner::<StructuredFormatter>::new().build();
///     let mut logs = scanner.get_logs_stream().await.unwrap();
///
///     loop {
///         match logs.next().await {
///             Some(log) => {
///                 if StructuredFormatter.is_idle_signal(&log) {
///                     logs.notify_when_new_tasks().await;
///                 } else {
///                     println!("Log: {:#?}", log);
///                 }
///             }
///             None => {
///                 break;
///             }
///         }
///     }
/// }
/// ```
pub trait LogFormatter: Send + Sync + 'static {
    type Output: Send + Sync + 'static + Clone + Debug + PartialEq;

    fn format(&self, actions_results: HashMap<String, String>, raw_data: &[u8]) -> Self::Output;

    fn idle_output(&self) -> Self::Output;

    fn is_idle_signal(&self, output: &Self::Output) -> bool {
        *output == self.idle_output()
    }
}

/// Formatter that returns scan results as raw bytes (`Vec<u8>`).
///
/// Useful for low-level or binary protocols.
pub struct RawFormatter;
/// Formatter that produces strongly-typed [`LogRecord`] values.
///
/// Useful for applications that want structured logs without serialization.
pub struct StructuredFormatter;
/// Formatter that serializes structured log records into JSON strings.
///
/// This is typically useful for:
/// - logging pipelines
/// - structured log ingestion systems
/// - sending logs across network boundaries
pub struct JsonFormatter;

impl LogFormatter for RawFormatter {
    /// The output type produced by this formatter.
    ///
    /// This type must be cloneable, thread-safe, and `'static`, since values
    /// may be passed across async tasks by the scanner.
    type Output = Vec<u8>;

    /// Formats action results and raw network data into the associated output type.
    fn format(&self, _actions_results: HashMap<String, String>, raw_data: &[u8]) -> Self::Output {
        raw_data.to_vec()
    }

    /// Returns the formatter's representation of an idle event.
    ///
    /// This value is emitted by the scanner whenever it becomes idle
    /// (i.e., no active or pending tasks).
    fn idle_output(&self) -> Self::Output {
        b"___IDLE___".to_vec()
    }
}

impl Default for RawFormatter {
    fn default() -> Self {
        Self
    }
}

impl LogFormatter for StructuredFormatter {
    type Output = LogRecord;

    fn format(&self, actions_results: HashMap<String, String>, raw_data: &[u8]) -> Self::Output {
        LogRecord {
            header_response: LogHeader { actions_results },
            data: String::from_utf8_lossy(raw_data).into_owned(),
        }
    }

    fn idle_output(&self) -> Self::Output {
        LogRecord {
            header_response: LogHeader {
                actions_results: HashMap::new(),
            },
            data: "idle".to_string(),
        }
    }
}

impl Default for StructuredFormatter {
    fn default() -> Self {
        Self
    }
}

impl LogFormatter for JsonFormatter {
    type Output = String;

    fn format(&self, actions_results: HashMap<String, String>, raw_data: &[u8]) -> Self::Output {
        serde_json::to_string(&LogRecord {
            header_response: LogHeader { actions_results },
            data: String::from_utf8_lossy(raw_data).into_owned(),
        })
        .unwrap()
    }

    fn idle_output(&self) -> Self::Output {
        serde_json::json!({"type": "idle"}).to_string()
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self
    }
}
