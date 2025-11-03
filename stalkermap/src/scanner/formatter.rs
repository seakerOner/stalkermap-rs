use super::*;

/// Trait for formatting scan results.
///
/// A `LogFormatter` defines how raw scan results and action outcomes
/// are converted into a structured output type.
pub trait LogFormatter: Send + Sync + 'static {
    type Output: Send + Sync + 'static + Clone + Debug;

    fn format(&self, actions_results: HashMap<Actions, String>, raw_data: &[u8]) -> Self::Output;
}

/// Formats scan results as raw bytes.
pub struct RawFormatter;
/// Formats scan results as structured Rust types (`LogRecord`).
pub struct StructuredFormatter;
/// Formats scan results as JSON strings.
pub struct JsonFormatter;

impl LogFormatter for RawFormatter {
    type Output = Vec<u8>;

    fn format(&self, _actions_results: HashMap<Actions, String>, raw_data: &[u8]) -> Self::Output {
        raw_data.to_vec()
    }
}

impl Default for RawFormatter {
    fn default() -> Self {
        Self
    }
}

impl LogFormatter for StructuredFormatter {
    type Output = LogRecord;

    fn format(&self, actions_results: HashMap<Actions, String>, raw_data: &[u8]) -> Self::Output {
        LogRecord {
            header_response: LogHeader { actions_results },
            data: String::from_utf8_lossy(raw_data).into_owned(),
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

    fn format(&self, actions_results: HashMap<Actions, String>, raw_data: &[u8]) -> Self::Output {
        serde_json::to_string(&LogRecord {
            header_response: LogHeader { actions_results },
            data: String::from_utf8_lossy(raw_data).into_owned(),
        })
        .unwrap()
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self
    }
}
