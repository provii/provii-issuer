// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Structured logging for the issuer service.
//!
//! Provides JSON-formatted logs with consistent structure for machine parsing and SIEM integration.
//! All logs include timestamp, level, request_id, and contextual information.

use std::sync::OnceLock;

use serde::Serialize;
use serde_json::json;

static CONFIGURED_LOG_LEVEL: OnceLock<LogLevel> = OnceLock::new();

fn configured_level() -> LogLevel {
    *CONFIGURED_LOG_LEVEL.get_or_init(|| {
        match std::env::var("LOG_LEVEL")
            .unwrap_or_else(|_| "info".to_string())
            .to_lowercase()
            .as_str()
        {
            "error" => LogLevel::Error,
            "warn" | "warning" => LogLevel::Warn,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => LogLevel::Info,
        }
    })
}

/// Log levels matching standard severity levels.
/// Ordered by severity: Error (0) > Warn (1) > Info (2) > Debug (3) > Trace (4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn severity_rank(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }

    fn is_enabled(self, min: LogLevel) -> bool {
        self.severity_rank() <= min.severity_rank()
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Trace => write!(f, "TRACE"),
        }
    }
}

/// Structured log entry
#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(level: LogLevel, message: String) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level,
            request_id: None,
            correlation_id: None,
            message,
            context: None,
        }
    }

    /// Set request ID for correlation. Also populates `correlation_id`
    /// to the same value so downstream log aggregators can join on
    /// either field.
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.correlation_id = Some(request_id.clone());
        self.request_id = Some(request_id);
        self
    }

    /// Add structured context
    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }

    /// Output the log entry. Skips entries below the configured LOG_LEVEL.
    pub fn log(&self) {
        if !self.level.is_enabled(configured_level()) {
            return;
        }
        let json = serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"timestamp":"{}","level":"{}","message":"Log serialization failed"}}"#,
                chrono::Utc::now().to_rfc3339(),
                self.level
            )
        });
        crate::log!("{}", json);
    }
}

/// Log an error with structured context
pub fn log_error(message: impl Into<String>) -> LogEntry {
    LogEntry::new(LogLevel::Error, message.into())
}

/// Log a security event with full context.
///
/// The `request_id` is included as a top-level field for flat-key
/// indexing. Callers that lack a request_id should pass `None`; the
/// field falls back to `"unknown"` so every security log line carries a
/// joinable identifier.
pub fn log_security_event(
    event_type: &str,
    severity: LogLevel,
    request_id: Option<String>,
    details: serde_json::Value,
) {
    let rid = request_id.unwrap_or_else(|| "unknown".to_string());
    LogEntry::new(severity, format!("Security event: {}", event_type))
        .with_request_id(rid)
        .with_context(json!({
            "event_type": event_type,
            "security": true,
            "details": details
        }))
        .log();
}

/// Maximum path length logged. Paths exceeding this are truncated to
/// prevent log injection or excessive storage consumption.
const MAX_LOG_PATH_LEN: usize = 512;

/// Log an HTTP request.
///
/// The raw client IP is intentionally excluded from console logs.
/// IP-based audit data is captured separately via `audit::audit_log`,
/// which hashes IPs through `PrivacyContext` before persisting.
/// Paths longer than 512 bytes are truncated.
pub fn log_request(method: &str, path: &str, request_id: &str) {
    let safe_path = if path.len() > MAX_LOG_PATH_LEN {
        path.get(..MAX_LOG_PATH_LEN).unwrap_or(path)
    } else {
        path
    };
    LogEntry::new(LogLevel::Info, format!("{} {}", method, safe_path))
        .with_request_id(request_id.to_string())
        .with_context(json!({
            "http": true,
            "method": method,
            "path": safe_path,
        }))
        .log();
}

/// Log an HTTP response
pub fn log_response(status: u16, request_id: &str, duration_ms: Option<u64>) {
    let level = match status {
        200..=299 => LogLevel::Info,
        300..=399 => LogLevel::Info,
        400..=499 => LogLevel::Warn,
        _ => LogLevel::Error,
    };

    let mut context = json!({
        "http": true,
        "status": status,
    });

    if let Some(duration) = duration_ms {
        if let Some(obj) = context.as_object_mut() {
            obj.insert("duration_ms".to_string(), json!(duration));
        }
    }

    LogEntry::new(level, format!("Response: {}", status))
        .with_request_id(request_id.to_string())
        .with_context(context)
        .log();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "test message".to_string());
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "test message");
        assert!(entry.request_id.is_none());
        assert!(entry.correlation_id.is_none());
        assert!(entry.context.is_none());
    }

    #[test]
    fn test_log_entry_with_request_id() {
        let entry = LogEntry::new(LogLevel::Info, "test".to_string())
            .with_request_id("req-123".to_string());
        assert_eq!(entry.request_id, Some("req-123".to_string()));
        assert_eq!(
            entry.correlation_id,
            Some("req-123".to_string()),
            "correlation_id must mirror request_id"
        );
    }

    #[test]
    fn test_log_entry_with_context() {
        let context = json!({"key": "value"});
        let entry = LogEntry::new(LogLevel::Info, "test".to_string()).with_context(context.clone());
        assert_eq!(entry.context, Some(context));
    }

    #[test]
    fn test_log_entry_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let entry = LogEntry::new(LogLevel::Error, "test error".to_string())
            .with_request_id("req-123".to_string())
            .with_context(json!({"error_code": "E001"}));

        let json = serde_json::to_string(&entry)?;
        assert!(json.contains("\"level\":\"ERROR\""));
        assert!(json.contains("\"message\":\"test error\""));
        assert!(json.contains("\"request_id\":\"req-123\""));
        assert!(json.contains("\"correlation_id\":\"req-123\""));
        assert!(json.contains("\"error_code\":\"E001\""));
        Ok(())
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(format!("{}", LogLevel::Error), "ERROR");
        assert_eq!(format!("{}", LogLevel::Warn), "WARN");
        assert_eq!(format!("{}", LogLevel::Info), "INFO");
        assert_eq!(format!("{}", LogLevel::Debug), "DEBUG");
        assert_eq!(format!("{}", LogLevel::Trace), "TRACE");
    }

    #[test]
    fn test_severity_rank_ordering() {
        assert!(LogLevel::Error.severity_rank() < LogLevel::Warn.severity_rank());
        assert!(LogLevel::Warn.severity_rank() < LogLevel::Info.severity_rank());
        assert!(LogLevel::Info.severity_rank() < LogLevel::Debug.severity_rank());
        assert!(LogLevel::Debug.severity_rank() < LogLevel::Trace.severity_rank());
    }

    #[test]
    fn test_is_enabled_error_always_enabled() {
        assert!(LogLevel::Error.is_enabled(LogLevel::Error));
        assert!(LogLevel::Error.is_enabled(LogLevel::Warn));
        assert!(LogLevel::Error.is_enabled(LogLevel::Info));
        assert!(LogLevel::Error.is_enabled(LogLevel::Debug));
        assert!(LogLevel::Error.is_enabled(LogLevel::Trace));
    }

    #[test]
    fn test_is_enabled_trace_only_when_configured() {
        assert!(!LogLevel::Trace.is_enabled(LogLevel::Error));
        assert!(!LogLevel::Trace.is_enabled(LogLevel::Info));
        assert!(LogLevel::Trace.is_enabled(LogLevel::Trace));
    }

    #[test]
    fn test_is_enabled_info_not_debug() {
        assert!(!LogLevel::Info.is_enabled(LogLevel::Error));
        assert!(!LogLevel::Info.is_enabled(LogLevel::Warn));
        assert!(LogLevel::Info.is_enabled(LogLevel::Info));
        assert!(LogLevel::Info.is_enabled(LogLevel::Debug));
    }

    #[test]
    fn test_log_entry_fields_all_none_by_default() {
        let entry = LogEntry::new(LogLevel::Debug, "msg".to_string());
        assert!(entry.request_id.is_none());
        assert!(entry.correlation_id.is_none());
        assert!(entry.context.is_none());
    }

    #[test]
    fn test_log_entry_chaining() {
        let entry = LogEntry::new(LogLevel::Warn, "chained".to_string())
            .with_request_id("rid".to_string())
            .with_context(json!({"k": "v"}));
        assert_eq!(entry.level, LogLevel::Warn);
        assert_eq!(entry.message, "chained");
        assert_eq!(entry.request_id.as_deref(), Some("rid"));
        assert!(entry.context.is_some());
    }

    #[test]
    fn test_log_error_returns_error_level() {
        let entry = log_error("something failed");
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.message, "something failed");
    }
}
