use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// Information messages
    Info,
    
    /// Warning messages
    Warning,
    
    /// Error messages
    Error,
    
    /// Debug messages
    Debug,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Debug => write!(f, "DEBUG"),
        }
    }
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp of the entry
    pub timestamp: DateTime<Utc>,
    
    /// Log level
    pub level: LogLevel,
    
    /// Message
    pub message: String,
    
    /// Source (file, line, function, etc.)
    pub source: Option<String>,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(level: LogLevel, message: impl Into<String>, source: Option<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            message: message.into(),
            source,
        }
    }
    
    /// Create a new info log entry
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, message, None)
    }
    
    /// Create a new warning log entry
    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Warning, message, None)
    }
    
    /// Create a new error log entry
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, message, None)
    }
    
    /// Create a new debug log entry
    pub fn debug(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Debug, message, None)
    }
}

/// Logger for collecting and storing log entries
pub struct Logger {
    /// Log entries
    entries: Vec<LogEntry>,
    
    /// Maximum number of entries to keep
    max_entries: usize,
}

impl Logger {
    /// Create a new logger
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }
    
    /// Log an entry
    pub fn log(&mut self, entry: LogEntry) {
        self.entries.push(entry);
        
        // Remove oldest entries if we exceed the maximum
        if self.entries.len() > self.max_entries {
            self.entries.drain(0..self.entries.len() - self.max_entries);
        }
    }
    
    /// Log an info message
    pub fn info(&mut self, message: impl Into<String>) {
        self.log(LogEntry::info(message));
    }
    
    /// Log a warning message
    pub fn warning(&mut self, message: impl Into<String>) {
        self.log(LogEntry::warning(message));
    }
    
    /// Log an error message
    pub fn error(&mut self, message: impl Into<String>) {
        self.log(LogEntry::error(message));
    }
    
    /// Log a debug message
    pub fn debug(&mut self, message: impl Into<String>) {
        self.log(LogEntry::debug(message));
    }
    
    /// Get all log entries
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }
    
    /// Clear all log entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }
} 