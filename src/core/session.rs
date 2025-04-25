use crate::core::attack::{AttackConfig, AttackResult};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

/// Represents a session that can be saved and loaded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique identifier for the session
    pub id: String,
    
    /// Name of the session
    pub name: String,
    
    /// When the session was created
    pub created_at: DateTime<Utc>,
    
    /// When the session was last modified
    pub updated_at: DateTime<Utc>,
    
    /// The attack configuration
    pub config: AttackConfig,
    
    /// The results of the attack
    pub results: Vec<AttackResult>,
    
    /// The current progress (0.0 - 1.0)
    pub progress: f64,
    
    /// Whether the session is complete
    pub is_complete: bool,
}

impl Session {
    /// Create a new session
    pub fn new(name: impl Into<String>, config: AttackConfig) -> Self {
        let now = Utc::now();
        let id = format!("session_{}", now.timestamp());
        
        Self {
            id,
            name: name.into(),
            created_at: now,
            updated_at: now,
            config,
            results: Vec::new(),
            progress: 0.0,
            is_complete: false,
        }
    }
    
    /// Save the session to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let file = File::create(path.as_ref())
            .with_context(|| format!("Failed to create session file {:?}", path.as_ref()))?;
            
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .with_context(|| "Failed to serialize session")?;
            
        Ok(())
    }
    
    /// Load a session from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open session file {:?}", path.as_ref()))?;
            
        let reader = BufReader::new(file);
        let session = serde_json::from_reader(reader)
            .with_context(|| "Failed to deserialize session")?;
            
        Ok(session)
    }
    
    /// Add a result to the session
    pub fn add_result(&mut self, result: AttackResult) {
        self.results.push(result);
        self.updated_at = Utc::now();
    }
    
    /// Update the progress
    pub fn update_progress(&mut self, progress: f64) {
        self.progress = progress;
        self.updated_at = Utc::now();
    }
    
    /// Mark the session as complete
    pub fn mark_complete(&mut self) {
        self.is_complete = true;
        self.progress = 1.0;
        self.updated_at = Utc::now();
    }
} 