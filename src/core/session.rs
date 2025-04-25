use crate::core::attack::{AttackConfig, AttackProgress, AttackResult};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

/// Represents a session that can be saved and loaded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique name of the session
    pub name: String,
    
    /// When the session was created
    pub created_at: DateTime<Utc>,
    
    /// When the session was last modified
    pub updated_at: DateTime<Utc>,
    
    /// Attack configuration
    pub config: Option<AttackConfig>,
    
    /// Attack progress
    pub progress: Option<AttackProgress>,
    
    /// Attack results
    pub results: Vec<AttackResult>,
    
    /// Session notes
    pub notes: String,
}

impl Session {
    /// Create a new session
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        
        Self {
            name,
            created_at: now,
            updated_at: now,
            config: None,
            progress: None,
            results: Vec::new(),
            notes: String::new(),
        }
    }
    
    /// Update the attack configuration
    pub fn update_config(&mut self, config: AttackConfig) {
        self.config = Some(config);
        self.updated_at = Utc::now();
    }
    
    /// Update the attack progress and results
    pub fn update_attack_data(&mut self, progress: AttackProgress, results: Vec<AttackResult>) {
        self.progress = Some(progress);
        self.results = results;
        self.updated_at = Utc::now();
    }
    
    /// Update the session notes
    pub fn update_notes(&mut self, notes: String) {
        self.notes = notes;
        self.updated_at = Utc::now();
    }
    
    /// Check if the session has any successful results
    pub fn has_successful_results(&self) -> bool {
        self.results.iter().any(|r| r.success)
    }
    
    /// Get successful credentials
    pub fn get_successful_credentials(&self) -> Vec<(&str, &str)> {
        self.results
            .iter()
            .filter(|r| r.success)
            .map(|r| (r.username.as_str(), r.password.as_str()))
            .collect()
    }
    
    /// Merge another session into this one
    pub fn merge(&mut self, other: &Session) {
        // Keep only unique results
        let existing_results: std::collections::HashSet<_> = self.results
            .iter()
            .map(|r| (r.target.clone(), r.port, r.protocol, r.username.clone(), r.password.clone()))
            .collect();
            
        let new_results: Vec<_> = other.results
            .iter()
            .filter(|r| !existing_results.contains(&(r.target.clone(), r.port, r.protocol, r.username.clone(), r.password.clone())))
            .cloned()
            .collect();
            
        self.results.extend(new_results);
        
        // Update progress if available and newer
        if let Some(other_progress) = &other.progress {
            if let Some(self_progress) = &self.progress {
                if other_progress.attempts_made > self_progress.attempts_made {
                    self.progress = Some(other_progress.clone());
                }
            } else {
                self.progress = Some(other_progress.clone());
            }
        }
        
        // Update notes if other has notes
        if !other.notes.is_empty() {
            if self.notes.is_empty() {
                self.notes = other.notes.clone();
            } else {
                self.notes.push_str("\n\n");
                self.notes.push_str(&other.notes);
            }
        }
        
        self.updated_at = Utc::now();
    }
    
    /// Export the session to a file
    pub fn export(&self, path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    /// Import a session from a file
    pub fn import(path: &PathBuf) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let session: Session = serde_json::from_str(&json)?;
        Ok(session)
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
        self.progress = Some(AttackProgress {
            attempts_made: progress as u64,
            total_attempts: 100,
        });
        self.updated_at = Utc::now();
    }
    
    /// Mark the session as complete
    pub fn mark_complete(&mut self) {
        self.progress = Some(AttackProgress {
            attempts_made: 100,
            total_attempts: 100,
        });
        self.updated_at = Utc::now();
    }
} 