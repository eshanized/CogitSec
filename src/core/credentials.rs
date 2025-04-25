use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Represents a set of login credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// Username
    pub username: String,
    
    /// Password
    pub password: String,
}

impl Credentials {
    /// Create a new credentials instance
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// Manages lists of usernames and passwords
pub struct CredentialManager {
    /// List of usernames
    usernames: Vec<String>,
    
    /// List of passwords
    passwords: Vec<String>,
}

impl CredentialManager {
    /// Create a new credential manager
    pub fn new() -> Self {
        Self {
            usernames: Vec::new(),
            passwords: Vec::new(),
        }
    }
    
    /// Load usernames from a file
    pub fn load_usernames<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open username file {:?}", path.as_ref()))?;
        
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                self.usernames.push(line.trim().to_string());
            }
        }
        
        Ok(())
    }
    
    /// Load passwords from a file
    pub fn load_passwords<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open password file {:?}", path.as_ref()))?;
        
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                self.passwords.push(line.trim().to_string());
            }
        }
        
        Ok(())
    }
    
    /// Get a list of all possible username/password combinations
    pub fn all_combinations(&self) -> Vec<Credentials> {
        let mut result = Vec::with_capacity(self.usernames.len() * self.passwords.len());
        
        for username in &self.usernames {
            for password in &self.passwords {
                result.push(Credentials::new(username, password));
            }
        }
        
        result
    }
    
    /// Get the number of usernames
    pub fn username_count(&self) -> usize {
        self.usernames.len()
    }
    
    /// Get the number of passwords
    pub fn password_count(&self) -> usize {
        self.passwords.len()
    }
    
    /// Get the total number of possible combinations
    pub fn combination_count(&self) -> usize {
        self.usernames.len() * self.passwords.len()
    }
} 