use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Represents a wordlist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wordlist {
    /// Name of the wordlist
    pub name: String,
    
    /// Path to the wordlist file
    pub path: PathBuf,
    
    /// Description of the wordlist
    pub description: Option<String>,
    
    /// Number of words in the wordlist
    pub word_count: usize,
    
    /// Type of the wordlist (username or password)
    pub wordlist_type: WordlistType,
}

/// Type of wordlist
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WordlistType {
    /// Username list
    Username,
    
    /// Password list
    Password,
}

impl Wordlist {
    /// Create a new wordlist
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>, wordlist_type: WordlistType) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            description: None,
            word_count: 0,
            wordlist_type,
        }
    }
    
    /// Load the wordlist and count words
    pub fn load(&mut self) -> Result<()> {
        let file = File::open(&self.path)
            .with_context(|| format!("Failed to open wordlist file {:?}", self.path))?;
            
        let reader = BufReader::new(file);
        let mut count = 0;
        
        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                count += 1;
            }
        }
        
        self.word_count = count;
        Ok(())
    }
    
    /// Read the contents of the wordlist
    pub fn read_contents(&self) -> Result<Vec<String>> {
        let file = File::open(&self.path)
            .with_context(|| format!("Failed to open wordlist file {:?}", self.path))?;
            
        let reader = BufReader::new(file);
        let mut words = Vec::new();
        
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                words.push(trimmed.to_string());
            }
        }
        
        Ok(words)
    }
}

/// Manages wordlists
pub struct WordlistManager {
    /// Path to the wordlist directory
    wordlist_dir: PathBuf,
    
    /// List of available wordlists
    wordlists: Vec<Wordlist>,
}

impl WordlistManager {
    /// Create a new wordlist manager
    pub fn new(wordlist_dir: impl Into<PathBuf>) -> Self {
        Self {
            wordlist_dir: wordlist_dir.into(),
            wordlists: Vec::new(),
        }
    }
    
    /// Initialize the wordlist manager
    pub fn initialize(&mut self) -> Result<()> {
        // Create wordlist directory if it doesn't exist
        if !self.wordlist_dir.exists() {
            fs::create_dir_all(&self.wordlist_dir)
                .with_context(|| format!("Failed to create wordlist directory {:?}", self.wordlist_dir))?;
        }
        
        // Load wordlists
        self.load_wordlists()?;
        
        Ok(())
    }
    
    /// Load wordlists from the wordlist directory
    pub fn load_wordlists(&mut self) -> Result<()> {
        self.wordlists.clear();
        
        if !self.wordlist_dir.exists() {
            return Ok(());
        }
        
        let entries = fs::read_dir(&self.wordlist_dir)
            .with_context(|| format!("Failed to read wordlist directory {:?}", self.wordlist_dir))?;
            
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                if let Some(file_name) = path.file_name() {
                    let name = file_name.to_string_lossy().to_string();
                    
                    // Determine wordlist type based on file name
                    let wordlist_type = if name.to_lowercase().contains("user") 
                        || name.to_lowercase().contains("username") {
                        WordlistType::Username
                    } else {
                        WordlistType::Password
                    };
                    
                    let mut wordlist = Wordlist::new(name, &path, wordlist_type);
                    if let Err(err) = wordlist.load() {
                        eprintln!("Failed to load wordlist {:?}: {}", path, err);
                        continue;
                    }
                    
                    self.wordlists.push(wordlist);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get all wordlists
    pub fn get_wordlists(&self) -> &[Wordlist] {
        &self.wordlists
    }
    
    /// Get username wordlists
    pub fn get_username_wordlists(&self) -> Vec<&Wordlist> {
        self.wordlists.iter()
            .filter(|w| w.wordlist_type == WordlistType::Username)
            .collect()
    }
    
    /// Get password wordlists
    pub fn get_password_wordlists(&self) -> Vec<&Wordlist> {
        self.wordlists.iter()
            .filter(|w| w.wordlist_type == WordlistType::Password)
            .collect()
    }
    
    /// Add a wordlist
    pub fn add_wordlist(&mut self, name: impl Into<String>, source_path: impl AsRef<Path>, wordlist_type: WordlistType) -> Result<()> {
        let name = name.into();
        let target_path = self.wordlist_dir.join(&name);
        
        // Copy the wordlist file
        fs::copy(source_path.as_ref(), &target_path)
            .with_context(|| format!("Failed to copy wordlist from {:?} to {:?}", source_path.as_ref(), target_path))?;
            
        // Create and add the wordlist
        let mut wordlist = Wordlist::new(name, target_path, wordlist_type);
        wordlist.load()?;
        
        self.wordlists.push(wordlist);
        
        Ok(())
    }
    
    /// Remove a wordlist
    pub fn remove_wordlist(&mut self, name: &str) -> Result<()> {
        let index = self.wordlists.iter().position(|w| w.name == name);
        
        if let Some(index) = index {
            let wordlist = &self.wordlists[index];
            
            // Delete the wordlist file
            fs::remove_file(&wordlist.path)
                .with_context(|| format!("Failed to remove wordlist file {:?}", wordlist.path))?;
                
            // Remove from the list
            self.wordlists.remove(index);
        }
        
        Ok(())
    }
} 