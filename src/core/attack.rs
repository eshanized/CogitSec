use crate::core::protocols::{Protocol, ProtocolFactory};
use crate::core::credentials::Credentials;
use crate::core::wordlist::WordlistManager;
use crate::core::logger::Logger;
use anyhow::{Result, Context, anyhow};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::sleep;
use log::{debug, info, warn, error};
use std::fs::File;
use std::io::{BufRead, BufReader};
use chrono::Utc;
use std::collections::HashMap;

/// Configuration for an attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    /// Target hostname or IP address
    pub target: String,
    
    /// Target port
    pub port: u16,
    
    /// Protocol to use for the attack
    pub protocol: Protocol,
    
    /// Path to username list
    pub username_list: PathBuf,
    
    /// Path to password list
    pub password_list: PathBuf,
    
    /// Number of concurrent tasks
    pub concurrency: usize,
    
    /// Delay between attempts
    pub delay: Duration,
    
    /// Whether to use SSL/TLS
    pub use_ssl: bool,
    
    /// Timeout for connection attempts
    pub timeout: Duration,
    
    /// Custom protocol options
    pub options: std::collections::HashMap<String, String>,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            port: 0,
            protocol: Protocol::SSH,
            username_list: PathBuf::new(),
            password_list: PathBuf::new(),
            concurrency: 10,
            delay: Duration::from_millis(100),
            use_ssl: false,
            timeout: Duration::from_secs(10),
            options: std::collections::HashMap::new(),
        }
    }
}

/// Result of an attack attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    /// Target that was attacked
    pub target: String,
    
    /// Port that was attacked
    pub port: u16,
    
    /// Protocol that was used
    pub protocol: Protocol,
    
    /// Username that was attempted
    pub username: String,
    
    /// Password that was attempted
    pub password: String,
    
    /// Whether the attempt was successful
    pub success: bool,
    
    /// Any error message (if applicable)
    pub error: Option<String>,
    
    /// Timestamp of the attempt
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Status of an attack
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackStatus {
    Idle,
    Running,
    Paused,
    Completed,
    Failed,
}

/// Progress of an attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackProgress {
    /// Status of the attack
    pub status: AttackStatus,
    
    /// Total number of attempts to make
    pub total_attempts: usize,
    
    /// Number of attempts made so far
    pub attempts_made: usize,
    
    /// Number of successful attempts
    pub successful_attempts: usize,
    
    /// Number of failed attempts
    pub failed_attempts: usize,
    
    /// Number of attempts with errors
    pub error_attempts: usize,
    
    /// Start time of the attack
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    
    /// End time of the attack
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    
    /// Estimated time remaining (in seconds)
    pub estimated_time_remaining: Option<u64>,
}

impl Default for AttackProgress {
    fn default() -> Self {
        Self {
            status: AttackStatus::Idle,
            total_attempts: 0,
            attempts_made: 0,
            successful_attempts: 0,
            failed_attempts: 0,
            error_attempts: 0,
            start_time: None,
            end_time: None,
            estimated_time_remaining: None,
        }
    }
}

/// Manages and executes attacks
pub struct AttackManager {
    /// Current attack configuration
    config: Option<AttackConfig>,
    
    /// Current attack progress
    progress: Arc<Mutex<AttackProgress>>,
    
    /// Attack results
    results: Arc<Mutex<Vec<AttackResult>>>,
    
    /// Logger
    logger: Arc<Mutex<Logger>>,
    
    /// Cancel channel
    cancel_tx: Option<mpsc::Sender<()>>,
    
    /// Pause channel
    pause_tx: Option<mpsc::Sender<bool>>,
}

impl AttackManager {
    /// Creates a new attack manager
    pub fn new(logger: Arc<Mutex<Logger>>) -> Self {
        Self {
            config: None,
            progress: Arc::new(Mutex::new(AttackProgress::default())),
            results: Arc::new(Mutex::new(Vec::new())),
            logger,
            cancel_tx: None,
            pause_tx: None,
        }
    }
    
    /// Get the current progress
    pub fn progress(&self) -> Arc<Mutex<AttackProgress>> {
        self.progress.clone()
    }
    
    /// Get the results
    pub fn results(&self) -> Arc<Mutex<Vec<AttackResult>>> {
        self.results.clone()
    }
    
    /// Cancel the current attack
    pub async fn cancel(&self) -> Result<()> {
        if let Some(tx) = &self.cancel_tx {
            let _ = tx.send(()).await;
            
            // Update progress
            let mut progress = self.progress.lock().unwrap();
            progress.status = AttackStatus::Idle;
            progress.end_time = Some(Utc::now());
        }
        
        Ok(())
    }
    
    /// Pause or resume the current attack
    pub async fn pause(&self, pause: bool) -> Result<()> {
        if let Some(tx) = &self.pause_tx {
            let _ = tx.send(pause).await;
            
            // Update progress
            let mut progress = self.progress.lock().unwrap();
            progress.status = if pause { AttackStatus::Paused } else { AttackStatus::Running };
        }
        
        Ok(())
    }
    
    /// Start a new attack with the given configuration
    pub async fn start(&mut self, config: AttackConfig) -> Result<()> {
        // Reset state
        *self.progress.lock().unwrap() = AttackProgress::default();
        self.results.lock().unwrap().clear();
        
        // Create channels for control
        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
        let (pause_tx, mut pause_rx) = mpsc::channel::<bool>(1);
        let (result_tx, mut result_rx) = mpsc::channel::<AttackResult>(100);
        
        self.cancel_tx = Some(cancel_tx);
        self.pause_tx = Some(pause_tx);
        self.config = Some(config.clone());
        
        // Clone Arc references for task
        let progress = self.progress.clone();
        let results = self.results.clone();
        let logger = self.logger.clone();
        
        // Create and start the attack task
        tokio::spawn(async move {
            if let Err(e) = Self::execute_attack(
                config, 
                progress.clone(), 
                results.clone(),
                logger.clone(),
                &mut cancel_rx, 
                &mut pause_rx,
                result_tx.clone()
            ).await {
                error!("Attack execution failed: {}", e);
                let mut progress = progress.lock().unwrap();
                progress.status = AttackStatus::Failed;
                progress.end_time = Some(Utc::now());
                
                // Log the error
                if let Ok(mut logger) = logger.lock() {
                    logger.log_error(&format!("Attack execution failed: {}", e));
                }
            }
        });
        
        // Process results
        tokio::spawn(async move {
            while let Some(result) = result_rx.recv().await {
                let mut results = results.lock().unwrap();
                results.push(result.clone());
                
                let mut progress = progress.lock().unwrap();
                progress.attempts_made += 1;
                
                if result.success {
                    progress.successful_attempts += 1;
                } else if result.error.is_some() {
                    progress.error_attempts += 1;
                } else {
                    progress.failed_attempts += 1;
                }
                
                // Calculate estimated time remaining
                if progress.attempts_made > 0 && progress.start_time.is_some() {
                    let elapsed = Utc::now()
                        .signed_duration_since(progress.start_time.unwrap())
                        .num_seconds() as f64;
                    
                    if elapsed > 0.0 {
                        let attempts_per_second = progress.attempts_made as f64 / elapsed;
                        let remaining_attempts = progress.total_attempts - progress.attempts_made;
                        
                        if attempts_per_second > 0.0 {
                            let estimated_seconds = remaining_attempts as f64 / attempts_per_second;
                            progress.estimated_time_remaining = Some(estimated_seconds as u64);
                        }
                    }
                }
                
                // Check if attack is complete
                if progress.attempts_made >= progress.total_attempts {
                    progress.status = AttackStatus::Completed;
                    progress.end_time = Some(Utc::now());
                    break;
                }
            }
        });
        
        Ok(())
    }
    
    /// Execute an attack with the given configuration
    async fn execute_attack(
        config: AttackConfig,
        progress: Arc<Mutex<AttackProgress>>,
        results: Arc<Mutex<Vec<AttackResult>>>,
        logger: Arc<Mutex<Logger>>,
        cancel_rx: &mut mpsc::Receiver<()>,
        pause_rx: &mut mpsc::Receiver<bool>,
        result_tx: mpsc::Sender<AttackResult>,
    ) -> Result<()> {
        // Load wordlists
        let username_file = File::open(&config.username_list)
            .with_context(|| format!("Failed to open username list: {:?}", config.username_list))?;
        let password_file = File::open(&config.password_list)
            .with_context(|| format!("Failed to open password list: {:?}", config.password_list))?;
        
        let usernames: Vec<String> = BufReader::new(username_file)
            .lines()
            .filter_map(|line| line.ok())
            .collect();
            
        let passwords: Vec<String> = BufReader::new(password_file)
            .lines()
            .filter_map(|line| line.ok())
            .collect();
        
        if usernames.is_empty() {
            return Err(anyhow!("Username list is empty"));
        }
        
        if passwords.is_empty() {
            return Err(anyhow!("Password list is empty"));
        }
        
        // Initialize progress
        let total_attempts = usernames.len() * passwords.len();
        {
            let mut progress = progress.lock().unwrap();
            progress.status = AttackStatus::Running;
            progress.total_attempts = total_attempts;
            progress.start_time = Some(Utc::now());
        }
        
        // Log information about the attack
        if let Ok(mut logger) = logger.lock() {
            logger.log_info(&format!(
                "Starting attack on {}:{} using protocol {:?} with {} usernames and {} passwords ({} total attempts)",
                config.target,
                config.port,
                config.protocol,
                usernames.len(),
                passwords.len(),
                total_attempts
            ));
        }
        
        // Create semaphore for concurrency control
        let semaphore = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
        
        // Keep track of paused state
        let paused = Arc::new(Mutex::new(false));
        
        // Spawn task to monitor pause channel
        let paused_clone = paused.clone();
        tokio::spawn(async move {
            while let Some(pause) = pause_rx.recv().await {
                *paused_clone.lock().unwrap() = pause;
            }
        });
        
        // Create protocol handler
        let handler = ProtocolFactory::create_handler(config.protocol);
        
        // Iterate over all username/password combinations
        for username in &usernames {
            for password in &passwords {
                // Check if cancelled
                if cancel_rx.try_recv().is_ok() {
                    info!("Attack cancelled");
                    return Ok(());
                }
                
                // Check if paused
                while *paused.lock().unwrap() {
                    sleep(Duration::from_millis(100)).await;
                    
                    // Check again if cancelled while paused
                    if cancel_rx.try_recv().is_ok() {
                        info!("Attack cancelled while paused");
                        return Ok(());
                    }
                }
                
                // Wait for a semaphore permit
                let permit = semaphore.clone().acquire_owned().await?;
                
                // Clone necessary values for the task
                let target = config.target.clone();
                let port = config.port;
                let protocol = config.protocol;
                let use_ssl = config.use_ssl;
                let timeout = config.timeout;
                let options = config.options.clone();
                let username = username.clone();
                let password = password.clone();
                let handler = handler.clone();
                let result_tx = result_tx.clone();
                let delay = config.delay;
                
                // Spawn task for this attempt
                tokio::spawn(async move {
                    let start_time = Instant::now();
                    
                    // Create credentials
                    let credentials = Credentials {
                        username: username.clone(),
                        password: password.clone(),
                    };
                    
                    // Try to authenticate
                    let auth_result = match handler.authenticate(
                        &target,
                        port,
                        &credentials,
                        timeout,
                        use_ssl,
                        &options,
                    ).await {
                        Ok(result) => result,
                        Err(e) => {
                            // Authentication error
                            let _ = result_tx.send(AttackResult {
                                target: target.clone(),
                                port,
                                protocol,
                                username: username.clone(),
                                password: password.clone(),
                                success: false,
                                error: Some(e.to_string()),
                                timestamp: Utc::now(),
                            }).await;
                            
                            drop(permit);
                            return;
                        }
                    };
                    
                    // Send result
                    let _ = result_tx.send(AttackResult {
                        target: target.clone(),
                        port,
                        protocol,
                        username: username.clone(),
                        password: password.clone(),
                        success: auth_result.success,
                        error: auth_result.error,
                        timestamp: Utc::now(),
                    }).await;
                    
                    // Calculate elapsed time and delay if needed
                    let elapsed = start_time.elapsed();
                    if elapsed < delay {
                        sleep(delay - elapsed).await;
                    }
                    
                    // Drop permit to release the semaphore
                    drop(permit);
                });
            }
        }
        
        Ok(())
    }
} 