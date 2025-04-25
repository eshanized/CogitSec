pub mod protocols;
pub mod attack;
pub mod session;
pub mod utils;
pub mod wordlist;
pub mod credentials;
pub mod proxy;
pub mod report;
pub mod logger;

use anyhow::Result;
use log::{error, info};
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use attack::{AttackManager, AttackConfig, AttackProgress, AttackResult, AttackStatus};
use session::Session;
use logger::Logger;

/// Represents the core engine of CogitSec
#[derive(Clone)]
pub struct Engine {
    /// Logger for recording events
    logger: Arc<Mutex<Logger>>,
    
    /// Attack manager for executing attacks
    attack_manager: Arc<Mutex<AttackManager>>,
    
    /// Current session
    session: Arc<Mutex<Option<Session>>>,
    
    /// Base directory for the application
    base_dir: PathBuf,
}

impl Engine {
    /// Creates a new Engine instance
    pub fn new(base_dir: PathBuf) -> Self {
        // Create logger
        let logger = Arc::new(Mutex::new(Logger::new(1000)));
        
        // Create attack manager
        let attack_manager = Arc::new(Mutex::new(AttackManager::new(logger.clone())));
        
        Self {
            logger,
            attack_manager,
            session: Arc::new(Mutex::new(None)),
            base_dir,
        }
    }

    /// Initializes the engine with configuration
    pub fn initialize(&mut self) -> Result<()> {
        info!("Initializing CogitSec engine");
        
        // Ensure directories exist
        let wordlist_dir = self.base_dir.join("wordlists");
        let sessions_dir = self.base_dir.join("sessions");
        let reports_dir = self.base_dir.join("reports");
        
        for dir in &[&wordlist_dir, &sessions_dir, &reports_dir] {
            if !dir.exists() {
                std::fs::create_dir_all(dir)?;
            }
        }
        
        // Log initialization
        if let Ok(mut logger) = self.logger.lock() {
            logger.log_info("Engine initialized successfully");
        }
        
        Ok(())
    }

    /// Starts an attack with the given configuration
    pub async fn start_attack(&self, config: AttackConfig) -> Result<()> {
        info!("Starting attack with config: {:?}", config);
        
        // Log start
        if let Ok(mut logger) = self.logger.lock() {
            logger.log_info(&format!(
                "Starting attack on {}:{} using protocol {:?}",
                config.target, config.port, config.protocol
            ));
        }
        
        // Start attack using the manager
        if let Ok(mut manager) = self.attack_manager.lock() {
            manager.start(config).await?;
        } else {
            return Err(anyhow::anyhow!("Failed to lock attack manager"));
        }
        
        Ok(())
    }

    /// Stops any running attacks
    pub async fn stop_attack(&self) -> Result<()> {
        info!("Stopping attack");
        
        // Log stop
        if let Ok(mut logger) = self.logger.lock() {
            logger.log_info("Stopping attack");
        }
        
        // Cancel attack using the manager
        if let Ok(manager) = self.attack_manager.lock() {
            manager.cancel().await?;
        } else {
            return Err(anyhow::anyhow!("Failed to lock attack manager"));
        }
        
        Ok(())
    }

    /// Pauses any running attacks
    pub async fn pause_attack(&self) -> Result<()> {
        info!("Pausing attack");
        
        // Log pause
        if let Ok(mut logger) = self.logger.lock() {
            logger.log_info("Pausing attack");
        }
        
        // Pause attack using the manager
        if let Ok(manager) = self.attack_manager.lock() {
            manager.pause(true).await?;
        } else {
            return Err(anyhow::anyhow!("Failed to lock attack manager"));
        }
        
        Ok(())
    }

    /// Resumes a paused attack
    pub async fn resume_attack(&self) -> Result<()> {
        info!("Resuming attack");
        
        // Log resume
        if let Ok(mut logger) = self.logger.lock() {
            logger.log_info("Resuming attack");
        }
        
        // Resume attack using the manager
        if let Ok(manager) = self.attack_manager.lock() {
            manager.pause(false).await?;
        } else {
            return Err(anyhow::anyhow!("Failed to lock attack manager"));
        }
        
        Ok(())
    }
    
    /// Get the current attack progress
    pub fn get_attack_progress(&self) -> Result<AttackProgress> {
        if let Ok(manager) = self.attack_manager.lock() {
            let progress_arc = manager.progress();
            let progress = progress_arc.lock().map_err(|_| anyhow::anyhow!("Failed to lock progress"))?;
            return Ok(progress.clone());
        }
        
        Err(anyhow::anyhow!("Failed to get attack progress"))
    }
    
    /// Get the current attack results
    pub fn get_attack_results(&self) -> Result<Vec<AttackResult>> {
        if let Ok(manager) = self.attack_manager.lock() {
            let results_arc = manager.results();
            let results = results_arc.lock().map_err(|_| anyhow::anyhow!("Failed to lock results"))?;
            return Ok(results.clone());
        }
        
        Err(anyhow::anyhow!("Failed to get attack results"))
    }
    
    /// Create a new session
    pub fn create_session(&self, name: &str) -> Result<()> {
        let session = Session::new(name.to_string());
        
        if let Ok(mut session_lock) = self.session.lock() {
            *session_lock = Some(session.clone());
            
            // Log session creation
            if let Ok(mut logger) = self.logger.lock() {
                logger.log_info(&format!("Created new session: {}", name));
            }
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to lock session"))
        }
    }
    
    /// Save the current session
    pub fn save_session(&self) -> Result<()> {
        if let Ok(session_lock) = self.session.lock() {
            if let Some(session) = &*session_lock {
                // Create sessions directory if it doesn't exist
                let sessions_dir = self.base_dir.join("sessions");
                if !sessions_dir.exists() {
                    std::fs::create_dir_all(&sessions_dir)?;
                }
                
                // Save session to file
                let path = sessions_dir.join(format!("{}.json", session.name));
                
                // Get attack data
                let mut attack_data = None;
                if let Ok(manager) = self.attack_manager.lock() {
                    if let Ok(results) = manager.results().lock() {
                        if let Ok(progress) = manager.progress().lock() {
                            attack_data = Some((progress.clone(), results.clone()));
                        }
                    }
                }
                
                if let Some((progress, results)) = attack_data {
                    // Update session with attack data
                    let mut session = session.clone();
                    session.update_attack_data(progress, results);
                    
                    // Serialize and save
                    let json = serde_json::to_string_pretty(&session)?;
                    std::fs::write(&path, json)?;
                    
                    // Log session save
                    if let Ok(mut logger) = self.logger.lock() {
                        logger.log_info(&format!("Saved session to: {:?}", path));
                    }
                    
                    return Ok(());
                }
            }
        }
        
        Err(anyhow::anyhow!("No active session to save"))
    }
    
    /// Load a session from file
    pub fn load_session(&self, name: &str) -> Result<()> {
        let sessions_dir = self.base_dir.join("sessions");
        let path = sessions_dir.join(format!("{}.json", name));
        
        if path.exists() {
            // Read and parse session
            let json = std::fs::read_to_string(&path)?;
            let session: Session = serde_json::from_str(&json)?;
            
            // Set as current session
            if let Ok(mut session_lock) = self.session.lock() {
                *session_lock = Some(session);
                
                // Log session load
                if let Ok(mut logger) = self.logger.lock() {
                    logger.log_info(&format!("Loaded session from: {:?}", path));
                }
                
                return Ok(());
            }
        }
        
        Err(anyhow::anyhow!("Failed to load session: {}", name))
    }
    
    /// Get the logger
    pub fn logger(&self) -> Arc<Mutex<Logger>> {
        self.logger.clone()
    }
    
    /// Get the base directory
    pub fn base_dir(&self) -> PathBuf {
        self.base_dir.clone()
    }
    
    /// Generate a report from the current attack results
    pub fn generate_report(&self, format: report::ReportFormat) -> Result<PathBuf> {
        // Get attack results
        let results = self.get_attack_results()?;
        
        // Create report
        let report = report::Report::new("CogitSec Attack Report".to_string(), results);
        
        // Generate report file
        let reports_dir = self.base_dir.join("reports");
        if !reports_dir.exists() {
            std::fs::create_dir_all(&reports_dir)?;
        }
        
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("report_{}.{}", timestamp, format.extension());
        let path = reports_dir.join(&filename);
        
        // Generate and save report
        report.generate(&path, format)?;
        
        // Log report generation
        if let Ok(mut logger) = self.logger.lock() {
            logger.log_info(&format!("Generated report: {:?}", path));
        }
        
        Ok(path)
    }
} 