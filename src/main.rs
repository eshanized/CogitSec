mod core;
mod gui;

use anyhow::Result;
use log::{info, error};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    info!("Starting CogitSec application");

    // Determine the base directory
    let base_dir = determine_base_dir()?;
    info!("Using base directory: {:?}", base_dir);
    
    // Create and initialize the engine
    let mut engine = core::Engine::new(base_dir);
    if let Err(e) = engine.initialize() {
        error!("Failed to initialize engine: {}", e);
        return Err(e);
    }

    // Run GUI application
    if let Err(err) = gui::run_application(engine) {
        eprintln!("Application error: {}", err);
        return Err(err.into());
    }

    Ok(())
}

/// Determine the base directory for the application
fn determine_base_dir() -> Result<PathBuf> {
    // Try to use the user's home directory
    if let Some(home_dir) = dirs::home_dir() {
        let app_dir = home_dir.join(".cogitsec");
        
        // Create the directory if it doesn't exist
        if !app_dir.exists() {
            std::fs::create_dir_all(&app_dir)?;
        }
        
        return Ok(app_dir);
    }
    
    // Fallback to the current directory
    let current_dir = std::env::current_dir()?;
    let app_dir = current_dir.join(".cogitsec");
    
    // Create the directory if it doesn't exist
    if !app_dir.exists() {
        std::fs::create_dir_all(&app_dir)?;
    }
    
    Ok(app_dir)
} 