mod core;
mod gui;

use anyhow::Result;
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    info!("Starting CogitSec application");

    // Run GUI application
    if let Err(err) = gui::run_application() {
        eprintln!("Application error: {}", err);
        return Err(err.into());
    }

    Ok(())
} 