mod app;
mod dashboard;
mod login_config;
mod protocol_config;
mod statistics;
mod themes;
mod utils;
mod wordlist_manager;
mod log_viewer;

use anyhow::Result;
use app::Application;
use gtk::prelude::*;
use crate::core::Engine;
use std::sync::{Arc, Mutex};

/// Runs the GTK application
pub fn run_application(engine: Engine) -> Result<()> {
    if let Err(err) = gtk::init() {
        return Err(anyhow::anyhow!("Failed to initialize GTK: {}", err));
    }
    
    // Initialize themes
    themes::initialize_themes();
    
    // Create shared engine
    let engine = Arc::new(Mutex::new(engine));
    
    // Create application
    let app = Application::new(engine);
    let app_id = "org.cogitsec.CogitSec";
    let application = gtk::Application::new(Some(app_id), Default::default());
    
    application.connect_activate(move |gtk_app| {
        app.build_ui(gtk_app);
    });
    
    application.run();
    Ok(())
} 