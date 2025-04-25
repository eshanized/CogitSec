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

/// Runs the GTK application
pub fn run_application() -> Result<()> {
    gtk::init().expect("Failed to initialize GTK");
    
    // Initialize themes
    themes::initialize_themes();
    
    let app = Application::new();
    let app_id = "org.cogitsec.CogitSec";
    let application = gtk::Application::new(Some(app_id), Default::default());
    
    application.connect_activate(move |gtk_app| {
        app.build_ui(gtk_app);
    });
    
    application.run();
    Ok(())
} 