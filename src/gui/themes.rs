use gtk::prelude::*;
use gtk::gdk;

/// Initialize application themes
pub fn initialize_themes() {
    let display = match gdk::Display::default() {
        Some(display) => display,
        None => {
            log::error!("Could not get default display");
            return;
        }
    };

    let provider = gtk::CssProvider::new();
    provider.load_from_data(include_css().as_str());
    
    gtk::StyleContext::add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

/// CSS for the application
fn include_css() -> String {
    r#"
    .title-1 {
        font-size: 24px;
        font-weight: bold;
        margin-bottom: 10px;
    }
    
    .title-2 {
        font-size: 20px;
        font-weight: bold;
        margin-bottom: 8px;
    }
    
    .title-3 {
        font-size: 16px;
        font-weight: bold;
        margin-bottom: 6px;
    }
    
    .success-text {
        color: #2ecc71;
    }
    
    .warning-text {
        color: #f39c12;
    }
    
    .error-text {
        color: #e74c3c;
    }
    
    .info-row {
        background-color: rgba(52, 152, 219, 0.1);
    }
    
    .warning-row {
        background-color: rgba(243, 156, 18, 0.1);
    }
    
    .error-row {
        background-color: rgba(231, 76, 60, 0.1);
    }
    
    .debug-row {
        background-color: rgba(46, 204, 113, 0.1);
    }
    
    .dashboard-box {
        background-color: #f8f9fa;
        border-radius: 5px;
        padding: 10px;
    }
    
    progressbar trough {
        min-height: 20px;
    }
    
    progressbar progress {
        min-height: 20px;
        background-color: #3498db;
    }
    
    .login-success progressbar progress {
        background-color: #2ecc71;
    }
    
    .login-failed progressbar progress {
        background-color: #e74c3c;
    }
    "#.to_string()
} 