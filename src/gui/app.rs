use gtk::prelude::*;
use gtk::{self, Application as GtkApplication, ApplicationWindow, HeaderBar, Label, Notebook};
use std::cell::RefCell;
use std::rc::Rc;

use crate::core::Engine;
use crate::gui::dashboard::DashboardPage;
use crate::gui::login_config::LoginConfigPage;
use crate::gui::wordlist_manager::WordlistManagerPage;
use crate::gui::log_viewer::LogViewer;

/// Main application structure
pub struct Application {
    /// Core engine
    engine: Engine,
    
    /// Main window
    window: RefCell<Option<ApplicationWindow>>,
    
    /// Notebook for tabs
    notebook: RefCell<Option<Notebook>>,
    
    /// Dashboard page
    dashboard: RefCell<Option<DashboardPage>>,
    
    /// Login configuration page
    login_config: RefCell<Option<LoginConfigPage>>,
    
    /// Wordlist manager page
    wordlist_manager: RefCell<Option<WordlistManagerPage>>,
    
    /// Log viewer
    log_viewer: RefCell<Option<LogViewer>>,
}

impl Application {
    /// Create a new application
    pub fn new() -> Rc<Self> {
        Rc::new(Self {
            engine: Engine::new(),
            window: RefCell::new(None),
            notebook: RefCell::new(None),
            dashboard: RefCell::new(None),
            login_config: RefCell::new(None),
            wordlist_manager: RefCell::new(None),
            log_viewer: RefCell::new(None),
        })
    }
    
    /// Build the application UI
    pub fn build_ui(&self, app: &GtkApplication) {
        // Create window
        let window = ApplicationWindow::builder()
            .application(app)
            .title("CogitSec")
            .default_width(1200)
            .default_height(800)
            .build();
            
        // Create header bar
        let header_bar = HeaderBar::builder()
            .title_widget(&Label::new(Some("CogitSec - Advanced Network Login Cracker")))
            .show_title_buttons(true)
            .build();
            
        window.set_titlebar(Some(&header_bar));
        
        // Create notebook for tabs
        let notebook = Notebook::builder()
            .scrollable(true)
            .build();
            
        // Create pages
        let engine = Rc::new(self.engine.clone());
        let dashboard = DashboardPage::new(engine.clone());
        let login_config = LoginConfigPage::new(engine.clone());
        let wordlist_manager = WordlistManagerPage::new(engine.clone());
        let log_viewer = LogViewer::new(engine.clone());
        
        // Add pages to notebook
        notebook.append_page(
            &dashboard.get_widget(),
            Some(&Label::new(Some("Dashboard"))),
        );
        
        notebook.append_page(
            &login_config.get_widget(),
            Some(&Label::new(Some("Attack Configuration"))),
        );
        
        notebook.append_page(
            &wordlist_manager.get_widget(),
            Some(&Label::new(Some("Wordlist Manager"))),
        );
        
        notebook.append_page(
            &log_viewer.get_widget(),
            Some(&Label::new(Some("Logs"))),
        );
        
        // Add notebook to window
        window.set_child(Some(&notebook));
        
        // Store components
        *self.window.borrow_mut() = Some(window);
        *self.notebook.borrow_mut() = Some(notebook);
        *self.dashboard.borrow_mut() = Some(dashboard);
        *self.login_config.borrow_mut() = Some(login_config);
        *self.wordlist_manager.borrow_mut() = Some(wordlist_manager);
        *self.log_viewer.borrow_mut() = Some(log_viewer);
        
        // Show window
        self.window.borrow().as_ref().unwrap().present();
    }
} 