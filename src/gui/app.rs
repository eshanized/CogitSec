use gtk::prelude::*;
use gtk::{self, Application as GtkApplication, ApplicationWindow, HeaderBar, Label, Notebook, MenuButton, Image};
use std::cell::RefCell;
use std::rc::Rc;

use crate::core::Engine;
use crate::gui::dashboard::Dashboard;
use crate::gui::login_config::LoginConfigView;
use crate::gui::wordlist_manager::WordlistManager;
use crate::gui::log_viewer::LogViewer;
use crate::gui::statistics::StatisticsView;
use anyhow::Result;
use std::sync::{Arc, Mutex};
use log::{debug, info, error};

/// Main application structure
pub struct Application {
    /// Application engine
    engine: Arc<Mutex<Engine>>,
    
    /// Main window
    window: Rc<RefCell<Option<gtk::ApplicationWindow>>>,
    
    /// Dashboard view
    dashboard: Rc<RefCell<Option<Dashboard>>>,
    
    /// Login configuration view
    login_config: Rc<RefCell<Option<LoginConfigView>>>,
    
    /// Wordlist manager view
    wordlist_manager: Rc<RefCell<Option<WordlistManager>>>,
    
    /// Log viewer
    log_viewer: Rc<RefCell<Option<LogViewer>>>,
    
    /// Statistics view
    statistics: Rc<RefCell<Option<StatisticsView>>>,
}

impl Application {
    /// Create a new application instance
    pub fn new(engine: Arc<Mutex<Engine>>) -> Self {
        Self {
            engine,
            window: Rc::new(RefCell::new(None)),
            dashboard: Rc::new(RefCell::new(None)),
            login_config: Rc::new(RefCell::new(None)),
            wordlist_manager: Rc::new(RefCell::new(None)),
            log_viewer: Rc::new(RefCell::new(None)),
            statistics: Rc::new(RefCell::new(None)),
        }
    }
    
    /// Build the UI
    pub fn build_ui(&self, app: &gtk::Application) {
        info!("Building application UI");
        
        // Create the main window
        let window = gtk::ApplicationWindow::new(app);
        window.set_title("CogitSec - Network Login Cracker");
        window.set_default_size(1200, 800);
        
        // Set up the main layout
        let main_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
        window.set_child(Some(&main_box));
        
        // Create header bar
        let header = HeaderBar::new();
        let title_label = Label::new(Some("CogitSec"));
        header.set_title_widget(Some(&title_label));
        
        // Create menu button for app settings
        let menu_button = MenuButton::new();
        let menu_icon = Image::from_icon_name("open-menu-symbolic");
        menu_button.set_child(Some(&menu_icon));
        
        // Create the menu model
        let menu_model = gio::Menu::new();
        menu_model.append(Some("New Session"), Some("app.new_session"));
        menu_model.append(Some("Open Session"), Some("app.open_session"));
        menu_model.append(Some("Save Session"), Some("app.save_session"));
        menu_model.append_section(None, &{
            let section = gio::Menu::new();
            section.append(Some("Generate Report"), Some("app.generate_report"));
            section
        });
        menu_model.append_section(None, &{
            let section = gio::Menu::new();
            section.append(Some("Preferences"), Some("app.preferences"));
            section.append(Some("About"), Some("app.about"));
            section
        });
        
        // Set up the menu
        let menu_popover = gtk::PopoverMenu::from_model(Some(&menu_model));
        menu_button.set_popover(Some(&menu_popover));
        header.pack_end(&menu_button);
        
        // Create action buttons
        let start_button = gtk::Button::with_label("Start Attack");
        start_button.add_css_class("suggested-action");
        header.pack_start(&start_button);
        
        let stop_button = gtk::Button::with_label("Stop");
        stop_button.add_css_class("destructive-action");
        header.pack_start(&stop_button);
        
        let pause_button = gtk::Button::with_label("Pause");
        header.pack_start(&pause_button);
        
        window.set_titlebar(Some(&header));
        
        // Create notebook for different views
        let notebook = gtk::Notebook::new();
        notebook.set_tab_pos(gtk::PositionType::Left);
        main_box.append(&notebook);
        
        // Get the engine reference
        let engine = self.engine.clone();
        
        // Create and add the dashboard
        let dashboard = Dashboard::new(engine.clone());
        let dashboard_widget = dashboard.widget();
        let dashboard_label = gtk::Label::new(Some("Dashboard"));
        dashboard_label.add_css_class("sidebar-label");
        notebook.append_page(dashboard_widget, Some(&dashboard_label));
        
        // Create and add the login configuration
        let login_config = LoginConfigView::new(engine.clone());
        let login_config_widget = login_config.widget();
        let login_config_label = gtk::Label::new(Some("Target Config"));
        login_config_label.add_css_class("sidebar-label");
        notebook.append_page(login_config_widget, Some(&login_config_label));
        
        // Create and add the wordlist manager
        let wordlist_manager = WordlistManager::new(engine.clone());
        let wordlist_manager_widget = wordlist_manager.widget();
        let wordlist_manager_label = gtk::Label::new(Some("Wordlists"));
        wordlist_manager_label.add_css_class("sidebar-label");
        notebook.append_page(wordlist_manager_widget, Some(&wordlist_manager_label));
        
        // Create and add the statistics view
        let statistics = StatisticsView::new(engine.clone());
        let statistics_widget = statistics.widget();
        let statistics_label = gtk::Label::new(Some("Statistics"));
        statistics_label.add_css_class("sidebar-label");
        notebook.append_page(statistics_widget, Some(&statistics_label));
        
        // Create and add the log viewer
        let log_viewer = LogViewer::new(engine.clone());
        let log_viewer_widget = log_viewer.widget();
        let log_viewer_label = gtk::Label::new(Some("Logs"));
        log_viewer_label.add_css_class("sidebar-label");
        notebook.append_page(log_viewer_widget, Some(&log_viewer_label));
        
        // Set up the start button
        let engine_start = engine.clone();
        let dashboard_start = dashboard.clone();
        start_button.connect_clicked(move |_| {
            debug!("Start button clicked");
            
            if let Some(config) = dashboard_start.get_attack_config() {
                // Clone for the async block
                let engine = engine_start.clone();
                
                // Execute the start in a separate task
                let _handle = gtk::glib::MainContext::default().spawn_local(async move {
                    if let Ok(mut engine_guard) = engine.lock() {
                        if let Err(e) = engine_guard.start_attack(config).await {
                            error!("Failed to start attack: {}", e);
                        }
                    }
                });
            } else {
                error!("No attack configuration available");
            }
        });
        
        // Set up the stop button
        let engine_stop = engine.clone();
        stop_button.connect_clicked(move |_| {
            debug!("Stop button clicked");
            
            // Clone for the async block
            let engine = engine_stop.clone();
            
            // Execute the stop in a separate task
            let _handle = gtk::glib::MainContext::default().spawn_local(async move {
                if let Ok(mut engine_guard) = engine.lock() {
                    if let Err(e) = engine_guard.stop_attack().await {
                        error!("Failed to stop attack: {}", e);
                    }
                }
            });
        });
        
        // Set up the pause button
        let engine_pause = engine.clone();
        let pause_active = Rc::new(RefCell::new(false));
        pause_button.connect_clicked(move |button| {
            debug!("Pause button clicked");
            
            // Toggle pause state
            let mut pause_state = pause_active.borrow_mut();
            *pause_state = !*pause_state;
            
            // Update button label
            button.set_label(if *pause_state { "Resume" } else { "Pause" });
            
            // Clone for the async block
            let engine = engine_pause.clone();
            let is_paused = *pause_state;
            
            // Execute the pause in a separate task
            let _handle = gtk::glib::MainContext::default().spawn_local(async move {
                if let Ok(mut engine_guard) = engine.lock() {
                    let result = if is_paused {
                        engine_guard.pause_attack().await
                    } else {
                        engine_guard.resume_attack().await
                    };
                    
                    if let Err(e) = result {
                        error!("Failed to pause/resume attack: {}", e);
                    }
                }
            });
        });
        
        // Set up a timer to update the UI
        let engine_timer = engine.clone();
        let dashboard_timer = dashboard.clone();
        let statistics_timer = statistics.clone();
        let log_viewer_timer = log_viewer.clone();
        
        gtk::glib::timeout_add_local(
            std::time::Duration::from_millis(500),
            move || {
                // Update various UI components
                if let Ok(engine) = engine_timer.lock() {
                    // Update dashboard
                    if let Ok(progress) = engine.get_attack_progress() {
                        if let Some(dashboard) = &*dashboard_timer.borrow() {
                            dashboard.update_progress(&progress);
                        }
                    }
                    
                    // Update statistics
                    if let Ok(results) = engine.get_attack_results() {
                        if let Some(statistics) = &*statistics_timer.borrow() {
                            statistics.update_statistics(&results);
                        }
                    }
                    
                    // Update log viewer
                    if let Some(log_viewer) = &*log_viewer_timer.borrow() {
                        log_viewer.refresh_logs();
                    }
                }
                
                // Continue the timer
                Continue(true)
            },
        );
        
        // Show the window
        window.set_default_size(800, 600);
        window.show();
        
        // Store references
        *self.window.borrow_mut() = Some(window);
        *self.dashboard.borrow_mut() = Some(dashboard);
        *self.login_config.borrow_mut() = Some(login_config);
        *self.wordlist_manager.borrow_mut() = Some(wordlist_manager);
        *self.statistics.borrow_mut() = Some(statistics);
        *self.log_viewer.borrow_mut() = Some(log_viewer);
        
        // Set up a default session
        if let Ok(mut engine) = self.engine.lock() {
            if let Err(e) = engine.create_session("default") {
                error!("Failed to create default session: {}", e);
            }
        }
    }
} 