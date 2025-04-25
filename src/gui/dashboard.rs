use gtk::prelude::*;
use gtk::{Button, Box as GtkBox, Grid, Label, Orientation, ProgressBar, ScrolledWindow};
use std::rc::Rc;

use crate::core::Engine;
use crate::core::attack::{AttackConfig, AttackProgress, AttackStatus};
use crate::core::protocols::Protocol;
use std::sync::{Arc, Mutex};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use log::{debug, info, error};

/// Dashboard page for displaying attack statistics
pub struct DashboardPage {
    /// Root widget
    root: GtkBox,
    
    /// Engine reference
    engine: Rc<Engine>,
    
    /// Progress bar
    progress_bar: ProgressBar,
    
    /// Status label
    status_label: Label,
    
    /// Attempts label
    attempts_label: Label,
    
    /// Successes label
    successes_label: Label,
    
    /// Time elapsed label
    time_elapsed_label: Label,
    
    /// Estimated time remaining label
    eta_label: Label,
}

impl DashboardPage {
    /// Create a new dashboard page
    pub fn new(engine: Rc<Engine>) -> Self {
        // Create main box
        let root = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .spacing(10)
            .margin_start(10)
            .margin_end(10)
            .margin_top(10)
            .margin_bottom(10)
            .build();
            
        // Create title
        let title = Label::builder()
            .label("Attack Dashboard")
            .css_classes(vec!["title-1"])
            .halign(gtk::Align::Start)
            .build();
            
        root.append(&title);
        
        // Create status section
        let status_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(10)
            .margin_top(10)
            .margin_bottom(10)
            .build();
            
        let status_label = Label::builder()
            .label("Status: Idle")
            .halign(gtk::Align::Start)
            .build();
            
        let progress_bar = ProgressBar::builder()
            .hexpand(true)
            .build();
            
        status_box.append(&status_label);
        status_box.append(&progress_bar);
        
        root.append(&status_box);
        
        // Create statistics grid
        let stats_frame = gtk::Frame::builder()
            .label("Attack Statistics")
            .margin_top(10)
            .build();
            
        let stats_grid = Grid::builder()
            .row_spacing(10)
            .column_spacing(10)
            .margin_start(10)
            .margin_end(10)
            .margin_top(10)
            .margin_bottom(10)
            .build();
            
        // First row - attempts
        let attempts_title = Label::builder()
            .label("Attempts:")
            .halign(gtk::Align::Start)
            .build();
            
        let attempts_label = Label::builder()
            .label("0")
            .halign(gtk::Align::Start)
            .build();
            
        stats_grid.attach(&attempts_title, 0, 0, 1, 1);
        stats_grid.attach(&attempts_label, 1, 0, 1, 1);
        
        // Second row - successes
        let successes_title = Label::builder()
            .label("Successes:")
            .halign(gtk::Align::Start)
            .build();
            
        let successes_label = Label::builder()
            .label("0")
            .halign(gtk::Align::Start)
            .build();
            
        stats_grid.attach(&successes_title, 0, 1, 1, 1);
        stats_grid.attach(&successes_label, 1, 1, 1, 1);
        
        // Third row - time elapsed
        let time_elapsed_title = Label::builder()
            .label("Time Elapsed:")
            .halign(gtk::Align::Start)
            .build();
            
        let time_elapsed_label = Label::builder()
            .label("00:00:00")
            .halign(gtk::Align::Start)
            .build();
            
        stats_grid.attach(&time_elapsed_title, 0, 2, 1, 1);
        stats_grid.attach(&time_elapsed_label, 1, 2, 1, 1);
        
        // Fourth row - estimated time remaining
        let eta_title = Label::builder()
            .label("Estimated Time Remaining:")
            .halign(gtk::Align::Start)
            .build();
            
        let eta_label = Label::builder()
            .label("--:--:--")
            .halign(gtk::Align::Start)
            .build();
            
        stats_grid.attach(&eta_title, 0, 3, 1, 1);
        stats_grid.attach(&eta_label, 1, 3, 1, 1);
        
        stats_frame.set_child(Some(&stats_grid));
        root.append(&stats_frame);
        
        // Create discovered credentials section
        let creds_frame = gtk::Frame::builder()
            .label("Discovered Credentials")
            .margin_top(10)
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let scrolled_window = ScrolledWindow::builder()
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let credentials_list = gtk::ListView::new(
            Some(gtk::NoSelection::new(Some(gtk::StringList::new(&[])))),
            None::<gtk::SignalListItemFactory>,
        );
        
        scrolled_window.set_child(Some(&credentials_list));
        creds_frame.set_child(Some(&scrolled_window));
        root.append(&creds_frame);
        
        // Create control buttons
        let button_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(10)
            .margin_top(10)
            .halign(gtk::Align::End)
            .build();
            
        let start_button = Button::builder()
            .label("Start Attack")
            .build();
            
        let pause_button = Button::builder()
            .label("Pause")
            .sensitive(false)
            .build();
            
        let stop_button = Button::builder()
            .label("Stop")
            .sensitive(false)
            .build();
            
        button_box.append(&start_button);
        button_box.append(&pause_button);
        button_box.append(&stop_button);
        
        root.append(&button_box);
        
        // Create the dashboard page
        let page = Self {
            root,
            engine,
            progress_bar,
            status_label,
            attempts_label,
            successes_label,
            time_elapsed_label,
            eta_label,
        };
        
        // Wrap in Rc for signal handlers
        let page_rc = Rc::new(page);
        let page_weak = Rc::downgrade(&page_rc);
        
        // Connect signals using weak references
        start_button.connect_clicked(move |button| {
            if let Some(p) = page_weak.upgrade() {
                p.on_start_clicked(button);
            }
        });
        
        let page_weak = Rc::downgrade(&page_rc);
        pause_button.connect_clicked(move |button| {
            if let Some(p) = page_weak.upgrade() {
                p.on_pause_clicked(button);
            }
        });
        
        let page_weak = Rc::downgrade(&page_rc);
        stop_button.connect_clicked(move |button| {
            if let Some(p) = page_weak.upgrade() {
                p.on_stop_clicked(button);
            }
        });
        
        // Unwrap the Rc to get our page
        match Rc::try_unwrap(page_rc) {
            Ok(page) => page,
            Err(_) => panic!("Unable to unwrap Rc - this shouldn't happen!"),
        }
    }
    
    /// Get the root widget
    pub fn get_widget(&self) -> GtkBox {
        self.root.clone()
    }
    
    /// Handle start button click
    fn on_start_clicked(&self, button: &Button) {
        self.status_label.set_text("Status: Running");
        button.set_sensitive(false);
        
        // Update button states
        if let Some(parent_box) = button.parent().and_then(|w| w.downcast::<GtkBox>().ok()) {
            update_button_states(&parent_box, "Start");
        }
    }
    
    /// Handle pause button click
    fn on_pause_clicked(&self, button: &Button) {
        let is_paused = button.label().map_or(false, |l| l == "Resume");
        
        if is_paused {
            self.status_label.set_text("Status: Paused");
            button.set_label("Resume");
        } else {
            self.status_label.set_text("Status: Running");
            button.set_label("Pause");
        }
        
        // Update button states
        if let Some(parent_box) = button.parent().and_then(|w| w.downcast::<GtkBox>().ok()) {
            update_button_states(&parent_box, if is_paused { "Resume" } else { "Pause" });
        }
    }
    
    /// Handle stop button click
    fn on_stop_clicked(&self, button: &Button) {
        self.status_label.set_text("Status: Idle");
        self.progress_bar.set_fraction(0.0);
        
        // Update button states
        if let Some(parent_box) = button.parent().and_then(|w| w.downcast::<GtkBox>().ok()) {
            update_button_states(&parent_box, "Stop");
        }
    }
}

fn update_button_states(parent_box: &GtkBox, active_button: &str) {
    // Properly handle button states in the parent box
    let mut children = Vec::new();
    let mut child = parent_box.first_child();
    
    while let Some(widget) = child {
        children.push(widget.clone());
        child = widget.next_sibling();
    }
    
    for child in children {
        if let Some(btn) = child.downcast_ref::<Button>() {
            let label = btn.label().unwrap_or_else(|| "".into());
            
            if active_button == "Start" {
                // Starting an attack
                if label == "Start Attack" {
                    btn.set_sensitive(false);
                } else if label == "Pause" {
                    btn.set_label("Pause");
                    btn.set_sensitive(true);
                } else if label == "Stop" {
                    btn.set_sensitive(true);
                }
            } else if active_button == "Pause" {
                // Pausing an attack
                if label == "Start Attack" {
                    btn.set_sensitive(false);
                } else if label == "Pause" {
                    btn.set_label("Resume");
                    btn.set_sensitive(true);
                } else if label == "Stop" {
                    btn.set_sensitive(true);
                }
            } else if active_button == "Resume" {
                // Resuming an attack
                if label == "Start Attack" {
                    btn.set_sensitive(false);
                } else if label == "Resume" {
                    btn.set_label("Pause");
                    btn.set_sensitive(true);
                } else if label == "Stop" {
                    btn.set_sensitive(true);
                }
            } else if active_button == "Stop" {
                // Stopping an attack
                if label == "Start Attack" {
                    btn.set_sensitive(true);
                } else if label == "Pause" || label == "Resume" {
                    btn.set_label("Pause");
                    btn.set_sensitive(false);
                } else if label == "Stop" {
                    btn.set_sensitive(false);
                }
            }
        }
    }
}

/// Dashboard view
#[derive(Clone)]
pub struct Dashboard {
    /// Engine instance
    engine: Arc<Mutex<Engine>>,
    
    /// Main widget
    widget: gtk::Box,
    
    /// Target entry
    target_entry: gtk::Entry,
    
    /// Port entry
    port_entry: gtk::Entry,
    
    /// Protocol combo box
    protocol_combo: gtk::ComboBoxText,
    
    /// Use SSL checkbox
    use_ssl_check: gtk::CheckButton,
    
    /// Username list selection
    username_list_entry: gtk::Entry,
    
    /// Password list selection
    password_list_entry: gtk::Entry,
    
    /// Concurrency adjustment
    concurrency_adjustment: gtk::Adjustment,
    
    /// Progress bar
    progress_bar: gtk::ProgressBar,
    
    /// Status label
    status_label: gtk::Label,
    
    /// Results text view
    results_view: gtk::TextView,
}

impl Dashboard {
    /// Create a new dashboard
    pub fn new(engine: Arc<Mutex<Engine>>) -> Self {
        // Create main container
        let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
        widget.set_margin_start(10);
        widget.set_margin_end(10);
        widget.set_margin_top(10);
        widget.set_margin_bottom(10);
        
        // Create header
        let header_label = gtk::Label::new(Some("Attack Dashboard"));
        header_label.get_style_context().add_class("title-1");
        widget.append(&header_label);
        
        // Create configuration grid
        let config_frame = gtk::Frame::new(Some("Attack Configuration"));
        let config_grid = gtk::Grid::new();
        config_grid.set_row_spacing(10);
        config_grid.set_column_spacing(10);
        config_grid.set_margin_start(10);
        config_grid.set_margin_end(10);
        config_grid.set_margin_top(10);
        config_grid.set_margin_bottom(10);
        config_frame.set_child(Some(&config_grid));
        widget.append(&config_frame);
        
        // Target configuration
        let target_label = gtk::Label::new(Some("Target:"));
        target_label.set_halign(gtk::Align::Start);
        let target_entry = gtk::Entry::new();
        target_entry.set_placeholder_text(Some("IP address or hostname"));
        config_grid.attach(&target_label, 0, 0, 1, 1);
        config_grid.attach(&target_entry, 1, 0, 1, 1);
        
        let port_label = gtk::Label::new(Some("Port:"));
        port_label.set_halign(gtk::Align::Start);
        let port_entry = gtk::Entry::new();
        port_entry.set_placeholder_text(Some("Port number"));
        config_grid.attach(&port_label, 2, 0, 1, 1);
        config_grid.attach(&port_entry, 3, 0, 1, 1);
        
        // Protocol configuration
        let protocol_label = gtk::Label::new(Some("Protocol:"));
        protocol_label.set_halign(gtk::Align::Start);
        let protocol_combo = gtk::ComboBoxText::new();
        
        // Add protocols
        for protocol in &[
            Protocol::SSH, 
            Protocol::FTP, 
            Protocol::HTTP, 
            Protocol::HTTPS, 
            Protocol::SMTP, 
            Protocol::SMTPS, 
            Protocol::MySQL, 
            Protocol::PostgreSQL, 
            Protocol::SMB
        ] {
            protocol_combo.append(Some(&format!("{:?}", protocol)), &format!("{}", protocol));
        }
        protocol_combo.set_active(Some(0));
        
        config_grid.attach(&protocol_label, 0, 1, 1, 1);
        config_grid.attach(&protocol_combo, 1, 1, 1, 1);
        
        let use_ssl_check = gtk::CheckButton::with_label("Use SSL/TLS");
        config_grid.attach(&use_ssl_check, 2, 1, 2, 1);
        
        // Wordlist configuration
        let username_list_label = gtk::Label::new(Some("Username List:"));
        username_list_label.set_halign(gtk::Align::Start);
        let username_list_box = gtk::Box::new(gtk::Orientation::Horizontal, 5);
        let username_list_entry = gtk::Entry::new();
        username_list_entry.set_placeholder_text(Some("Path to username list"));
        username_list_entry.set_hexpand(true);
        let username_list_button = gtk::Button::with_label("Browse");
        username_list_box.append(&username_list_entry);
        username_list_box.append(&username_list_button);
        config_grid.attach(&username_list_label, 0, 2, 1, 1);
        config_grid.attach(&username_list_box, 1, 2, 3, 1);
        
        let password_list_label = gtk::Label::new(Some("Password List:"));
        password_list_label.set_halign(gtk::Align::Start);
        let password_list_box = gtk::Box::new(gtk::Orientation::Horizontal, 5);
        let password_list_entry = gtk::Entry::new();
        password_list_entry.set_placeholder_text(Some("Path to password list"));
        password_list_entry.set_hexpand(true);
        let password_list_button = gtk::Button::with_label("Browse");
        password_list_box.append(&password_list_entry);
        password_list_box.append(&password_list_button);
        config_grid.attach(&password_list_label, 0, 3, 1, 1);
        config_grid.attach(&password_list_box, 1, 3, 3, 1);
        
        // Advanced options
        let concurrency_label = gtk::Label::new(Some("Concurrency:"));
        concurrency_label.set_halign(gtk::Align::Start);
        let concurrency_adjustment = gtk::Adjustment::new(10.0, 1.0, 100.0, 1.0, 5.0, 0.0);
        let concurrency_spin = gtk::SpinButton::new(Some(&concurrency_adjustment), 1.0, 0);
        config_grid.attach(&concurrency_label, 0, 4, 1, 1);
        config_grid.attach(&concurrency_spin, 1, 4, 1, 1);
        
        let delay_label = gtk::Label::new(Some("Delay (ms):"));
        delay_label.set_halign(gtk::Align::Start);
        let delay_adjustment = gtk::Adjustment::new(100.0, 0.0, 5000.0, 10.0, 100.0, 0.0);
        let delay_spin = gtk::SpinButton::new(Some(&delay_adjustment), 1.0, 0);
        config_grid.attach(&delay_label, 2, 4, 1, 1);
        config_grid.attach(&delay_spin, 3, 4, 1, 1);
        
        // Progress section
        let progress_frame = gtk::Frame::new(Some("Attack Progress"));
        let progress_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        progress_box.set_margin_start(10);
        progress_box.set_margin_end(10);
        progress_box.set_margin_top(10);
        progress_box.set_margin_bottom(10);
        progress_frame.set_child(Some(&progress_box));
        
        let status_label = gtk::Label::new(Some("Status: Idle"));
        status_label.set_halign(gtk::Align::Start);
        progress_box.append(&status_label);
        
        let progress_bar = gtk::ProgressBar::new();
        progress_bar.set_text(Some("0%"));
        progress_bar.set_show_text(true);
        progress_box.append(&progress_bar);
        
        let stats_grid = gtk::Grid::new();
        stats_grid.set_row_spacing(5);
        stats_grid.set_column_spacing(10);
        
        // Stats labels
        let attempts_label = gtk::Label::new(Some("Attempts:"));
        attempts_label.set_halign(gtk::Align::Start);
        let attempts_value = gtk::Label::new(Some("0 / 0"));
        attempts_value.set_halign(gtk::Align::Start);
        stats_grid.attach(&attempts_label, 0, 0, 1, 1);
        stats_grid.attach(&attempts_value, 1, 0, 1, 1);
        
        let success_label = gtk::Label::new(Some("Successful:"));
        success_label.set_halign(gtk::Align::Start);
        let success_value = gtk::Label::new(Some("0"));
        success_value.set_halign(gtk::Align::Start);
        stats_grid.attach(&success_label, 0, 1, 1, 1);
        stats_grid.attach(&success_value, 1, 1, 1, 1);
        
        let time_label = gtk::Label::new(Some("Elapsed Time:"));
        time_label.set_halign(gtk::Align::Start);
        let time_value = gtk::Label::new(Some("00:00:00"));
        time_value.set_halign(gtk::Align::Start);
        stats_grid.attach(&time_label, 2, 0, 1, 1);
        stats_grid.attach(&time_value, 3, 0, 1, 1);
        
        let eta_label = gtk::Label::new(Some("ETA:"));
        eta_label.set_halign(gtk::Align::Start);
        let eta_value = gtk::Label::new(Some("--:--:--"));
        eta_value.set_halign(gtk::Align::Start);
        stats_grid.attach(&eta_label, 2, 1, 1, 1);
        stats_grid.attach(&eta_value, 3, 1, 1, 1);
        
        progress_box.append(&stats_grid);
        widget.append(&progress_frame);
        
        // Results section
        let results_frame = gtk::Frame::new(Some("Results"));
        let results_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        results_box.set_margin_start(10);
        results_box.set_margin_end(10);
        results_box.set_margin_top(10);
        results_box.set_margin_bottom(10);
        
        let results_scroll = gtk::ScrolledWindow::new();
        results_scroll.set_hexpand(true);
        results_scroll.set_vexpand(true);
        results_scroll.set_min_content_height(200);
        
        let results_view = gtk::TextView::new();
        results_view.set_editable(false);
        results_view.set_cursor_visible(false);
        results_view.set_monospace(true);
        results_scroll.set_child(Some(&results_view));
        
        results_box.append(&results_scroll);
        results_frame.set_child(Some(&results_box));
        widget.append(&results_frame);
        
        // Set up file chooser for username list
        let username_entry_clone = username_list_entry.clone();
        username_list_button.connect_clicked(move |_| {
            let file_chooser = gtk::FileChooserDialog::new(
                Some("Select Username List"),
                None::<&gtk::Window>,
                gtk::FileChooserAction::Open,
                &[
                    ("Cancel", gtk::ResponseType::Cancel),
                    ("Open", gtk::ResponseType::Accept),
                ],
            );
            
            file_chooser.connect_response(clone!(@strong username_entry_clone => move |dialog, response| {
                if response == gtk::ResponseType::Accept {
                    if let Some(file) = dialog.file() {
                        if let Some(path) = file.path() {
                            username_entry_clone.set_text(&path.to_string_lossy());
                        }
                    }
                }
                dialog.close();
            }));
            
            file_chooser.show();
        });
        
        // Set up file chooser for password list
        let password_entry_clone = password_list_entry.clone();
        password_list_button.connect_clicked(move |_| {
            let file_chooser = gtk::FileChooserDialog::new(
                Some("Select Password List"),
                None::<&gtk::Window>,
                gtk::FileChooserAction::Open,
                &[
                    ("Cancel", gtk::ResponseType::Cancel),
                    ("Open", gtk::ResponseType::Accept),
                ],
            );
            
            file_chooser.connect_response(clone!(@strong password_entry_clone => move |dialog, response| {
                if response == gtk::ResponseType::Accept {
                    if let Some(file) = dialog.file() {
                        if let Some(path) = file.path() {
                            password_entry_clone.set_text(&path.to_string_lossy());
                        }
                    }
                }
                dialog.close();
            }));
            
            file_chooser.show();
        });
        
        // Update protocol-specific port
        protocol_combo.connect_changed(clone!(@strong port_entry, @strong use_ssl_check => move |combo| {
            if let Some(active_id) = combo.active_id() {
                if let Ok(protocol) = active_id.parse::<String>().map(|s| match s.as_str() {
                    "SSH" => Protocol::SSH,
                    "FTP" => Protocol::FTP,
                    "HTTP" => Protocol::HTTP,
                    "HTTPS" => Protocol::HTTPS,
                    "SMTP" => Protocol::SMTP,
                    "SMTPS" => Protocol::SMTPS,
                    "MySQL" => Protocol::MySQL,
                    "PostgreSQL" => Protocol::PostgreSQL,
                    "SMB" => Protocol::SMB,
                    _ => Protocol::SSH,
                }) {
                    port_entry.set_text(&protocol.default_port().to_string());
                    use_ssl_check.set_active(protocol.uses_ssl_by_default());
                }
            }
        }));
        
        Self {
            engine,
            widget,
            target_entry,
            port_entry,
            protocol_combo,
            use_ssl_check,
            username_list_entry,
            password_list_entry,
            concurrency_adjustment,
            progress_bar,
            status_label,
            results_view,
        }
    }
    
    /// Get the main widget
    pub fn widget(&self) -> &gtk::Box {
        &self.widget
    }
    
    /// Get the current attack configuration
    pub fn get_attack_config(&self) -> Option<AttackConfig> {
        // Get target
        let target = self.target_entry.text().to_string();
        if target.is_empty() {
            error!("Target is required");
            return None;
        }
        
        // Get port
        let port = match self.port_entry.text().to_string().parse::<u16>() {
            Ok(port) => port,
            Err(e) => {
                error!("Invalid port: {}", e);
                return None;
            }
        };
        
        // Get protocol
        let protocol = if let Some(active_id) = self.protocol_combo.active_id() {
            match active_id.parse::<String>().map(|s| match s.as_str() {
                "SSH" => Protocol::SSH,
                "FTP" => Protocol::FTP,
                "HTTP" => Protocol::HTTP,
                "HTTPS" => Protocol::HTTPS,
                "SMTP" => Protocol::SMTP,
                "SMTPS" => Protocol::SMTPS,
                "MySQL" => Protocol::MySQL,
                "PostgreSQL" => Protocol::PostgreSQL,
                "SMB" => Protocol::SMB,
                _ => Protocol::SSH,
            }) {
                Ok(p) => p,
                Err(e) => {
                    error!("Invalid protocol: {}", e);
                    return None;
                }
            }
        } else {
            error!("No protocol selected");
            return None;
        };
        
        // Get username list
        let username_list = PathBuf::from(self.username_list_entry.text().to_string());
        if !username_list.exists() {
            error!("Username list does not exist: {:?}", username_list);
            return None;
        }
        
        // Get password list
        let password_list = PathBuf::from(self.password_list_entry.text().to_string());
        if !password_list.exists() {
            error!("Password list does not exist: {:?}", password_list);
            return None;
        }
        
        // Get concurrency
        let concurrency = self.concurrency_adjustment.value() as usize;
        
        // Create config
        Some(AttackConfig {
            target,
            port,
            protocol,
            username_list,
            password_list,
            concurrency,
            delay: std::time::Duration::from_millis(100),
            use_ssl: self.use_ssl_check.is_active(),
            timeout: std::time::Duration::from_secs(10),
            options: std::collections::HashMap::new(),
        })
    }
    
    /// Update progress display
    pub fn update_progress(&self, progress: &AttackProgress) {
        // Update status label
        let status_text = match progress.status {
            AttackStatus::Idle => "Status: Idle",
            AttackStatus::Running => "Status: Running",
            AttackStatus::Paused => "Status: Paused",
            AttackStatus::Completed => "Status: Completed",
            AttackStatus::Failed => "Status: Failed",
        };
        self.status_label.set_text(status_text);
        
        // Update progress bar
        if progress.total_attempts > 0 {
            let fraction = progress.attempts_made as f64 / progress.total_attempts as f64;
            self.progress_bar.set_fraction(fraction);
            self.progress_bar.set_text(Some(&format!("{:.1}%", fraction * 100.0)));
        } else {
            self.progress_bar.set_fraction(0.0);
            self.progress_bar.set_text(Some("0%"));
        }
        
        // Get successful results to display
        if let Ok(engine) = self.engine.lock() {
            if let Ok(results) = engine.get_attack_results() {
                let successful_results: Vec<_> = results.iter()
                    .filter(|r| r.success)
                    .collect();
                
                if !successful_results.is_empty() {
                    // Update text view with successful results
                    let buffer = self.results_view.buffer().unwrap();
                    buffer.set_text("");
                    
                    let mut iter = buffer.end_iter();
                    buffer.insert(&mut iter, "Successful credentials:\n\n");
                    
                    for result in successful_results {
                        buffer.insert(
                            &mut iter, 
                            &format!(
                                "Target: {}:{} ({})\nUsername: {}\nPassword: {}\nTimestamp: {}\n\n",
                                result.target,
                                result.port,
                                result.protocol,
                                result.username,
                                result.password,
                                result.timestamp.format("%Y-%m-%d %H:%M:%S")
                            )
                        );
                    }
                }
            }
        }
    }
} 