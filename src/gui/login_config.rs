use gtk::prelude::*;
use gtk::{
    Box as GtkBox, Button, ComboBoxText, Entry, Grid, Label, Orientation,
    Scale, SpinButton,
};
use std::rc::Rc;

use crate::core::Engine;
use crate::core::protocols::Protocol;
use crate::core::attack::AttackConfig;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::cell::RefCell;

/// Login configuration page
pub struct LoginConfigPage {
    /// Root widget
    root: GtkBox,
    
    /// Engine reference
    engine: Rc<Engine>,
    
    /// Target entry
    target_entry: Entry,
    
    /// Port spin button
    port_spin: SpinButton,
    
    /// Protocol combo box
    protocol_combo: ComboBoxText,
    
    /// Username list entry
    username_list_entry: Entry,
    
    /// Password list entry
    password_list_entry: Entry,
    
    /// Concurrency spin button
    concurrency_spin: SpinButton,
    
    /// Delay scale
    delay_scale: Scale,
    
    /// Use SSL checkbox
    use_ssl_check: gtk::CheckButton,
    
    /// Timeout scale
    timeout_scale: Scale,
}

impl LoginConfigPage {
    /// Create a new login configuration page
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
            .label("Attack Configuration")
            .css_classes(vec!["title-1"])
            .halign(gtk::Align::Start)
            .build();
            
        root.append(&title);
        
        // Create configuration grid
        let grid = Grid::builder()
            .row_spacing(10)
            .column_spacing(10)
            .margin_top(10)
            .build();
            
        // Target configuration
        let target_label = Label::builder()
            .label("Target Host/IP:")
            .halign(gtk::Align::Start)
            .build();
            
        let target_entry = Entry::builder()
            .placeholder_text("Enter hostname or IP address")
            .build();
            
        grid.attach(&target_label, 0, 0, 1, 1);
        grid.attach(&target_entry, 1, 0, 1, 1);
        
        // Port configuration
        let port_label = Label::builder()
            .label("Port:")
            .halign(gtk::Align::Start)
            .build();
            
        let port_adj = gtk::Adjustment::new(22.0, 1.0, 65535.0, 1.0, 10.0, 0.0);
        let port_spin = SpinButton::builder()
            .adjustment(&port_adj)
            .build();
            
        grid.attach(&port_label, 0, 1, 1, 1);
        grid.attach(&port_spin, 1, 1, 1, 1);
        
        // Protocol configuration
        let protocol_label = Label::builder()
            .label("Protocol:")
            .halign(gtk::Align::Start)
            .build();
            
        let protocol_combo = ComboBoxText::new();
        protocol_combo.append(Some("ssh"), "SSH");
        protocol_combo.append(Some("ftp"), "FTP");
        protocol_combo.append(Some("http"), "HTTP");
        protocol_combo.append(Some("https"), "HTTPS");
        protocol_combo.append(Some("smtp"), "SMTP");
        protocol_combo.append(Some("smtps"), "SMTPS");
        protocol_combo.append(Some("mysql"), "MySQL");
        protocol_combo.append(Some("postgres"), "PostgreSQL");
        protocol_combo.append(Some("smb"), "SMB");
        protocol_combo.set_active_id(Some("ssh"));
        
        grid.attach(&protocol_label, 0, 2, 1, 1);
        grid.attach(&protocol_combo, 1, 2, 1, 1);
        
        // Username list configuration
        let username_list_label = Label::builder()
            .label("Username List:")
            .halign(gtk::Align::Start)
            .build();
            
        let username_list_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(5)
            .hexpand(true)
            .build();
            
        let username_list_entry = Entry::builder()
            .placeholder_text("Path to username list")
            .hexpand(true)
            .build();
            
        let username_list_button = Button::builder()
            .label("Browse...")
            .build();
            
        username_list_box.append(&username_list_entry);
        username_list_box.append(&username_list_button);
        
        grid.attach(&username_list_label, 0, 3, 1, 1);
        grid.attach(&username_list_box, 1, 3, 1, 1);
        
        // Password list configuration
        let password_list_label = Label::builder()
            .label("Password List:")
            .halign(gtk::Align::Start)
            .build();
            
        let password_list_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(5)
            .hexpand(true)
            .build();
            
        let password_list_entry = Entry::builder()
            .placeholder_text("Path to password list")
            .hexpand(true)
            .build();
            
        let password_list_button = Button::builder()
            .label("Browse...")
            .build();
            
        password_list_box.append(&password_list_entry);
        password_list_box.append(&password_list_button);
        
        grid.attach(&password_list_label, 0, 4, 1, 1);
        grid.attach(&password_list_box, 1, 4, 1, 1);
        
        // Concurrency configuration
        let concurrency_label = Label::builder()
            .label("Concurrency:")
            .halign(gtk::Align::Start)
            .build();
            
        let concurrency_adj = gtk::Adjustment::new(10.0, 1.0, 100.0, 1.0, 5.0, 0.0);
        let concurrency_spin = SpinButton::builder()
            .adjustment(&concurrency_adj)
            .build();
            
        grid.attach(&concurrency_label, 0, 5, 1, 1);
        grid.attach(&concurrency_spin, 1, 5, 1, 1);
        
        // Delay configuration
        let delay_label = Label::builder()
            .label("Delay between attempts (ms):")
            .halign(gtk::Align::Start)
            .build();
            
        let delay_scale = Scale::builder()
            .orientation(Orientation::Horizontal)
            .adjustment(&gtk::Adjustment::new(100.0, 0.0, 2000.0, 10.0, 100.0, 0.0))
            .draw_value(true)
            .value_pos(gtk::PositionType::Right)
            .hexpand(true)
            .build();
            
        grid.attach(&delay_label, 0, 6, 1, 1);
        grid.attach(&delay_scale, 1, 6, 1, 1);
        
        // SSL configuration
        let ssl_label = Label::builder()
            .label("Use SSL/TLS:")
            .halign(gtk::Align::Start)
            .build();
            
        let use_ssl_check = gtk::CheckButton::builder()
            .build();
            
        grid.attach(&ssl_label, 0, 7, 1, 1);
        grid.attach(&use_ssl_check, 1, 7, 1, 1);
        
        // Timeout configuration
        let timeout_label = Label::builder()
            .label("Connection timeout (sec):")
            .halign(gtk::Align::Start)
            .build();
            
        let timeout_scale = Scale::builder()
            .orientation(Orientation::Horizontal)
            .adjustment(&gtk::Adjustment::new(10.0, 1.0, 60.0, 1.0, 5.0, 0.0))
            .draw_value(true)
            .value_pos(gtk::PositionType::Right)
            .hexpand(true)
            .build();
            
        grid.attach(&timeout_label, 0, 8, 1, 1);
        grid.attach(&timeout_scale, 1, 8, 1, 1);
        
        root.append(&grid);
        
        // Create save button
        let button_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(10)
            .margin_top(10)
            .halign(gtk::Align::End)
            .build();
            
        let save_button = Button::builder()
            .label("Save Configuration")
            .build();
            
        button_box.append(&save_button);
        root.append(&button_box);
        
        // Create the page
        let page = Self {
            root,
            engine,
            target_entry,
            port_spin,
            protocol_combo: protocol_combo.clone(),
            username_list_entry,
            password_list_entry,
            concurrency_spin,
            delay_scale,
            use_ssl_check,
            timeout_scale,
        };
        
        // Wrap in Rc for signal handlers
        let page_rc = Rc::new(page);
        
        // Connect signals
        let page_weak = Rc::downgrade(&page_rc);
        protocol_combo.connect_changed(move |combo| {
            if let Some(p) = page_weak.upgrade() {
                p.on_protocol_changed(combo);
            }
        });
        
        let page_weak = Rc::downgrade(&page_rc);
        username_list_button.connect_clicked(move |_| {
            if let Some(p) = page_weak.upgrade() {
                p.on_username_list_button_clicked();
            }
        });
        
        let page_weak = Rc::downgrade(&page_rc);
        password_list_button.connect_clicked(move |_| {
            if let Some(p) = page_weak.upgrade() {
                p.on_password_list_button_clicked();
            }
        });
        
        let page_weak = Rc::downgrade(&page_rc);
        save_button.connect_clicked(move |_| {
            if let Some(p) = page_weak.upgrade() {
                p.on_save_button_clicked();
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
    
    /// Handle protocol selection change
    fn on_protocol_changed(&self, combo: &ComboBoxText) {
        if let Some(protocol_id) = combo.active_id() {
            match protocol_id.as_str() {
                "ssh" => {
                    self.port_spin.set_value(22.0);
                    self.use_ssl_check.set_active(true);
                },
                "ftp" => {
                    self.port_spin.set_value(21.0);
                    self.use_ssl_check.set_active(false);
                },
                "http" => {
                    self.port_spin.set_value(80.0);
                    self.use_ssl_check.set_active(false);
                },
                "https" => {
                    self.port_spin.set_value(443.0);
                    self.use_ssl_check.set_active(true);
                },
                "smtp" => {
                    self.port_spin.set_value(25.0);
                    self.use_ssl_check.set_active(false);
                },
                "smtps" => {
                    self.port_spin.set_value(465.0);
                    self.use_ssl_check.set_active(true);
                },
                "mysql" => {
                    self.port_spin.set_value(3306.0);
                    self.use_ssl_check.set_active(false);
                },
                "postgres" => {
                    self.port_spin.set_value(5432.0);
                    self.use_ssl_check.set_active(false);
                },
                "smb" => {
                    self.port_spin.set_value(445.0);
                    self.use_ssl_check.set_active(false);
                },
                _ => {}
            }
        }
    }
    
    /// Handle username list button click
    fn on_username_list_button_clicked(&self) {
        if let Some(parent) = self.root.ancestor(gtk::Window::static_type()) {
            if let Ok(parent) = parent.downcast::<gtk::Window>() {
                if let Some(path) = crate::gui::utils::open_file_chooser_dialog(
                    &parent,
                    "Select Username List",
                    &[("Text Files", &["*.txt"]), ("All Files", &["*"])],
                ) {
                    self.username_list_entry.set_text(&path.to_string_lossy());
                }
            }
        }
    }
    
    /// Handle password list button click
    fn on_password_list_button_clicked(&self) {
        if let Some(parent) = self.root.ancestor(gtk::Window::static_type()) {
            if let Ok(parent) = parent.downcast::<gtk::Window>() {
                if let Some(path) = crate::gui::utils::open_file_chooser_dialog(
                    &parent,
                    "Select Password List",
                    &[("Text Files", &["*.txt"]), ("All Files", &["*"])],
                ) {
                    self.password_list_entry.set_text(&path.to_string_lossy());
                }
            }
        }
    }
    
    /// Handle save button click
    fn on_save_button_clicked(&self) {
        // Create attack configuration from the form
        // TODO: Implement actual configuration saving
    }
}

/// Login configuration view
#[derive(Clone)]
pub struct LoginConfigView {
    /// Engine instance
    engine: Arc<Mutex<Engine>>,
    
    /// Main widget
    widget: gtk::Box,
    
    /// Protocol-specific option widgets
    protocol_options: HashMap<Protocol, gtk::Widget>,
    
    /// Current protocol
    current_protocol: Rc<RefCell<Protocol>>,
    
    /// Protocol stack
    protocol_stack: gtk::Stack,
    
    /// Timeout adjustment
    timeout_adjustment: gtk::Adjustment,
}

impl LoginConfigView {
    /// Create a new login configuration view
    pub fn new(engine: Arc<Mutex<Engine>>) -> Self {
        // Create main container
        let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
        widget.set_margin_start(10);
        widget.set_margin_end(10);
        widget.set_margin_top(10);
        widget.set_margin_bottom(10);
        
        // Create header
        let header_label = gtk::Label::new(Some("Connection Configuration"));
        header_label.style_context().add_class("title-1");
        widget.append(&header_label);
        
        // Create protocol selector
        let protocol_frame = gtk::Frame::new(Some("Protocol"));
        let protocol_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        protocol_box.set_margin_start(10);
        protocol_box.set_margin_end(10);
        protocol_box.set_margin_top(10);
        protocol_box.set_margin_bottom(10);
        protocol_frame.set_child(Some(&protocol_box));
        
        let protocol_combo = gtk::ComboBoxText::new();
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
            protocol_combo.append_text(&format!("{}", protocol));
        }
        protocol_combo.set_active(Some(0));
        protocol_box.append(&protocol_combo);
        
        // Create protocol-specific options stack
        let protocol_stack = gtk::Stack::new();
        
        // Create timeout selector
        let timeout_frame = gtk::Frame::new(Some("Connection Timeout"));
        let timeout_box = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        timeout_box.set_margin_start(10);
        timeout_box.set_margin_end(10);
        timeout_box.set_margin_top(10);
        timeout_box.set_margin_bottom(10);
        
        let timeout_label = gtk::Label::new(Some("Timeout (seconds):"));
        timeout_box.append(&timeout_label);
        
        let timeout_adjustment = gtk::Adjustment::new(10.0, 1.0, 60.0, 1.0, 5.0, 0.0);
        let timeout_spin = gtk::SpinButton::new(Some(&timeout_adjustment), 1.0, 0);
        timeout_box.append(&timeout_spin);
        
        timeout_frame.set_child(Some(&timeout_box));
        
        // Create protocol option widgets
        let mut protocol_options = HashMap::new();
        
        // SSH options
        let ssh_options = create_ssh_options();
        protocol_stack.add_titled(&ssh_options, Some("SSH"), "SSH");
        protocol_options.insert(Protocol::SSH, ssh_options.into());
        
        // FTP options
        let ftp_options = create_ftp_options();
        protocol_stack.add_titled(&ftp_options, Some("FTP"), "FTP");
        protocol_options.insert(Protocol::FTP, ftp_options.into());
        
        // HTTP options
        let http_options = create_http_options();
        protocol_stack.add_titled(&http_options, Some("HTTP"), "HTTP");
        protocol_options.insert(Protocol::HTTP, http_options.clone().into());
        protocol_options.insert(Protocol::HTTPS, http_options.into());
        
        // SMTP options
        let smtp_options = create_smtp_options();
        protocol_stack.add_titled(&smtp_options, Some("SMTP"), "SMTP");
        protocol_options.insert(Protocol::SMTP, smtp_options.clone().into());
        protocol_options.insert(Protocol::SMTPS, smtp_options.into());
        
        // MySQL options
        let mysql_options = create_mysql_options();
        protocol_stack.add_titled(&mysql_options, Some("MySQL"), "MySQL");
        protocol_options.insert(Protocol::MySQL, mysql_options.into());
        
        // PostgreSQL options
        let pg_options = create_postgres_options();
        protocol_stack.add_titled(&pg_options, Some("PostgreSQL"), "PostgreSQL");
        protocol_options.insert(Protocol::PostgreSQL, pg_options.into());
        
        // SMB options
        let smb_options = create_smb_options();
        protocol_stack.add_titled(&smb_options, Some("SMB"), "SMB");
        protocol_options.insert(Protocol::SMB, smb_options.into());
        
        // Add options frame
        let options_frame = gtk::Frame::new(Some("Protocol-specific Options"));
        options_frame.set_child(Some(&protocol_stack));
        
        // Add frames to main widget
        widget.append(&protocol_frame);
        widget.append(&options_frame);
        widget.append(&timeout_frame);
        
        // Track current protocol
        let current_protocol = Rc::new(RefCell::new(Protocol::SSH));
        
        // Connect protocol change handler
        let cp = current_protocol.clone();
        let ps = protocol_stack.clone();
        protocol_combo.connect_changed(move |combo| {
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
                    *cp.borrow_mut() = protocol;
                    
                    // Show the appropriate options panel
                    match protocol {
                        Protocol::SSH => ps.set_visible_child_name("SSH"),
                        Protocol::FTP => ps.set_visible_child_name("FTP"),
                        Protocol::HTTP | Protocol::HTTPS => ps.set_visible_child_name("HTTP"),
                        Protocol::SMTP | Protocol::SMTPS => ps.set_visible_child_name("SMTP"),
                        Protocol::MySQL => ps.set_visible_child_name("MySQL"),
                        Protocol::PostgreSQL => ps.set_visible_child_name("PostgreSQL"),
                        Protocol::SMB => ps.set_visible_child_name("SMB"),
                    }
                }
            }
        });
        
        Self {
            engine,
            widget,
            protocol_options,
            current_protocol,
            protocol_stack,
            timeout_adjustment,
        }
    }
    
    /// Get the main widget
    pub fn widget(&self) -> &gtk::Box {
        &self.widget
    }
    
    /// Get connection options as a HashMap
    pub fn get_options(&self) -> HashMap<String, String> {
        let mut options = HashMap::new();
        
        // Get protocol-specific options based on current protocol
        let protocol = *self.current_protocol.borrow();
        
        match protocol {
            Protocol::SSH => get_ssh_options(&mut options),
            Protocol::FTP => get_ftp_options(&mut options),
            Protocol::HTTP | Protocol::HTTPS => get_http_options(&mut options),
            Protocol::SMTP | Protocol::SMTPS => get_smtp_options(&mut options),
            Protocol::MySQL => get_mysql_options(&mut options),
            Protocol::PostgreSQL => get_postgres_options(&mut options),
            Protocol::SMB => get_smb_options(&mut options),
        }
        
        options
    }
}

/// Create SSH options widget
fn create_ssh_options() -> gtk::Box {
    let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
    widget.set_margin_start(10);
    widget.set_margin_end(10);
    widget.set_margin_top(10);
    widget.set_margin_bottom(10);
    
    let auth_label = gtk::Label::new(Some("Authentication Method:"));
    auth_label.set_halign(gtk::Align::Start);
    widget.append(&auth_label);
    
    let auth_combo = gtk::ComboBoxText::new();
    auth_combo.append_text("password");
    auth_combo.append_text("keyboard-interactive");
    auth_combo.set_active(Some(0));
    widget.append(&auth_combo);
    
    widget
}

/// Create FTP options widget
fn create_ftp_options() -> gtk::Box {
    let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
    widget.set_margin_start(10);
    widget.set_margin_end(10);
    widget.set_margin_top(10);
    widget.set_margin_bottom(10);
    
    let passive_check = gtk::CheckButton::with_label("Use Passive Mode");
    passive_check.set_active(true);
    widget.append(&passive_check);
    
    widget
}

/// Create HTTP options widget
fn create_http_options() -> gtk::Box {
    let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
    widget.set_margin_start(10);
    widget.set_margin_end(10);
    widget.set_margin_top(10);
    widget.set_margin_bottom(10);
    
    let auth_label = gtk::Label::new(Some("Authentication Type:"));
    auth_label.set_halign(gtk::Align::Start);
    widget.append(&auth_label);
    
    let auth_combo = gtk::ComboBoxText::new();
    auth_combo.append_text("basic");
    auth_combo.append_text("digest");
    auth_combo.append_text("form");
    auth_combo.set_active(Some(0));
    widget.append(&auth_combo);
    
    let url_label = gtk::Label::new(Some("Login URL:"));
    url_label.set_halign(gtk::Align::Start);
    widget.append(&url_label);
    
    let url_entry = gtk::Entry::new();
    url_entry.set_placeholder_text(Some("https://example.com/login"));
    widget.append(&url_entry);
    
    widget
}

/// Create SMTP options widget
fn create_smtp_options() -> gtk::Box {
    let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
    widget.set_margin_start(10);
    widget.set_margin_end(10);
    widget.set_margin_top(10);
    widget.set_margin_bottom(10);
    
    let auth_label = gtk::Label::new(Some("Authentication Method:"));
    auth_label.set_halign(gtk::Align::Start);
    widget.append(&auth_label);
    
    let auth_combo = gtk::ComboBoxText::new();
    auth_combo.append_text("None");
    auth_combo.append_text("PLAIN");
    auth_combo.append_text("LOGIN");
    auth_combo.set_active(Some(0));
    widget.append(&auth_combo);
    
    widget
}

/// Create MySQL options widget
fn create_mysql_options() -> gtk::Box {
    let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
    widget.set_margin_start(10);
    widget.set_margin_end(10);
    widget.set_margin_top(10);
    widget.set_margin_bottom(10);
    
    let db_label = gtk::Label::new(Some("Database Name:"));
    db_label.set_halign(gtk::Align::Start);
    widget.append(&db_label);
    
    let db_entry = gtk::Entry::new();
    db_entry.set_placeholder_text(Some("Database name"));
    widget.append(&db_entry);
    
    widget
}

/// Create PostgreSQL options widget
fn create_postgres_options() -> gtk::Box {
    let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
    widget.set_margin_start(10);
    widget.set_margin_end(10);
    widget.set_margin_top(10);
    widget.set_margin_bottom(10);
    
    let db_label = gtk::Label::new(Some("Database Name:"));
    db_label.set_halign(gtk::Align::Start);
    widget.append(&db_label);
    
    let db_entry = gtk::Entry::new();
    db_entry.set_placeholder_text(Some("Database name"));
    widget.append(&db_entry);
    
    widget
}

/// Create SMB options widget
fn create_smb_options() -> gtk::Box {
    let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
    widget.set_margin_start(10);
    widget.set_margin_end(10);
    widget.set_margin_top(10);
    widget.set_margin_bottom(10);
    
    let domain_label = gtk::Label::new(Some("Domain:"));
    domain_label.set_halign(gtk::Align::Start);
    widget.append(&domain_label);
    
    let domain_entry = gtk::Entry::new();
    domain_entry.set_placeholder_text(Some("WORKGROUP"));
    widget.append(&domain_entry);
    
    let share_label = gtk::Label::new(Some("Share:"));
    share_label.set_halign(gtk::Align::Start);
    widget.append(&share_label);
    
    let share_entry = gtk::Entry::new();
    share_entry.set_placeholder_text(Some("share"));
    widget.append(&share_entry);
    
    widget
}

/// Get SSH options from the widget
fn get_ssh_options(options: &mut HashMap<String, String>) {
    // This would normally extract values from the widgets
    options.insert("auth_method".to_string(), "password".to_string());
}

/// Get FTP options from the widget
fn get_ftp_options(options: &mut HashMap<String, String>) {
    options.insert("passive".to_string(), "true".to_string());
}

/// Get HTTP options from the widget
fn get_http_options(options: &mut HashMap<String, String>) {
    options.insert("auth_type".to_string(), "basic".to_string());
    options.insert("login_url".to_string(), "/login".to_string());
}

/// Get SMTP options from the widget
fn get_smtp_options(options: &mut HashMap<String, String>) {
    options.insert("auth_method".to_string(), "plain".to_string());
}

/// Get MySQL options from the widget
fn get_mysql_options(options: &mut HashMap<String, String>) {
    options.insert("database".to_string(), "mysql".to_string());
}

/// Get PostgreSQL options from the widget
fn get_postgres_options(options: &mut HashMap<String, String>) {
    options.insert("database".to_string(), "postgres".to_string());
}

/// Get SMB options from the widget
fn get_smb_options(options: &mut HashMap<String, String>) {
    options.insert("domain".to_string(), "WORKGROUP".to_string());
    options.insert("share".to_string(), "C$".to_string());
} 