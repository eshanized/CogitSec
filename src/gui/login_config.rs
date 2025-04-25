use gtk::prelude::*;
use gtk::{
    Box as GtkBox, Button, ComboBoxText, Entry, Grid, Label, Orientation,
    Scale, SpinButton,
};
use std::rc::Rc;

use crate::core::Engine;

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
            let parent = parent.downcast::<gtk::Window>().unwrap();
            
            if let Some(path) = crate::gui::utils::open_file_chooser_dialog(
                &parent,
                "Select Username List",
                &[("Text Files", &["*.txt"]), ("All Files", &["*"])],
            ) {
                self.username_list_entry.set_text(&path.to_string_lossy());
            }
        }
    }
    
    /// Handle password list button click
    fn on_password_list_button_clicked(&self) {
        if let Some(parent) = self.root.ancestor(gtk::Window::static_type()) {
            let parent = parent.downcast::<gtk::Window>().unwrap();
            
            if let Some(path) = crate::gui::utils::open_file_chooser_dialog(
                &parent,
                "Select Password List",
                &[("Text Files", &["*.txt"]), ("All Files", &["*"])],
            ) {
                self.password_list_entry.set_text(&path.to_string_lossy());
            }
        }
    }
    
    /// Handle save button click
    fn on_save_button_clicked(&self) {
        // Create attack configuration from the form
        // TODO: Implement actual configuration saving
    }
} 