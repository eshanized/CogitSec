use gtk::prelude::*;
use gtk::{Box as GtkBox, Grid, Label, Entry, SpinButton, ComboBoxText, CheckButton};
use std::rc::Rc;

use crate::core::Engine;
use crate::core::protocols::Protocol;

/// Protocol-specific configuration page
pub struct ProtocolConfigPage {
    /// Root widget
    root: GtkBox,
    
    /// Engine reference
    engine: Rc<Engine>,
    
    /// Currently selected protocol
    protocol: Protocol,
}

impl ProtocolConfigPage {
    /// Create a new protocol configuration page
    pub fn new(engine: Rc<Engine>, protocol: Protocol) -> Self {
        let root = GtkBox::new(gtk::Orientation::Vertical, 10);
        root.set_margin_start(10);
        root.set_margin_end(10);
        root.set_margin_top(10);
        root.set_margin_bottom(10);
        
        let label = Label::new(Some(&format!("{} Configuration", protocol)));
        label.set_halign(gtk::Align::Start);
        root.append(&label);
        
        // Create a grid for configuration options
        let grid = Grid::new();
        grid.set_row_spacing(10);
        grid.set_column_spacing(10);
        grid.set_margin_top(10);
        
        // Add protocol-specific options
        match protocol {
            Protocol::SSH => {
                add_grid_row(&grid, 0, "Key authentication:", &create_checkbox(false));
                add_grid_row(&grid, 1, "Port forwarding:", &create_checkbox(false));
            },
            Protocol::HTTP | Protocol::HTTPS => {
                add_grid_row(&grid, 0, "Authentication type:", &create_combobox(&["Basic", "Form", "Digest"]));
                add_grid_row(&grid, 1, "Username field:", &create_entry("username"));
                add_grid_row(&grid, 2, "Password field:", &create_entry("password"));
                add_grid_row(&grid, 3, "URL path:", &create_entry("/login"));
            },
            Protocol::FTP => {
                add_grid_row(&grid, 0, "Passive mode:", &create_checkbox(true));
            },
            Protocol::MySQL | Protocol::PostgreSQL => {
                add_grid_row(&grid, 0, "Database:", &create_entry("mysql"));
            },
            Protocol::SMTP | Protocol::SMTPS => {
                add_grid_row(&grid, 0, "Require TLS:", &create_checkbox(false));
            },
            Protocol::SMB => {
                add_grid_row(&grid, 0, "Domain:", &create_entry("WORKGROUP"));
                add_grid_row(&grid, 1, "Share:", &create_entry(""));
            }
        }
        
        root.append(&grid);
        
        Self {
            root,
            engine,
            protocol,
        }
    }
    
    /// Get the widget
    pub fn get_widget(&self) -> GtkBox {
        self.root.clone()
    }
    
    /// Get the protocol
    pub fn get_protocol(&self) -> Protocol {
        self.protocol
    }
}

// Helper functions to create widgets
fn create_entry(default_text: &str) -> Entry {
    let entry = Entry::new();
    entry.set_text(default_text);
    entry
}

fn create_checkbox(default_state: bool) -> CheckButton {
    let check = CheckButton::new();
    check.set_active(default_state);
    check
}

fn create_combobox(items: &[&str]) -> ComboBoxText {
    let combo = ComboBoxText::new();
    for item in items {
        combo.append_text(item);
    }
    if !items.is_empty() {
        combo.set_active(Some(0));
    }
    combo
}

fn add_grid_row(grid: &Grid, row: i32, label_text: &str, widget: &impl IsA<gtk::Widget>) {
    let label = Label::new(Some(label_text));
    label.set_halign(gtk::Align::End);
    grid.attach(&label, 0, row, 1, 1);
    grid.attach(widget, 1, row, 1, 1);
} 