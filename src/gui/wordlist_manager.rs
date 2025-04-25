use gtk::prelude::*;
use gtk::{
    Box as GtkBox, Button, Entry, Grid, Label, ListBox, Orientation, 
    ScrolledWindow, TextView,
};
use gtk::glib::clone;
use std::cell::RefCell;
use std::rc::Rc;

use crate::core::Engine;

/// Wordlist manager page
pub struct WordlistManagerPage {
    /// Root widget
    root: GtkBox,
    
    /// Engine reference
    engine: Rc<Engine>,
    
    /// Username list box
    username_list_box: ListBox,
    
    /// Password list box
    password_list_box: ListBox,
    
    /// Word mangling rules text view
    mangling_rules_text: TextView,
}

impl WordlistManagerPage {
    /// Create a new wordlist manager page
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
            .label("Wordlist Manager")
            .css_classes(vec!["title-1"])
            .halign(gtk::Align::Start)
            .build();
            
        root.append(&title);
        
        // Create the main grid
        let grid = Grid::builder()
            .column_spacing(10)
            .row_spacing(10)
            .hexpand(true)
            .vexpand(true)
            .build();
            
        // Username list section
        let username_frame = gtk::Frame::builder()
            .label("Username Lists")
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let username_box = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .spacing(10)
            .margin_start(10)
            .margin_end(10)
            .margin_top(10)
            .margin_bottom(10)
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let username_list_scroll = ScrolledWindow::builder()
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let username_list_box = ListBox::builder()
            .selection_mode(gtk::SelectionMode::Single)
            .build();
            
        username_list_scroll.set_child(Some(&username_list_box));
        username_box.append(&username_list_scroll);
        
        let username_buttons = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(5)
            .homogeneous(true)
            .margin_top(5)
            .build();
            
        let add_username_list_button = Button::builder()
            .label("Add")
            .build();
            
        let edit_username_list_button = Button::builder()
            .label("Edit")
            .sensitive(false)
            .build();
            
        let remove_username_list_button = Button::builder()
            .label("Remove")
            .sensitive(false)
            .build();
            
        username_buttons.append(&add_username_list_button);
        username_buttons.append(&edit_username_list_button);
        username_buttons.append(&remove_username_list_button);
        
        username_box.append(&username_buttons);
        username_frame.set_child(Some(&username_box));
        
        grid.attach(&username_frame, 0, 0, 1, 1);
        
        // Password list section
        let password_frame = gtk::Frame::builder()
            .label("Password Lists")
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let password_box = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .spacing(10)
            .margin_start(10)
            .margin_end(10)
            .margin_top(10)
            .margin_bottom(10)
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let password_list_scroll = ScrolledWindow::builder()
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let password_list_box = ListBox::builder()
            .selection_mode(gtk::SelectionMode::Single)
            .build();
            
        password_list_scroll.set_child(Some(&password_list_box));
        password_box.append(&password_list_scroll);
        
        let password_buttons = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(5)
            .homogeneous(true)
            .margin_top(5)
            .build();
            
        let add_password_list_button = Button::builder()
            .label("Add")
            .build();
            
        let edit_password_list_button = Button::builder()
            .label("Edit")
            .sensitive(false)
            .build();
            
        let remove_password_list_button = Button::builder()
            .label("Remove")
            .sensitive(false)
            .build();
            
        password_buttons.append(&add_password_list_button);
        password_buttons.append(&edit_password_list_button);
        password_buttons.append(&remove_password_list_button);
        
        password_box.append(&password_buttons);
        password_frame.set_child(Some(&password_box));
        
        grid.attach(&password_frame, 1, 0, 1, 1);
        
        // Word mangling rules section
        let mangling_frame = gtk::Frame::builder()
            .label("Word Mangling Rules")
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let mangling_box = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .spacing(10)
            .margin_start(10)
            .margin_end(10)
            .margin_top(10)
            .margin_bottom(10)
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let mangling_rules_scroll = ScrolledWindow::builder()
            .hexpand(true)
            .vexpand(true)
            .build();
            
        let mangling_rules_text = TextView::builder()
            .monospace(true)
            .editable(true)
            .build();
            
        mangling_rules_text.buffer().set_text(
            "# Example rules:\n\
             # Append digits\n\
             $1\n\
             $2\n\
             # Capitalize first letter\n\
             c\n\
             # All uppercase\n\
             u\n\
             # All lowercase\n\
             l\n\
             # Replace 'a' with '@'\n\
             sa@\n\
             # Replace 'e' with '3'\n\
             se3\n"
        );
        
        mangling_rules_scroll.set_child(Some(&mangling_rules_text));
        mangling_box.append(&mangling_rules_scroll);
        
        let mangling_buttons = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(5)
            .homogeneous(true)
            .margin_top(5)
            .build();
            
        let save_rules_button = Button::builder()
            .label("Save Rules")
            .build();
            
        let apply_rules_button = Button::builder()
            .label("Apply Rules")
            .build();
            
        mangling_buttons.append(&save_rules_button);
        mangling_buttons.append(&apply_rules_button);
        
        mangling_box.append(&mangling_buttons);
        mangling_frame.set_child(Some(&mangling_box));
        
        grid.attach(&mangling_frame, 0, 1, 2, 1);
        
        root.append(&grid);
        
        // We need to clone these widgets before creating signal handlers
        let username_list_box_clone = username_list_box.clone();
        let password_list_box_clone = password_list_box.clone();
        
        // Create the page object
        let page = Self {
            root,
            engine,
            username_list_box: username_list_box.clone(),
            password_list_box: password_list_box.clone(),
            mangling_rules_text,
        };
        
        // Create a weak reference for signal handlers
        let page_rc = Rc::new(page);
        let page_weak = Rc::downgrade(&page_rc);
        
        // Connect signals
        add_username_list_button.connect_clicked(move |_| {
            if let Some(p) = page_weak.upgrade() {
                p.on_add_username_list_clicked();
            }
        });
        
        let page_weak = Rc::downgrade(&page_rc);
        add_password_list_button.connect_clicked(move |_| {
            if let Some(p) = page_weak.upgrade() {
                p.on_add_password_list_clicked();
            }
        });
        
        username_list_box_clone.connect_row_selected(move |_, row| {
            edit_username_list_button.set_sensitive(row.is_some());
            remove_username_list_button.set_sensitive(row.is_some());
        });
        
        password_list_box_clone.connect_row_selected(move |_, row| {
            edit_password_list_button.set_sensitive(row.is_some());
            remove_password_list_button.set_sensitive(row.is_some());
        });
        
        let page_weak = Rc::downgrade(&page_rc);
        save_rules_button.connect_clicked(move |_| {
            if let Some(p) = page_weak.upgrade() {
                p.on_save_rules_clicked();
            }
        });
        
        let page_weak = Rc::downgrade(&page_rc);
        apply_rules_button.connect_clicked(move |_| {
            if let Some(p) = page_weak.upgrade() {
                p.on_apply_rules_clicked();
            }
        });
        
        // Unwrap the Rc to get our page
        let page = match Rc::try_unwrap(page_rc) {
            Ok(page) => page,
            Err(_) => panic!("Unable to unwrap Rc - this shouldn't happen!"),
        };
        
        page
    }
    
    /// Get the root widget
    pub fn get_widget(&self) -> GtkBox {
        self.root.clone()
    }
    
    /// Handle add username list button click
    fn on_add_username_list_clicked(&self) {
        // TODO: Implement file selection and list addition
    }
    
    /// Handle add password list button click
    fn on_add_password_list_clicked(&self) {
        // TODO: Implement file selection and list addition
    }
    
    /// Handle save rules button click
    fn on_save_rules_clicked(&self) {
        // TODO: Implement rules saving
    }
    
    /// Handle apply rules button click
    fn on_apply_rules_clicked(&self) {
        // TODO: Implement rules application
    }
} 