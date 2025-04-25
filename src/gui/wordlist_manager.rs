use gtk::prelude::*;
use gtk::{
    Box as GtkBox, Button, Entry, Grid, Label, ListBox, Orientation, 
    ScrolledWindow, TextView,
};
use gtk::glib::clone;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use std::fs;
use log::{info, warn, error};

use crate::core::Engine;
use crate::core::wordlist::WordlistManager as CoreWordlistManager;

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
        match Rc::try_unwrap(page_rc) {
            Ok(page) => page,
            Err(_) => {
                log::error!("Unable to unwrap Rc in WordlistManager");
                // Create a new instance as fallback
                WordlistManagerPage::new(engine.clone())
            }
        }
    }
    
    /// Get the root widget
    pub fn get_widget(&self) -> GtkBox {
        self.root.clone()
    }
    
    /// Handle add username list button click
    fn on_add_username_list_clicked(&self) {
        if let Some(parent) = self.root.downcast::<gtk::Window>().ok() {
            let file_chooser = gtk::FileChooserNative::new(
                Some("Select Wordlist File"),
                Some(&parent),
                gtk::FileChooserAction::Open,
                Some("Open"),
                Some("Cancel"),
            );
            
            file_chooser.connect_response(move |dialog, response| {
                if response == gtk::ResponseType::Accept {
                    if let Some(file) = dialog.file() {
                        if let Some(path) = file.path() {
                            // TODO: Implement file selection and list addition
                        }
                    }
                }
            });
            
            file_chooser.show();
        }
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

/// Wordlist manager view
#[derive(Clone)]
pub struct WordlistManager {
    /// Engine instance
    engine: Arc<Mutex<Engine>>,
    
    /// Main widget
    widget: gtk::Box,
    
    /// Username list store
    username_list_store: gtk::ListStore,
    
    /// Password list store
    password_list_store: gtk::ListStore,
    
    /// Current directory
    current_dir: Arc<Mutex<PathBuf>>,
}

impl WordlistManager {
    /// Create a new wordlist manager
    pub fn new(engine: Arc<Mutex<Engine>>) -> Self {
        // Create main container
        let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
        widget.set_margin_start(10);
        widget.set_margin_end(10);
        widget.set_margin_top(10);
        widget.set_margin_bottom(10);
        
        // Create header
        let header_label = gtk::Label::new(Some("Wordlist Manager"));
        header_label.style_context().add_class("title-1");
        widget.append(&header_label);
        
        // Create paned view for username/password list management
        let paned = gtk::Paned::new(gtk::Orientation::Horizontal);
        
        // Username list side
        let username_frame = gtk::Frame::new(Some("Username Lists"));
        let username_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        username_box.set_margin_start(10);
        username_box.set_margin_end(10);
        username_box.set_margin_top(10);
        username_box.set_margin_bottom(10);
        
        // Create list store for username lists
        let username_list_store = gtk::ListStore::new(&[
            glib::Type::STRING, // Filename
            glib::Type::STRING, // Path
            glib::Type::U32,    // Size (KB)
            glib::Type::U32,    // Entry Count
        ]);
        
        let username_tree = gtk::TreeView::with_model(&username_list_store);
        username_tree.set_headers_visible(true);
        
        // Add columns
        add_column(&username_tree, "Filename", 0);
        add_column(&username_tree, "Size (KB)", 2);
        add_column(&username_tree, "Entries", 3);
        
        let username_scroll = gtk::ScrolledWindow::new();
        username_scroll.set_hexpand(true);
        username_scroll.set_vexpand(true);
        username_scroll.set_min_content_height(300);
        username_scroll.set_child(Some(&username_tree));
        
        // Create username list controls
        let username_controls = gtk::Box::new(gtk::Orientation::Horizontal, 5);
        let username_add_button = gtk::Button::with_label("Add");
        let username_remove_button = gtk::Button::with_label("Remove");
        let username_edit_button = gtk::Button::with_label("Edit");
        
        username_controls.append(&username_add_button);
        username_controls.append(&username_remove_button);
        username_controls.append(&username_edit_button);
        
        username_box.append(&username_scroll);
        username_box.append(&username_controls);
        
        username_frame.set_child(Some(&username_box));
        
        // Password list side
        let password_frame = gtk::Frame::new(Some("Password Lists"));
        let password_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        password_box.set_margin_start(10);
        password_box.set_margin_end(10);
        password_box.set_margin_top(10);
        password_box.set_margin_bottom(10);
        
        // Create list store for password lists
        let password_list_store = gtk::ListStore::new(&[
            glib::Type::STRING, // Filename
            glib::Type::STRING, // Path
            glib::Type::U32,    // Size (KB)
            glib::Type::U32,    // Entry Count
        ]);
        
        let password_tree = gtk::TreeView::with_model(&password_list_store);
        password_tree.set_headers_visible(true);
        
        // Add columns
        add_column(&password_tree, "Filename", 0);
        add_column(&password_tree, "Size (KB)", 2);
        add_column(&password_tree, "Entries", 3);
        
        let password_scroll = gtk::ScrolledWindow::new();
        password_scroll.set_hexpand(true);
        password_scroll.set_vexpand(true);
        password_scroll.set_min_content_height(300);
        password_scroll.set_child(Some(&password_tree));
        
        // Create password list controls
        let password_controls = gtk::Box::new(gtk::Orientation::Horizontal, 5);
        let password_add_button = gtk::Button::with_label("Add");
        let password_remove_button = gtk::Button::with_label("Remove");
        let password_edit_button = gtk::Button::with_label("Edit");
        
        password_controls.append(&password_add_button);
        password_controls.append(&password_remove_button);
        password_controls.append(&password_edit_button);
        
        password_box.append(&password_scroll);
        password_box.append(&password_controls);
        
        password_frame.set_child(Some(&password_box));
        
        // Add frames to paned view
        paned.set_start_child(Some(&username_frame));
        paned.set_end_child(Some(&password_frame));
        paned.set_position(300);
        
        // Add tools section
        let tools_frame = gtk::Frame::new(Some("Wordlist Tools"));
        let tools_grid = gtk::Grid::new();
        tools_grid.set_row_spacing(10);
        tools_grid.set_column_spacing(10);
        tools_grid.set_margin_start(10);
        tools_grid.set_margin_end(10);
        tools_grid.set_margin_top(10);
        tools_grid.set_margin_bottom(10);
        
        // Add tools
        let combine_button = gtk::Button::with_label("Combine Lists");
        tools_grid.attach(&combine_button, 0, 0, 1, 1);
        
        let sort_button = gtk::Button::with_label("Sort & Deduplicate");
        tools_grid.attach(&sort_button, 1, 0, 1, 1);
        
        let generate_button = gtk::Button::with_label("Generate Variations");
        tools_grid.attach(&generate_button, 2, 0, 1, 1);
        
        let analyze_button = gtk::Button::with_label("Analyze List");
        tools_grid.attach(&analyze_button, 3, 0, 1, 1);
        
        tools_frame.set_child(Some(&tools_grid));
        
        // Add all to main widget
        widget.append(&paned);
        widget.append(&tools_frame);
        
        // Get wordlist directory
        let current_dir = if let Ok(engine) = engine.lock() {
            let base_dir = engine.base_dir();
            let wordlist_dir = base_dir.join("wordlists");
            
            // Create directory if it doesn't exist
            if !wordlist_dir.exists() {
                if let Err(e) = fs::create_dir_all(&wordlist_dir) {
                    error!("Failed to create wordlist directory: {}", e);
                }
            }
            
            wordlist_dir
        } else {
            PathBuf::from("./wordlists")
        };
        
        let current_dir = Arc::new(Mutex::new(current_dir));
        
        // Create instance
        let instance = Self {
            engine,
            widget,
            username_list_store,
            password_list_store,
            current_dir,
        };
        
        // Set up add buttons
        let instance_add_username = instance.clone();
        username_add_button.connect_clicked(move |_| {
            if let Err(e) = instance_add_username.add_wordlist(true) {
                error!("Error adding username list: {}", e);
            }
        });
        
        let instance_add_password = instance.clone();
        password_add_button.connect_clicked(move |_| {
            if let Err(e) = instance_add_password.add_wordlist(false) {
                error!("Error adding password list: {}", e);
            }
        });
        
        // Load existing wordlists
        instance.refresh_wordlists();
        
        instance
    }
    
    /// Get the main widget
    pub fn widget(&self) -> &gtk::Box {
        &self.widget
    }
    
    /// Refresh the wordlist views
    fn refresh_wordlists(&self) {
        // Clear existing lists
        self.username_list_store.clear();
        self.password_list_store.clear();
        
        // Get current directory
        let wordlist_dir = match self.current_dir.lock() {
            Ok(dir) => dir.clone(),
            Err(_) => {
                error!("Failed to lock wordlist directory");
                return;
            }
        };
        
        // List username lists
        let username_dir = wordlist_dir.join("usernames");
        if username_dir.exists() {
            self.load_wordlists(&username_dir, true);
        }
        
        // List password lists
        let password_dir = wordlist_dir.join("passwords");
        if password_dir.exists() {
            self.load_wordlists(&password_dir, false);
        }
    }
    
    /// Load wordlists from a directory
    fn load_wordlists(&self, dir: &Path, is_username: bool) {
        if !dir.exists() || !dir.is_dir() {
            return;
        }
        
        // Get file list
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                error!("Failed to read directory {:?}: {}", dir, e);
                return;
            }
        };
        
        // Process each file
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                
                // Skip non-files
                if !path.is_file() {
                    continue;
                }
                
                // Skip non-text files
                let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if !["txt", "lst", "list", "dict"].contains(&extension) {
                    continue;
                }
                
                // Get filename
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Unknown")
                    .to_string();
                
                // Get file size
                let metadata = match fs::metadata(&path) {
                    Ok(meta) => meta,
                    Err(_) => continue,
                };
                
                let size_kb = (metadata.len() / 1024) as u32;
                
                // Count lines
                let content = match fs::read_to_string(&path) {
                    Ok(content) => content,
                    Err(_) => continue,
                };
                
                let line_count = content.lines().count() as u32;
                
                // Add to appropriate list store
                let store = if is_username {
                    &self.username_list_store
                } else {
                    &self.password_list_store
                };
                
                store.insert_with_values(
                    None,
                    &[
                        (0, &filename),
                        (1, &path.to_string_lossy().to_string()),
                        (2, &size_kb),
                        (3, &line_count),
                    ],
                );
            }
        }
    }
    
    /// Add a new wordlist
    fn add_wordlist(&self, is_username: bool) -> anyhow::Result<()> {
        let file_chooser = gtk::FileChooserNative::new(
            Some(if is_username { "Select Username List" } else { "Select Password List" }),
            None::<&gtk::Window>,
            gtk::FileChooserAction::Open,
            &[
                ("Cancel", gtk::ResponseType::Cancel),
                ("Open", gtk::ResponseType::Accept),
            ],
        );
        
        let file_filter = gtk::FileFilter::new();
        file_filter.set_name(Some("Text Files"));
        file_filter.add_pattern("*.txt");
        file_filter.add_pattern("*.lst");
        file_filter.add_pattern("*.list");
        file_filter.add_pattern("*.dict");
        file_chooser.add_filter(&file_filter);
        
        let wordlist_dir = self.current_dir.lock().map_err(|_| anyhow::anyhow!("Failed to lock wordlist directory"))?;
        
        // Make sure the target directory exists
        let target_dir = if is_username {
            wordlist_dir.join("usernames")
        } else {
            wordlist_dir.join("passwords")
        };
        
        if !target_dir.exists() {
            fs::create_dir_all(&target_dir)?;
        }
        
        // Current instance for the closure
        let instance = self.clone();
        let target_dir_clone = target_dir.clone();
        
        file_chooser.connect_response(move |dialog, response| {
            if response == gtk::ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(path) = file.path() {
                        // Copy file to wordlist directory
                        if let Some(filename) = path.file_name() {
                            let target_path = target_dir_clone.join(filename);
                            
                            match fs::copy(&path, &target_path) {
                                Ok(_) => {
                                    info!("Copied wordlist to {:?}", target_path);
                                    instance.refresh_wordlists();
                                },
                                Err(e) => {
                                    error!("Failed to copy wordlist: {}", e);
                                }
                            }
                        }
                    }
                }
            }
            dialog.close();
        });
        
        file_chooser.show();
        
        Ok(())
    }
}

/// Add a column to a TreeView
fn add_column(tree: &gtk::TreeView, title: &str, column_id: i32) {
    let column = gtk::TreeViewColumn::new();
    column.set_title(title);
    
    let cell = gtk::CellRendererText::new();
    column.pack_start(&cell, true);
    column.add_attribute(&cell, "text", column_id);
    
    tree.append_column(&column);
} 