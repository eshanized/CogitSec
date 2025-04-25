use gtk::prelude::*;
use gtk::{Button, Box as GtkBox, Grid, Label, Orientation, ProgressBar, ScrolledWindow};
use std::rc::Rc;

use crate::core::Engine;

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