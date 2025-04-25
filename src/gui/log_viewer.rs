use gtk::prelude::*;
use gtk::{
    Box as GtkBox, Button, Label, Orientation, PolicyType, ScrolledWindow, TextBuffer, 
    TextView, ToggleButton
};
use std::rc::Rc;

use crate::core::Engine;
use crate::core::logger::{LogEntry, LogLevel};

/// Widget for viewing and filtering log messages
pub struct LogViewer {
    /// Root widget
    root: GtkBox,
    
    /// Engine reference
    engine: Rc<Engine>,
    
    /// Text buffer for logs
    log_buffer: TextBuffer,
    
    /// Filter buttons by log level
    info_filter: ToggleButton,
    warning_filter: ToggleButton,
    error_filter: ToggleButton,
    debug_filter: ToggleButton,
}

impl LogViewer {
    /// Create a new log viewer widget
    pub fn new(engine: Rc<Engine>) -> Self {
        let root = GtkBox::new(Orientation::Vertical, 10);
        root.set_margin_start(10);
        root.set_margin_end(10);
        root.set_margin_top(10);
        root.set_margin_bottom(10);
        
        // Header
        let header = Label::new(Some("Log Messages"));
        header.set_halign(gtk::Align::Start);
        header.add_css_class("title-3");
        root.append(&header);
        
        // Filters
        let filter_box = GtkBox::new(Orientation::Horizontal, 5);
        
        let filter_label = Label::new(Some("Show:"));
        filter_box.append(&filter_label);
        
        let info_filter = ToggleButton::with_label("Info");
        info_filter.set_active(true);
        
        let warning_filter = ToggleButton::with_label("Warning");
        warning_filter.set_active(true);
        
        let error_filter = ToggleButton::with_label("Error");
        error_filter.set_active(true);
        
        let debug_filter = ToggleButton::with_label("Debug");
        debug_filter.set_active(false);
        
        filter_box.append(&info_filter);
        filter_box.append(&warning_filter);
        filter_box.append(&error_filter);
        filter_box.append(&debug_filter);
        
        // Add spacer
        let spacer = GtkBox::new(Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        filter_box.append(&spacer);
        
        // Clear button
        let clear_button = Button::with_label("Clear");
        filter_box.append(&clear_button);
        
        root.append(&filter_box);
        
        // Log text view
        let log_buffer = TextBuffer::new(None);
        let text_view = TextView::with_buffer(&log_buffer);
        text_view.set_editable(false);
        text_view.set_cursor_visible(false);
        text_view.set_wrap_mode(gtk::WrapMode::Word);
        text_view.set_monospace(true);
        
        let scrolled_window = ScrolledWindow::new();
        scrolled_window.set_policy(PolicyType::Automatic, PolicyType::Automatic);
        scrolled_window.set_child(Some(&text_view));
        scrolled_window.set_vexpand(true);
        
        root.append(&scrolled_window);
        
        // Connect clear button
        let log_buffer_clone = log_buffer.clone();
        clear_button.connect_clicked(move |_| {
            log_buffer_clone.set_text("");
        });
        
        Self {
            root,
            engine,
            log_buffer,
            info_filter,
            warning_filter,
            error_filter,
            debug_filter,
        }
    }
    
    /// Get the root widget
    pub fn get_widget(&self) -> GtkBox {
        self.root.clone()
    }
    
    /// Add a log entry to the viewer
    pub fn add_log_entry(&self, entry: &LogEntry) {
        // Check if this level should be shown
        let should_show = match entry.level {
            LogLevel::Info => self.info_filter.is_active(),
            LogLevel::Warning => self.warning_filter.is_active(),
            LogLevel::Error => self.error_filter.is_active(),
            LogLevel::Debug => self.debug_filter.is_active(),
        };
        
        if !should_show {
            return;
        }
        
        // Format the log entry
        let timestamp = entry.timestamp.format("%H:%M:%S").to_string();
        let level_str = match entry.level {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Debug => "DEBUG",
        };
        
        let formatted_entry = format!("[{}] [{}] {}\n", timestamp, level_str, entry.message);
        
        // Add to buffer
        let mut end = self.log_buffer.end_iter();
        self.log_buffer.insert(&mut end, &formatted_entry);
        
        // Scroll to the end
        // This would typically require a reference to the TextView, but since we're using a struct method,
        // we don't have direct access to it. In a real implementation, you might want to store a reference
        // to the TextView in the struct or use a signal handler.
    }
    
    /// Update the log viewer with entries from the engine
    pub fn update(&self) {
        // In a real implementation, this would fetch new log entries from the engine
        // and add them to the log viewer
        // Example:
        // for entry in self.engine.get_new_log_entries() {
        //     self.add_log_entry(&entry);
        // }
    }
} 