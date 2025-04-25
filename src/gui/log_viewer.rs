use gtk::prelude::*;
use gtk::{
    Box as GtkBox, Button, Label, Orientation, PolicyType, ScrolledWindow, TextBuffer, 
    TextView, ToggleButton
};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::cell::RefCell;

use crate::core::Engine;
use crate::core::logger::{LogEntry, LogLevel};

/// Log viewer widget
#[derive(Clone)]
pub struct LogViewer {
    /// Engine instance
    engine: Arc<Mutex<Engine>>,
    
    /// Main widget
    widget: gtk::Box,
    
    /// Log buffer
    buffer: gtk::TextBuffer,
    
    /// Auto-scroll switch
    auto_scroll: Rc<RefCell<bool>>,
    
    /// Only show errors switch
    only_errors: Rc<RefCell<bool>>,
    
    /// Last seen log ID
    last_seen_id: Rc<RefCell<usize>>,
}

impl LogViewer {
    /// Create a new log viewer
    pub fn new(engine: Arc<Mutex<Engine>>) -> Self {
        // Create main widget
        let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
        widget.set_margin_start(10);
        widget.set_margin_end(10);
        widget.set_margin_top(10);
        widget.set_margin_bottom(10);
        
        // Create header
        let header_label = gtk::Label::new(Some("Application Logs"));
        header_label.style_context().add_class("title-1");
        widget.append(&header_label);
        
        // Create log view
        let log_frame = gtk::Frame::new(Some("Logs"));
        let log_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        log_box.set_margin_start(10);
        log_box.set_margin_end(10);
        log_box.set_margin_top(10);
        log_box.set_margin_bottom(10);
        
        // Create text view
        let scroll = gtk::ScrolledWindow::new();
        scroll.set_hexpand(true);
        scroll.set_vexpand(true);
        
        let text_view = gtk::TextView::new();
        text_view.set_editable(false);
        text_view.set_cursor_visible(false);
        text_view.set_monospace(true);
        text_view.set_wrap_mode(gtk::WrapMode::WordChar);
        scroll.set_child(Some(&text_view));
        
        let buffer = text_view.buffer();
        
        // Create tag for errors
        let error_tag = buffer.create_tag(Some("error"), &[("foreground", &"#ff0000")]);
        
        // Create tag for info
        let info_tag = buffer.create_tag(Some("info"), &[("foreground", &"#000000")]);
        
        // Create tag for warnings
        let warning_tag = buffer.create_tag(Some("warning"), &[("foreground", &"#ffaa00")]);
        
        // Create tag for debug
        let debug_tag = buffer.create_tag(Some("debug"), &[("foreground", &"#999999")]);
        
        // Create tag for timestamps
        let timestamp_tag = buffer.create_tag(Some("timestamp"), &[("weight", &pango::Weight::Bold.to_value())]);
        
        // Create controls
        let controls_box = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        
        let clear_button = gtk::Button::with_label("Clear");
        controls_box.append(&clear_button);
        
        let auto_scroll_check = gtk::CheckButton::with_label("Auto-scroll");
        auto_scroll_check.set_active(true);
        controls_box.append(&auto_scroll_check);
        
        let only_errors_check = gtk::CheckButton::with_label("Show only errors");
        only_errors_check.set_active(false);
        controls_box.append(&only_errors_check);
        
        // Add to log box
        log_box.append(&scroll);
        log_box.append(&controls_box);
        
        // Add to frame
        log_frame.set_child(Some(&log_box));
        
        // Add to main widget
        widget.append(&log_frame);
        
        // State variables
        let auto_scroll = Rc::new(RefCell::new(true));
        let only_errors = Rc::new(RefCell::new(false));
        let last_seen_id = Rc::new(RefCell::new(0usize));
        
        // Create instance
        let instance = Self {
            engine,
            widget,
            buffer,
            auto_scroll,
            only_errors,
            last_seen_id,
        };
        
        // Set up auto-scroll check
        let auto_scroll_ref = instance.auto_scroll.clone();
        auto_scroll_check.connect_toggled(move |check| {
            *auto_scroll_ref.borrow_mut() = check.is_active();
        });
        
        // Set up only-errors check
        let only_errors_ref = instance.only_errors.clone();
        let instance_refresh = instance.clone();
        only_errors_check.connect_toggled(move |check| {
            *only_errors_ref.borrow_mut() = check.is_active();
            instance_refresh.refresh_logs();
        });
        
        // Set up clear button
        let instance_clear = instance.clone();
        clear_button.connect_clicked(move |_| {
            instance_clear.buffer.set_text("");
            *instance_clear.last_seen_id.borrow_mut() = 0;
        });
        
        // Initial refresh
        instance.refresh_logs();
        
        instance
    }
    
    /// Get the main widget
    pub fn widget(&self) -> &gtk::Box {
        &self.widget
    }
    
    /// Refresh the logs display
    pub fn refresh_logs(&self) {
        if let Ok(engine) = self.engine.lock() {
            if let Ok(logger) = engine.logger().lock() {
                // Get entries
                let entries = logger.entries();
                
                // Get only new entries
                let last_id = *self.last_seen_id.borrow();
                let new_entries: Vec<&LogEntry> = entries.iter()
                    .skip(last_id)
                    .filter(|e| !*self.only_errors.borrow() || e.level == LogLevel::Error)
                    .collect();
                
                if !new_entries.is_empty() {
                    // Update the last seen ID
                    if let Some(_) = new_entries.last() {
                        *self.last_seen_id.borrow_mut() = last_id + new_entries.len();
                    }
                    
                    // Get current end iter
                    let mut end_iter = self.buffer.end_iter();
                    
                    // Append new entries
                    for entry in new_entries {
                        // Add a newline if the buffer is not empty
                        if self.buffer.char_count() > 0 {
                            self.buffer.insert(&mut end_iter, "\n");
                        }
                        
                        // Add timestamp
                        let timestamp = entry.timestamp.format("[%Y-%m-%d %H:%M:%S]").to_string();
                        let timestamp_offset = end_iter.offset();
                        self.buffer.insert(&mut end_iter, &timestamp);
                        self.buffer.apply_tag_by_name(
                            "timestamp",
                            &self.buffer.iter_at_offset(timestamp_offset),
                            &end_iter,
                        );
                        
                        // Add level and message
                        self.buffer.insert(&mut end_iter, &format!(" {} - ", entry.level));
                        
                        // Apply tag based on level
                        let message_offset = end_iter.offset();
                        self.buffer.insert(&mut end_iter, &entry.message);
                        
                        let tag_name = match entry.level {
                            LogLevel::Error => "error",
                            LogLevel::Warning => "warning",
                            LogLevel::Info => "info",
                            LogLevel::Debug => "debug",
                        };
                        
                        self.buffer.apply_tag_by_name(
                            tag_name,
                            &self.buffer.iter_at_offset(message_offset),
                            &end_iter,
                        );
                    }
                    
                    // Auto-scroll if enabled
                    if *self.auto_scroll.borrow() {
                        let scroll_mark = self.buffer.create_mark(None, &end_iter, false);
                        
                        // Find an existing TextView with our buffer, and scroll it
                        // This is a simplified approach - in a real app this would need more work
                        // to ensure we're scrolling the correct view
                        self.buffer.scroll_mark_onscreen(&scroll_mark);
                    }
                }
            }
        }
    }
} 