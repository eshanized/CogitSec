use gtk::prelude::*;
use gtk::{
    FileChooserAction, FileChooserNative, FileFilter, ResponseType, Window,
};
use gtk::glib;
use std::path::PathBuf;
use std::cell::RefCell;
use std::rc::Rc;

/// Open a file chooser dialog
pub fn open_file_chooser_dialog(
    parent: &impl IsA<Window>,
    title: &str,
    filters: &[(&str, &[&str])],
) -> Option<PathBuf> {
    let dialog = FileChooserNative::new(
        Some(title),
        Some(parent),
        FileChooserAction::Open,
        Some("Open"),
        Some("Cancel"),
    );

    // Add filters
    for (name, patterns) in filters {
        let filter = FileFilter::new();
        filter.set_name(Some(name));
        
        for pattern in *patterns {
            filter.add_pattern(pattern);
        }
        
        dialog.add_filter(&filter);
    }

    // Set up response handling 
    let result = Rc::new(RefCell::new(None));
    let result_clone = result.clone();
    
    dialog.connect_response(move |dialog, response| {
        if response == ResponseType::Accept {
            *result_clone.borrow_mut() = dialog.file().and_then(|file| file.path());
        }
    });
    
    // Present the dialog and wait until a response is received
    dialog.show();
    
    // Wait until response is received
    let context = glib::MainContext::default();
    let main_loop = glib::MainLoop::new(Some(&context), false);
    
    let main_loop_clone = main_loop.clone();
    dialog.connect_response(move |_, _| {
        main_loop_clone.quit();
    });
    
    main_loop.run();
    
    result.borrow().clone()
}

/// Open a save file dialog
pub fn save_file_dialog(
    parent: &impl IsA<Window>,
    title: &str,
    filters: &[(&str, &[&str])],
) -> Option<PathBuf> {
    let dialog = FileChooserNative::new(
        Some(title),
        Some(parent),
        FileChooserAction::Save,
        Some("Save"),
        Some("Cancel"),
    );
    
    // Add filters
    for (name, patterns) in filters {
        let filter = FileFilter::new();
        filter.set_name(Some(name));
        
        for pattern in *patterns {
            filter.add_pattern(pattern);
        }
        
        dialog.add_filter(&filter);
    }
    
    // Set up response handling
    let result = Rc::new(RefCell::new(None));
    let result_clone = result.clone();
    
    dialog.connect_response(move |dialog, response| {
        if response == ResponseType::Accept {
            *result_clone.borrow_mut() = dialog.file().and_then(|file| file.path());
        }
    });
    
    // Present the dialog and wait until a response is received
    dialog.show();
    
    // Wait until response is received
    let context = glib::MainContext::default();
    let main_loop = glib::MainLoop::new(Some(&context), false);
    
    let main_loop_clone = main_loop.clone();
    dialog.connect_response(move |_, _| {
        main_loop_clone.quit();
    });
    
    main_loop.run();
    
    result.borrow().clone()
}

/// Format duration as HH:MM:SS
pub fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    
    format!("{:02}:{:02}:{:02}", hours, minutes, secs)
}

/// Format file size in human-readable format
pub fn format_file_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if size >= GB {
        format!("{:.2} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{} bytes", size)
    }
} 