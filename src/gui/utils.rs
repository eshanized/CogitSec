use gtk::prelude::*;
use gtk::{
    FileChooserAction, FileChooserDialog, FileFilter, ResponseType, Window,
};
use gtk::glib;
use std::path::PathBuf;

/// Open a file chooser dialog
pub fn open_file_chooser_dialog(
    parent: &impl IsA<Window>,
    title: &str,
    filters: &[(&str, &[&str])],
) -> Option<PathBuf> {
    let dialog = FileChooserDialog::new(
        Some(title),
        Some(parent),
        FileChooserAction::Open,
        &[("Cancel", ResponseType::Cancel), ("Open", ResponseType::Accept)],
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
    let result = std::rc::Rc::new(std::cell::RefCell::new(None));
    let result_clone = result.clone();
    
    dialog.connect_response(move |dialog, response| {
        if response == ResponseType::Accept {
            *result_clone.borrow_mut() = dialog.file().and_then(|file| file.path());
        }
        dialog.close();
    });
    
    // Present the dialog and wait synchronously (this is simplified but will work for simple apps)
    dialog.set_modal(true);
    dialog.present();
    
    // Wait until response is received
    while dialog.is_visible() {
        let ctx = glib::MainContext::default();
        let _ = ctx.iteration(true);
    }
    
    // Clone the result before returning to avoid lifetime issues
    let final_result = (*result.borrow()).clone();
    final_result
}

/// Open a save file dialog
pub fn save_file_dialog(
    parent: &impl IsA<Window>,
    title: &str,
    filters: &[(&str, &[&str])],
) -> Option<PathBuf> {
    let dialog = FileChooserDialog::new(
        Some(title),
        Some(parent),
        FileChooserAction::Save,
        &[("Cancel", ResponseType::Cancel), ("Save", ResponseType::Accept)],
    );
    
    // In GTK4, we need to use creation_properties instead of set_do_overwrite_confirmation
    // For now, we'll just work without that functionality
    
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
    let result = std::rc::Rc::new(std::cell::RefCell::new(None));
    let result_clone = result.clone();
    
    dialog.connect_response(move |dialog, response| {
        if response == ResponseType::Accept {
            *result_clone.borrow_mut() = dialog.file().and_then(|file| file.path());
        }
        dialog.close();
    });
    
    // Present the dialog and wait synchronously
    dialog.set_modal(true);
    dialog.present();
    
    // Wait until response is received
    while dialog.is_visible() {
        let ctx = glib::MainContext::default();
        let _ = ctx.iteration(true);
    }
    
    // Clone the result before returning to avoid lifetime issues
    let final_result = (*result.borrow()).clone();
    final_result
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