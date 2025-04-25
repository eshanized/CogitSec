use gtk::prelude::*;
use gtk::{Box as GtkBox, Label, Grid, Orientation, Frame, ProgressBar};
use std::rc::Rc;

use crate::core::Engine;

/// Widget for displaying attack statistics
pub struct StatisticsWidget {
    /// Root widget
    root: GtkBox,
    
    /// Engine reference
    engine: Rc<Engine>,
    
    /// Status label
    status_label: Label,
    
    /// Progress bar
    progress_bar: ProgressBar,
    
    /// Attempts label
    attempts_label: Label,
    
    /// Success label
    success_label: Label,
    
    /// Time elapsed label
    time_label: Label,
    
    /// Speed label
    speed_label: Label,
}

impl StatisticsWidget {
    /// Create a new statistics widget
    pub fn new(engine: Rc<Engine>) -> Self {
        let root = GtkBox::new(Orientation::Vertical, 10);
        root.set_margin_start(10);
        root.set_margin_end(10);
        root.set_margin_top(10);
        root.set_margin_bottom(10);
        
        let header = Label::new(Some("Attack Statistics"));
        header.set_halign(gtk::Align::Start);
        header.add_css_class("title-3");
        root.append(&header);
        
        // Status section
        let status_frame = Frame::new(Some("Status"));
        let status_box = GtkBox::new(Orientation::Vertical, 5);
        status_box.set_margin_start(10);
        status_box.set_margin_end(10);
        status_box.set_margin_top(10);
        status_box.set_margin_bottom(10);
        
        let status_label = Label::new(Some("Ready"));
        let progress_bar = ProgressBar::new();
        progress_bar.set_fraction(0.0);
        progress_bar.set_show_text(true);
        
        status_box.append(&status_label);
        status_box.append(&progress_bar);
        status_frame.set_child(Some(&status_box));
        root.append(&status_frame);
        
        // Statistics grid
        let stats_frame = Frame::new(Some("Details"));
        let grid = Grid::new();
        grid.set_row_spacing(5);
        grid.set_column_spacing(10);
        grid.set_margin_start(10);
        grid.set_margin_end(10);
        grid.set_margin_top(10);
        grid.set_margin_bottom(10);
        
        // Create statistics grid
        let attempts_label = add_stat_row(&grid, 0, "Attempts:");
        let success_label = add_stat_row(&grid, 1, "Successful:");
        let time_label = add_stat_row(&grid, 2, "Time elapsed:");
        let speed_label = add_stat_row(&grid, 3, "Speed:");
        
        stats_frame.set_child(Some(&grid));
        root.append(&stats_frame);
        
        Self {
            root,
            engine,
            status_label,
            progress_bar,
            attempts_label,
            success_label,
            time_label,
            speed_label,
        }
    }
    
    /// Get the root widget
    pub fn get_widget(&self) -> GtkBox {
        self.root.clone()
    }
    
    /// Update the statistics display
    pub fn update(&self, attempts: u64, successes: u64, elapsed_seconds: u64, progress: f64) {
        self.attempts_label.set_text(&format!("{}", attempts));
        self.success_label.set_text(&format!("{}", successes));
        self.time_label.set_text(&format_time(elapsed_seconds));
        
        let speed = if elapsed_seconds > 0 {
            attempts as f64 / elapsed_seconds as f64
        } else {
            0.0
        };
        
        self.speed_label.set_text(&format!("{:.2} attempts/sec", speed));
        self.progress_bar.set_fraction(progress);
        self.progress_bar.set_text(Some(&format!("{:.1}%", progress * 100.0)));
        
        if progress >= 1.0 {
            self.status_label.set_text("Complete");
        } else if attempts > 0 {
            self.status_label.set_text("Running");
        } else {
            self.status_label.set_text("Ready");
        }
    }
}

// Helper function to add a statistic row to the grid
fn add_stat_row(grid: &Grid, row: i32, label_text: &str) -> Label {
    let title_label = Label::new(Some(label_text));
    title_label.set_halign(gtk::Align::End);
    
    let value_label = Label::new(Some("-"));
    value_label.set_halign(gtk::Align::Start);
    
    grid.attach(&title_label, 0, row, 1, 1);
    grid.attach(&value_label, 1, row, 1, 1);
    
    value_label
}

// Format time as HH:MM:SS
fn format_time(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    
    format!("{:02}:{:02}:{:02}", hours, minutes, secs)
} 