use gtk::prelude::*;
use gtk::{Box as GtkBox, Label, Grid, Orientation, Frame, ProgressBar};
use std::rc::Rc;
use crate::core::Engine;
use crate::core::attack::{AttackResult, Protocol};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::cell::RefCell;

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

/// Statistics view for displaying attack results
#[derive(Clone)]
pub struct StatisticsView {
    /// Engine instance
    engine: Arc<Mutex<Engine>>,
    
    /// Main widget
    widget: gtk::Box,
    
    /// Success rate label
    success_rate_label: gtk::Label,
    
    /// Protocol stats labels
    protocol_stats: HashMap<Protocol, gtk::Label>,
    
    /// Target stats tree view
    target_tree: gtk::TreeView,
    
    /// Target tree store
    target_store: gtk::TreeStore,
}

impl StatisticsView {
    /// Create a new statistics view
    pub fn new(engine: Arc<Mutex<Engine>>) -> Self {
        // Create main container
        let widget = gtk::Box::new(gtk::Orientation::Vertical, 10);
        widget.set_margin_start(10);
        widget.set_margin_end(10);
        widget.set_margin_top(10);
        widget.set_margin_bottom(10);
        
        // Create header
        let header_label = gtk::Label::new(Some("Attack Statistics"));
        header_label.get_style_context().add_class("title-1");
        widget.append(&header_label);
        
        // Create summary section
        let summary_frame = gtk::Frame::new(Some("Summary"));
        let summary_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        summary_box.set_margin_start(10);
        summary_box.set_margin_end(10);
        summary_box.set_margin_top(10);
        summary_box.set_margin_bottom(10);
        summary_frame.set_child(Some(&summary_box));
        
        // Create success rate widget
        let success_rate_label = gtk::Label::new(Some("Success Rate: 0% (0/0)"));
        success_rate_label.set_halign(gtk::Align::Start);
        summary_box.append(&success_rate_label);
        
        // Create protocol stats section
        let protocol_frame = gtk::Frame::new(Some("Protocol Statistics"));
        let protocol_grid = gtk::Grid::new();
        protocol_grid.set_row_spacing(5);
        protocol_grid.set_column_spacing(10);
        protocol_grid.set_margin_start(10);
        protocol_grid.set_margin_end(10);
        protocol_grid.set_margin_top(10);
        protocol_grid.set_margin_bottom(10);
        protocol_frame.set_child(Some(&protocol_grid));
        
        // Create labels for each protocol
        let mut protocol_stats = HashMap::new();
        let protocols = [
            Protocol::SSH,
            Protocol::FTP,
            Protocol::HTTP,
            Protocol::HTTPS,
            Protocol::SMTP,
            Protocol::SMTPS,
            Protocol::MySQL,
            Protocol::PostgreSQL,
            Protocol::SMB,
        ];
        
        for (i, protocol) in protocols.iter().enumerate() {
            let row = i / 3;
            let col = i % 3;
            
            let protocol_label = gtk::Label::new(Some(&format!("{}:", protocol)));
            protocol_label.set_halign(gtk::Align::Start);
            protocol_grid.attach(&protocol_label, col * 2, row, 1, 1);
            
            let stats_label = gtk::Label::new(Some("0/0 (0%)"));
            stats_label.set_halign(gtk::Align::Start);
            protocol_grid.attach(&stats_label, col * 2 + 1, row, 1, 1);
            
            protocol_stats.insert(*protocol, stats_label);
        }
        
        // Create target results section
        let target_frame = gtk::Frame::new(Some("Target Results"));
        let target_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        target_box.set_margin_start(10);
        target_box.set_margin_end(10);
        target_box.set_margin_top(10);
        target_box.set_margin_bottom(10);
        target_frame.set_child(Some(&target_box));
        
        // Create tree view for target results
        let scroll = gtk::ScrolledWindow::new();
        scroll.set_hexpand(true);
        scroll.set_vexpand(true);
        scroll.set_min_content_height(300);
        
        // Create tree store for targets
        let target_store = gtk::TreeStore::new(&[
            glib::Type::STRING,  // Target
            glib::Type::STRING,  // Protocol
            glib::Type::U32,     // Port
            glib::Type::U32,     // Attempts
            glib::Type::U32,     // Successes
            glib::Type::U32,     // Failures
            glib::Type::DOUBLE,  // Success Rate
        ]);
        
        let target_tree = gtk::TreeView::with_model(&target_store);
        target_tree.set_headers_visible(true);
        
        // Add columns
        let add_column = |tree: &gtk::TreeView, title: &str, column_id: u32| {
            let column = gtk::TreeViewColumn::new();
            column.set_title(title);
            
            let cell = gtk::CellRendererText::new();
            column.pack_start(&cell, true);
            column.add_attribute(&cell, "text", column_id as i32);
            
            tree.append_column(&column);
        };
        
        add_column(&target_tree, "Target", 0);
        add_column(&target_tree, "Protocol", 1);
        add_column(&target_tree, "Port", 2);
        add_column(&target_tree, "Attempts", 3);
        add_column(&target_tree, "Successes", 4);
        add_column(&target_tree, "Failures", 5);
        add_column(&target_tree, "Success Rate (%)", 6);
        
        scroll.set_child(Some(&target_tree));
        target_box.append(&scroll);
        
        // Add all frames to the main widget
        widget.append(&summary_frame);
        widget.append(&protocol_frame);
        widget.append(&target_frame);
        
        Self {
            engine,
            widget,
            success_rate_label,
            protocol_stats,
            target_tree,
            target_store,
        }
    }
    
    /// Get the main widget
    pub fn widget(&self) -> &gtk::Box {
        &self.widget
    }
    
    /// Update statistics with current results
    pub fn update_statistics(&self, results: &[AttackResult]) {
        if results.is_empty() {
            return;
        }
        
        // Calculate overall success rate
        let total = results.len();
        let successful = results.iter().filter(|r| r.success).count();
        let success_rate = if total > 0 {
            (successful as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        
        self.success_rate_label.set_text(&format!(
            "Success Rate: {:.1}% ({}/{})",
            success_rate,
            successful,
            total
        ));
        
        // Calculate protocol-specific stats
        let mut protocol_counts: HashMap<Protocol, (usize, usize)> = HashMap::new();
        
        for result in results {
            let (total, success) = protocol_counts.entry(result.protocol).or_insert((0, 0));
            *total += 1;
            if result.success {
                *success += 1;
            }
        }
        
        for (protocol, (total, success)) in protocol_counts {
            if let Some(label) = self.protocol_stats.get(&protocol) {
                let rate = if total > 0 {
                    (success as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                
                label.set_text(&format!("{}/{} ({:.1}%)", success, total, rate));
            }
        }
        
        // Group results by target
        let mut target_stats: HashMap<(String, u16, Protocol), (usize, usize)> = HashMap::new();
        
        for result in results {
            let key = (result.target.clone(), result.port, result.protocol);
            let (total, success) = target_stats.entry(key).or_insert((0, 0));
            *total += 1;
            if result.success {
                *success += 1;
            }
        }
        
        // Clear and update tree
        self.target_store.clear();
        
        for ((target, port, protocol), (attempts, successes)) in target_stats {
            let failures = attempts - successes;
            let success_rate = if attempts > 0 {
                (successes as f64 / attempts as f64) * 100.0
            } else {
                0.0
            };
            
            self.target_store.insert_with_values(
                None,
                None,
                &[
                    (0, &target),
                    (1, &format!("{}", protocol)),
                    (2, &(port as u32)),
                    (3, &(attempts as u32)),
                    (4, &(successes as u32)),
                    (5, &(failures as u32)),
                    (6, &success_rate),
                ],
            );
        }
    }
} 