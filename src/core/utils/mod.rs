pub mod network;
pub mod password;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Tracks statistics for an attack
pub struct AttackStats {
    /// Number of attempts made
    attempts: AtomicUsize,
    
    /// Number of successful attempts
    successes: AtomicUsize,
    
    /// Number of failed attempts
    failures: AtomicUsize,
    
    /// Start time of the attack
    start_time: Instant,
    
    /// Whether the attack is paused
    is_paused: AtomicBool,
    
    /// Accumulated duration when paused
    paused_duration: Arc<std::sync::Mutex<Duration>>,
    
    /// Time when the attack was last paused
    pause_time: Arc<std::sync::Mutex<Option<Instant>>>,
}

impl AttackStats {
    /// Create a new attack statistics tracker
    pub fn new() -> Self {
        Self {
            attempts: AtomicUsize::new(0),
            successes: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            start_time: Instant::now(),
            is_paused: AtomicBool::new(false),
            paused_duration: Arc::new(std::sync::Mutex::new(Duration::from_secs(0))),
            pause_time: Arc::new(std::sync::Mutex::new(None)),
        }
    }
    
    /// Record an attempt
    pub fn record_attempt(&self, success: bool) {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        
        if success {
            self.successes.fetch_add(1, Ordering::SeqCst);
        } else {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
    }
    
    /// Pause the attack
    pub fn pause(&self) {
        if !self.is_paused.load(Ordering::SeqCst) {
            self.is_paused.store(true, Ordering::SeqCst);
            let mut pause_time = self.pause_time.lock().unwrap();
            *pause_time = Some(Instant::now());
        }
    }
    
    /// Resume the attack
    pub fn resume(&self) {
        if self.is_paused.load(Ordering::SeqCst) {
            self.is_paused.store(false, Ordering::SeqCst);
            
            let mut pause_time = self.pause_time.lock().unwrap();
            if let Some(time) = *pause_time {
                let duration = time.elapsed();
                let mut paused_duration = self.paused_duration.lock().unwrap();
                *paused_duration += duration;
            }
            
            *pause_time = None;
        }
    }
    
    /// Get the elapsed time
    pub fn elapsed(&self) -> Duration {
        let mut total = self.start_time.elapsed();
        
        // Subtract paused duration
        let paused_duration = *self.paused_duration.lock().unwrap();
        total -= paused_duration;
        
        // Subtract current pause if paused
        if self.is_paused.load(Ordering::SeqCst) {
            let pause_time = self.pause_time.lock().unwrap();
            if let Some(time) = *pause_time {
                total -= time.elapsed();
            }
        }
        
        total
    }
    
    /// Get the number of attempts
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
    
    /// Get the number of successes
    pub fn successes(&self) -> usize {
        self.successes.load(Ordering::SeqCst)
    }
    
    /// Get the number of failures
    pub fn failures(&self) -> usize {
        self.failures.load(Ordering::SeqCst)
    }
    
    /// Get whether the attack is paused
    pub fn is_paused(&self) -> bool {
        self.is_paused.load(Ordering::SeqCst)
    }
    
    /// Reset the statistics
    pub fn reset(&self) {
        self.attempts.store(0, Ordering::SeqCst);
        self.successes.store(0, Ordering::SeqCst);
        self.failures.store(0, Ordering::SeqCst);
        
        let mut paused_duration = self.paused_duration.lock().unwrap();
        *paused_duration = Duration::from_secs(0);
        
        let mut pause_time = self.pause_time.lock().unwrap();
        *pause_time = None;
        
        self.is_paused.store(false, Ordering::SeqCst);
    }
} 