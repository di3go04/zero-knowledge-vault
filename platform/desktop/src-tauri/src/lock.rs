// Auto-lock timer for the desktop app.
//
// Locks the vault after a configurable period of inactivity.
// Uses a monotonic clock for accurate idle detection.

use std::time::{Duration, Instant};

pub struct AutoLock {
    timeout: Duration,
    last_activity: Instant,
}

impl AutoLock {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            last_activity: Instant::now(),
        }
    }

    pub fn record_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn is_locked(&self) -> bool {
        self.last_activity.elapsed() >= self.timeout
    }

    pub fn set_timeout(&mut self, timeout_secs: u64) {
        self.timeout = Duration::from_secs(timeout_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_auto_lock() {
        let mut lock = AutoLock::new(1);
        assert!(!lock.is_locked());
        thread::sleep(Duration::from_millis(1100));
        assert!(lock.is_locked());
        lock.record_activity();
        assert!(!lock.is_locked());
    }
}
