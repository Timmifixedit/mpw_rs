use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

pub struct CancellationToken {
    cancel: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        CancellationToken { cancel: Arc::new(AtomicBool::new(false)) }
    }

    pub fn launch<F: FnOnce() + Send + 'static>(f: F, delay: Duration) -> CancellationToken {
        let ret = CancellationToken {
            cancel: Arc::from(AtomicBool::new(false)),
        };

        let token = ret.cancel.clone();
        std::thread::spawn(move || {
            println!("Timer launched");
            std::thread::sleep(delay);
            if !token.load(Relaxed) {
                println!("Timer expired");
                f()
            }
        });
        ret
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Relaxed);
    }
}
