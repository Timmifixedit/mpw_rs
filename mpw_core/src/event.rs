pub struct MessageEvent {
    callbacks: Vec<Box<dyn Fn(&str) + 'static>>,
}

impl MessageEvent {
    pub fn new() -> MessageEvent {
        MessageEvent {
            callbacks: Vec::new()
        }
    }

    pub fn subscribe(&mut self, callback: impl Fn(&str) + 'static) {
        self.callbacks.push(Box::new(callback));
    }

    pub fn trigger(&self, message: &str) {
        for c in &self.callbacks {
            c(message);
        }
    }
}