use secure_string::SecureString;

pub trait CommandProcessor {
    fn process_command(&mut self, command: &str) -> String;
    fn process_raw(&mut self, command: &str) -> String;
    fn process_secret(&mut self, secret: SecureString) -> String;
    fn require_secret(&self) -> bool;
    fn require_raw(&self) -> bool;
    fn handle_cancel(&mut self);
    fn help(&self) -> String;
}