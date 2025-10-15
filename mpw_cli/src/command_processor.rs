use rustyline::completion::Completer;
use secure_string::SecureString;

pub trait CommandProcessor: Completer<Candidate = String> {
    fn process_command(&mut self, command: &str);
    fn process_raw(&mut self, command: &str);
    fn process_secret(&mut self, secret: SecureString);
    fn require_secret(&self) -> bool;
    fn require_raw(&self) -> bool;
    fn handle_cancel(&mut self);
    fn handle_shutdown(&mut self);
}
