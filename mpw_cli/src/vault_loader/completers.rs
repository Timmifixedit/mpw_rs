use crate::vault_loader::{add, load, mv, remove};
use mpw_core::path_manager::PathManager;
use rustyline::Context;
use rustyline::completion::Completer;

pub struct CompleterImpl<'e> {
    entries: &'e PathManager,
}

impl<'e> CompleterImpl<'e> {
    pub fn new(entries: &'e PathManager) -> Self {
        Self { entries }
    }
}

fn get_command(line: &str) -> Option<&str> {
    line.trim_start().split_whitespace().next()
}

impl<'e> Completer for CompleterImpl<'e> {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        match get_command(line) {
            Some("add") => add::AddCompleter::new(self.entries).complete(line, pos, ctx),
            Some("load") => load::LoadCompleter::new(self.entries).complete(line, pos, ctx),
            Some("rm") => remove::RemoveCompleter::new(self.entries).complete(line, pos, ctx),
            Some("mv") => mv::MoveCompleter::new(self.entries).complete(line, pos, ctx),
            _ => Ok((0, vec![line.to_string()])),
        }
    }
}
