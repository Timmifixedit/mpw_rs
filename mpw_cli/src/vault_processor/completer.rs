use crate::vault_processor::get;
use mpw_core::vault::Vault;
use rustyline::Context;
use rustyline::completion::Completer;

pub struct CompleterImpl<'v> {
    vault: &'v Vault,
}

impl<'v> CompleterImpl<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }
}

fn get_command(line: &str) -> Option<&str> {
    line.trim_start().split_whitespace().next()
}

impl<'v> Completer for CompleterImpl<'v> {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        match get_command(line) {
            Some("get") => get::GetCompleter::new(self.vault).complete(line, pos, ctx),
            _ => Ok((0, vec![])),
        }
    }
}
