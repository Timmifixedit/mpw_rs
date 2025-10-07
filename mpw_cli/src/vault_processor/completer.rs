use crate::vault_processor::{add, enc_dec, get, mv, remove, secure_release};
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
            Some("add") => add::AddCompleter::new(self.vault).complete(line, pos, ctx),
            Some("mv") => mv::MoveCompleter::new(self.vault).complete(line, pos, ctx),
            Some("rm") => remove::RemoveCompleter::new(self.vault).complete(line, pos, ctx),
            Some("rel") => {
                secure_release::ReleaseCompleter::new(self.vault).complete(line, pos, ctx)
            }
            Some("enc") => {enc_dec::EncDecCompleter::new(self.vault).complete(line, pos, ctx)}
            Some("dec")  => {enc_dec::EncDecCompleter::new(self.vault).complete(line, pos, ctx)}
            _ => Ok((0, vec![])),
        }
    }
}
