use crate::file_name_completer::FilenameCompleter;
use crate::print_if_error;
use crate::util::current_arg_idx;
use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::PathManager;
use rustyline::Context;
use rustyline::completion::Completer;
use std::path::{Path, PathBuf};

pub struct AddCompleter {
    file_completer: FilenameCompleter,
}

impl AddCompleter {
    pub fn new() -> Self {
        Self {
            file_completer: FilenameCompleter::new(),
        }
    }
}

impl Completer for AddCompleter {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        if current_arg_idx(pos, line) < 2 {
            return Ok((0, vec![]));
        }

        self.file_completer
            .complete(line, pos, ctx)
            .map(|(size, candidates)| {
                (
                    size,
                    candidates
                        .into_iter()
                        .filter(|c| Path::new(c).is_dir())
                        .collect::<Vec<_>>(),
                )
            })
    }
}

#[derive(Debug, Args)]
#[command(about = "add a new or existing vault", long_about = None)]
pub struct Add {
    #[arg(required = true)]
    name: String,
    #[arg(required = false, default_value = None)]
    path: Option<PathBuf>,
    #[arg(short, long, default_value = "false")]
    default: bool,
    #[arg(short, long, default_value = "false")]
    overwrite: bool,
}

impl Handler for Add {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        if self.overwrite {
            print_if_error!({
                if let Some(path) = self.path {
                    entries.update(&self.name, path)?;
                }
                entries.update_default(&self.name, self.default)
            });
        } else {
            if let Some(path) = self.path {
                if !path.is_dir() {
                    println!("Path is not a directory");
                } else {
                    print_if_error!(entries.add(self.name, path, self.default));
                }
            } else {
                println!("Please specify a path to add.");
            };
        }

        (LoaderState::Select, Followup::None)
    }
}
