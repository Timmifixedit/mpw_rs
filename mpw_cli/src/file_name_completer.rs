use rustyline::Context;
use rustyline::completion::Completer;

pub struct FilenameCompleter(rustyline::completion::FilenameCompleter);

impl FilenameCompleter {
    pub fn new() -> FilenameCompleter {
        FilenameCompleter(rustyline::completion::FilenameCompleter::new())
    }
}

impl Completer for FilenameCompleter {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        self.0
            .complete(line, pos, ctx)
            .map(|(s, c)| (s, c.into_iter().map(|p| p.replacement).collect()))
    }
}
