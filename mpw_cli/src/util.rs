use crate::util::detail::State;
use std::cmp::min;

#[macro_export]
macro_rules! print_if_error {
    ($expr:expr) => {
        print_if_error!($expr, "");
    };
    ($expr:expr, $msg:expr) => {
        let run = || -> Result<_, _> { $expr };
        if let Err(e) = run() {
            println!("{}{e}", $msg);
        }
    };
}

mod detail {
    pub enum State {
        Empty,
        InWord,
        InOpt,
    }
}

pub fn current_arg_idx(pos: usize, line: &str) -> usize {
    let trimmed = line[..min(pos, line.len())].trim_start();
    let mut res = 0usize;
    let mut state = State::Empty;
    for c in trimmed.chars() {
        match state {
            State::Empty => {
                if c.is_alphanumeric() {
                    state = State::InWord
                } else if c == '-' {
                    state = State::InOpt
                }
            }
            State::InWord => {
                if c.is_whitespace() {
                    state = State::Empty;
                    res += 1;
                }
            }
            State::InOpt => {
                if c.is_whitespace() {
                    state = State::Empty;
                }
            }
        }
    }

    res
}

mod test {
    use crate::util::current_arg_idx;

    #[test]
    fn test_get_arg_index() {
        assert_eq!(current_arg_idx(7, " test one two"), 1);
        assert_eq!(current_arg_idx(3, " test one two"), 0);
        assert_eq!(current_arg_idx(14, " bla -s 3 --blabla 15"), 2);
        assert_eq!(current_arg_idx(100, " bla -s 30 move --blabla 15"), 3);
        assert_eq!(current_arg_idx(100, ""), 0);
        assert_eq!(current_arg_idx(4, " -t 4"), 0);
        assert_eq!(current_arg_idx(10, "abc -t def "), 1);
        assert_eq!(current_arg_idx(11, "abc -t def  "), 2);
    }
}
