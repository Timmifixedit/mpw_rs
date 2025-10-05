mod util {
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

}
