pub struct Constant<T> {
    pub value: T,
    pub name: &'static str,
    pub as_string: &'static str,
}

#[macro_export]
macro_rules! define {
    ($name:ident : $t:ty = $val:expr) => {
        const $name: Constant<$t> = Constant {
            value: $val,
            name: stringify!($name),
            as_string: stringify!($val),
        };
    };
}
