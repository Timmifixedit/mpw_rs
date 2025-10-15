pub struct Constant<T> {
    pub value: T,
    pub as_string: &'static str,
}

#[macro_export]
macro_rules! define {
    ($name:ident : $t:ty = $val:expr) => {
        const $name: crate::utility::Constant<$t> = crate::utility::Constant {
            value: $val,
            as_string: stringify!($val),
        };
    };
}
