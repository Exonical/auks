#![allow(
    missing_docs,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod manual;

pub use manual::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_roundtrip() {
        let mut context = std::ptr::null_mut();
        let code = unsafe { krb5_init_context(&mut context) };
        assert_eq!(code, 0);
        assert!(!context.is_null());
        unsafe { krb5_free_context(context) };
    }
}
