use crate::{
    krb5_address, krb5_context, krb5_creds, krb5_data, krb5_deltat, krb5_error_code, krb5_flags,
    krb5_pointer, krb5_rcache,
};

unsafe extern "C" {
    pub fn krb5_get_cred_via_tkt(
        context: krb5_context,
        in_cred: *mut krb5_creds,
        options: krb5_flags,
        addresses: *const *mut krb5_address,
        desired: *mut krb5_creds,
        output: *mut *mut krb5_creds,
    ) -> krb5_error_code;

    pub fn krb5_rc_initialize(
        context: krb5_context,
        rcache: krb5_rcache,
        lifespan: krb5_deltat,
    ) -> krb5_error_code;

    pub fn krb5_read_message(
        context: krb5_context,
        connection: krb5_pointer,
        message: *mut krb5_data,
    ) -> krb5_error_code;

    pub fn krb5_write_message(
        context: krb5_context,
        connection: krb5_pointer,
        message: *mut krb5_data,
    ) -> krb5_error_code;

}
