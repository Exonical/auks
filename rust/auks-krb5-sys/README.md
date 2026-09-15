# auks-krb5-sys

Build-time bindings for the system MIT Kerberos library. The crate discovers
the library with `pkg-config krb5`, falling back to `krb5-config`, and does
not vendor Kerberos.

`krb5_get_cred_via_tkt`, `krb5_rc_initialize`, `krb5_read_message`, and
`krb5_write_message` are exported by the installed MIT library but are not
declared by the public headers, so their prototypes are maintained in
`src/manual.rs`. `krb5_rc_resolve_full` and `krb5_rc_close` were not exported
by the installed library and are intentionally not declared.
