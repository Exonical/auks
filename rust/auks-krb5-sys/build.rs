#![allow(missing_docs)]

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn dependency_flags() -> Vec<String> {
    for (program, args) in [
        ("pkg-config", &["--cflags", "--libs", "krb5"][..]),
        ("krb5-config", &["--cflags", "--libs"][..]),
    ] {
        if let Ok(output) = Command::new(program).args(args).output()
            && output.status.success()
        {
            return String::from_utf8(output.stdout)
                .expect("Kerberos dependency flags are not UTF-8")
                .split_whitespace()
                .map(str::to_owned)
                .collect();
        }
    }
    panic!("unable to locate MIT Kerberos with pkg-config or krb5-config");
}

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=src/manual.rs");

    let flags = dependency_flags();
    let mut index = 0;
    while index < flags.len() {
        let flag = &flags[index];
        match flag.as_str() {
            "-I" | "-isystem" => {
                index += 1;
                println!("cargo:rustc-env=AUKS_KRB5_INCLUDE={}", flags[index]);
            }
            _ if flag.starts_with("-I") => {
                println!("cargo:rustc-env=AUKS_KRB5_INCLUDE={}", &flag[2..]);
            }
            "-L" => {
                index += 1;
                println!("cargo:rustc-link-search=native={}", flags[index]);
            }
            _ if flag.starts_with("-L") => {
                println!("cargo:rustc-link-search=native={}", &flag[2..]);
            }
            _ if flag.starts_with("-l") => {
                println!("cargo:rustc-link-lib={}", &flag[2..]);
            }
            _ if flag.starts_with("-Wl,") || flag.starts_with("-f") => {}
            _ => {}
        }
        index += 1;
    }

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function(
            "krb5_(init_context|free_context|parse_name|unparse_name|unparse_name_ext|build_principal|copy_principal|free_principal|cc_default|cc_default_name|cc_resolve|cc_new_unique|cc_initialize|cc_store_cred|cc_get_principal|cc_get_full_name|cc_get_type|cc_get_name|cc_start_seq_get|cc_next_cred|cc_end_seq_get|cc_close|cc_destroy|cc_switch|cc_support_switch|copy_creds|free_creds|free_cred_contents|free_tgt_creds|auth_con_init|auth_con_free|auth_con_setflags|auth_con_setaddrs|auth_con_setrcache|auth_con_getauthenticator|free_authenticator|mk_ncred|mk_1cred|rd_cred|fwd_tgt_creds|get_credentials|get_cred_via_tkt|sendauth|recvauth|mk_priv|rd_priv|read_message|write_message|kt_default|kt_resolve|kt_close|rc_initialize|rc_resolve_full|rc_close|aname_to_localname|get_error_message|free_error_message|free_data|free_data_contents|free_string|timeofday)",
        )
        .allowlist_type("krb5_.*")
        .allowlist_var(
            "(ADDRTYPE_INET|KRB5_AUTH_CONTEXT_.*|AP_OPTS_.*|KDC_OPT_.*|KRB5_TC_.*|KRB5_NT_.*|KRB5_GC_.*|KRB5_FCC_NOFILE|KRB5_CC_.*|KRB5KRB_.*|KRB5_RC_.*|KRB5_NO_TKT_SUPPLIED|KRB5_TGS_NAME.*)",
        )
        .derive_default(true)
        .derive_debug(true)
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    if let Ok(include_path) = env::var("AUKS_KRB5_INCLUDE") {
        builder = builder.clang_arg(format!("-isystem{include_path}"));
    }

    let bindings = builder
        .generate()
        .expect("failed to generate MIT Kerberos bindings");
    let out_path = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is unset"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write MIT Kerberos bindings");
}
