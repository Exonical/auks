#![allow(missing_docs)]

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=SLURM_PREFIX");
    println!("cargo:rerun-if-env-changed=AUKS_BINDIR");
    println!("cargo:rerun-if-env-changed=AUKS_SYSCONFDIR");
    let bindir = env::var("AUKS_BINDIR").unwrap_or_else(|_| "/usr/local/bin".to_owned());
    println!("cargo:rustc-env=AUKS_BINDIR={bindir}");
    let sysconfdir = env::var("AUKS_SYSCONFDIR").unwrap_or_else(|_| "/etc".to_owned());
    println!("cargo:rustc-env=AUKS_SYSCONFDIR={sysconfdir}");
    let prefix = env::var("SLURM_PREFIX").unwrap_or_else(|_| "/usr".to_owned());
    let header = PathBuf::from(&prefix).join("include/slurm/slurm_version.h");
    let text = fs::read_to_string(&header).unwrap_or_else(|error| {
        panic!(
            "unable to read Slurm version header {}: {error}",
            header.display()
        )
    });
    let value = text
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() == Some("#define") && fields.next() == Some("SLURM_VERSION_NUMBER") {
                fields.next().map(str::to_owned)
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("SLURM_VERSION_NUMBER is missing from {}", header.display()));
    let numeric = u32::from_str_radix(value.trim_start_matches("0x"), 16)
        .unwrap_or_else(|error| panic!("invalid SLURM_VERSION_NUMBER {value}: {error}"));
    println!("cargo:rustc-env=SLURM_VERSION_NUMBER={numeric}");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is unset"));
    fs::write(
        out.join("version.rs"),
        format!("pub const SLURM_VERSION_NUMBER: u32 = {numeric};\n"),
    )
    .expect("unable to write generated Slurm version");
}
