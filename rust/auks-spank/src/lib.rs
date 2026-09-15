#![allow(missing_docs, non_upper_case_globals)]

use std::ffi::{CStr, c_char, c_int, c_uint};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, OnceLock};

use auks_spank_sys as sys;

mod config;
mod mode;
mod spank;

use config::{PluginConfig, parse};
use mode::{OPTION_MODE, decide_for_spank, parse_option};
use spank::{Spank, log};

mod generated {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}

static CONFIG: OnceLock<Mutex<PluginConfig>> = OnceLock::new();
static OPTION_NAME: &[u8] = b"auks\0";
static OPTION_ARGINFO: &[u8] = b"yes|no|done\0";
static OPTION_USAGE: &[u8] = b"enable or disable AUKS credential forwarding\0";

#[unsafe(no_mangle)]
/// SPANK plugin name.
pub static plugin_name: [c_char; 5] = [
    b'a' as c_char,
    b'u' as c_char,
    b'k' as c_char,
    b's' as c_char,
    0,
];
#[unsafe(no_mangle)]
/// SPANK plugin type.
pub static plugin_type: [c_char; 6] = [
    b's' as c_char,
    b'p' as c_char,
    b'a' as c_char,
    b'n' as c_char,
    b'k' as c_char,
    0,
];
#[unsafe(no_mangle)]
/// Slurm version supported by this plugin.
pub static plugin_version: c_uint = generated::SLURM_VERSION_NUMBER;
#[unsafe(no_mangle)]
/// SPANK ABI version used by this plugin.
pub static spank_plugin_version: c_uint = 1;

unsafe extern "C" fn option_callback(_val: c_int, argument: *const c_char, remote: c_int) -> c_int {
    let Some(argument) = (unsafe { argument.as_ref() }) else {
        return -1;
    };
    let argument = unsafe { CStr::from_ptr(argument) }.to_string_lossy();
    let Some(mode) = parse_option(&argument) else {
        log::error(&format!("spank-auks-rs: invalid --auks value {argument}"));
        return -1;
    };
    if let Ok(mut option) = OPTION_MODE.lock() {
        *option = Some(mode);
    }
    if remote == 0 {
        unsafe { std::env::set_var("SLURM_SPANK_AUKS", argument.as_ref()) };
    }
    0
}

static mut OPTION: sys::spank_option = sys::spank_option {
    name: OPTION_NAME.as_ptr() as *mut c_char,
    arginfo: OPTION_ARGINFO.as_ptr() as *mut c_char,
    usage: OPTION_USAGE.as_ptr() as *mut c_char,
    has_arg: 2,
    val: 0,
    cb: Some(option_callback),
};

fn arguments(ac: c_int, av: *mut *mut c_char) -> Vec<String> {
    if ac <= 0 || av.is_null() {
        return Vec::new();
    }
    (0..ac as isize)
        .filter_map(|index| unsafe {
            let value = *av.offset(index);
            (!value.is_null()).then(|| CStr::from_ptr(value).to_string_lossy().into_owned())
        })
        .collect()
}

fn config() -> PluginConfig {
    CONFIG
        .get()
        .and_then(|config| config.lock().ok().map(|config| config.clone()))
        .unwrap_or_default()
}

fn init(spank: Spank, ac: c_int, av: *mut *mut c_char) -> c_int {
    let (parsed_config, unknown) = parse(&arguments(ac, av));
    for argument in unknown {
        log::debug(&format!("spank-auks-rs: unknown argument {argument}"));
    }
    CONFIG
        .get_or_init(|| Mutex::new(parsed_config.clone()))
        .lock()
        .map(|mut current| *current = parsed_config)
        .ok();
    let registration = unsafe { sys::spank_option_register(spank.into(), &raw mut OPTION) };
    if registration != sys::ESPANK_SUCCESS {
        log::error("spank-auks-rs: option registration failed");
        return registration;
    }
    log::info(&format!(
        "spank-auks-rs: init ctx={:?} remote={} mode-default={:?}",
        spank.context(),
        spank.remote(),
        config().default_mode
    ));
    0
}

fn callback_result<F: FnOnce() -> c_int + std::panic::UnwindSafe>(name: &str, body: F) -> c_int {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            log::error(&format!("spank-auks-rs: panic in {name}: {message}"));
            -1
        }
    }
}

#[unsafe(no_mangle)]
/// Initializes the plugin in each Slurm context.
///
/// # Safety
///
/// Slurm supplies a valid handle and argument array.
pub unsafe extern "C" fn slurm_spank_init(
    raw: sys::spank_t,
    ac: c_int,
    av: *mut *mut c_char,
) -> c_int {
    callback_result("init", || init(unsafe { Spank::from_raw(raw) }, ac, av))
}

#[unsafe(no_mangle)]
/// Finishes option processing.
///
/// # Safety
///
/// Slurm supplies a valid handle.
pub unsafe extern "C" fn slurm_spank_init_post_opt(
    raw: sys::spank_t,
    _ac: c_int,
    _av: *mut *mut c_char,
) -> c_int {
    callback_result("init_post_opt", || {
        let spank = unsafe { Spank::from_raw(raw) };
        log::info(&format!(
            "spank-auks-rs: init_post_opt mode={:?}",
            decide_for_spank(spank, &config())
        ));
        0
    })
}

#[unsafe(no_mangle)]
/// Initializes a remote job user.
///
/// # Safety
///
/// Slurm supplies a valid handle.
pub unsafe extern "C" fn slurm_spank_user_init(
    raw: sys::spank_t,
    _ac: c_int,
    _av: *mut *mut c_char,
) -> c_int {
    callback_result("user_init", || {
        let spank = unsafe { Spank::from_raw(raw) };
        log::info(&format!(
            "spank-auks-rs: user_init mode={:?} uid={:?} gid={:?} jobid={:?}",
            decide_for_spank(spank, &config()),
            spank.job_uid(),
            spank.job_gid(),
            spank.job_id()
        ));
        0
    })
}

#[unsafe(no_mangle)]
/// Records task completion.
///
/// # Safety
///
/// Slurm supplies a valid handle.
pub unsafe extern "C" fn slurm_spank_task_exit(
    raw: sys::spank_t,
    _ac: c_int,
    _av: *mut *mut c_char,
) -> c_int {
    callback_result("task_exit", || {
        let spank = unsafe { Spank::from_raw(raw) };
        log::info(&format!(
            "spank-auks-rs: task_exit status={:?}",
            spank.task_exit_status()
        ));
        0
    })
}

#[unsafe(no_mangle)]
/// Shuts down the plugin.
///
/// # Safety
///
/// Slurm supplies a valid handle.
pub unsafe extern "C" fn slurm_spank_exit(
    raw: sys::spank_t,
    _ac: c_int,
    _av: *mut *mut c_char,
) -> c_int {
    callback_result("exit", || {
        let spank = unsafe { Spank::from_raw(raw) };
        log::info(&format!("spank-auks-rs: exit ctx={:?}", spank.context()));
        0
    })
}
