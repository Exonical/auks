//! Rust implementation of the AUKS Slurm SPANK plugin.

#![allow(non_upper_case_globals)]

use std::ffi::{CStr, CString, c_char, c_int, c_uint};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

use auks_client::Client;
use auks_config::parse_file;
use auks_krb5::{Context, cred_blob};
use auks_spank_sys as sys;

mod config;
mod mode;
mod r#priv;
mod spank;

use config::{PluginConfig, parse};
use mode::{OPTION_MODE, decide_for_spank, parse_option};
use r#priv::as_user;
use spank::{Spank, log};

mod generated {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}

#[derive(Default)]
struct PluginState {
    config: PluginConfig,
    credcache: Option<String>,
    file_credcache: bool,
    renewer_pid: Option<libc::pid_t>,
    exited_tasks: u32,
    synced: bool,
}

static STATE: Mutex<PluginState> = Mutex::new(PluginState {
    config: PluginConfig {
        conf_file: None,
        sync: None,
        hostcredcache: None,
        default_mode: mode::Mode::Disabled,
        spankstackcred: false,
        enforced: false,
        force_file_ccache: false,
        no_cc_switch: false,
        minimum_uid: None,
    },
    credcache: None,
    file_credcache: false,
    renewer_pid: None,
    exited_tasks: 0,
    synced: false,
});
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
    STATE
        .lock()
        .map(|state| state.config.clone())
        .unwrap_or_default()
}

fn update_config(parsed_config: PluginConfig) {
    if let Ok(mut state) = STATE.lock() {
        state.config = parsed_config;
        state.credcache = None;
        state.file_credcache = false;
        state.renewer_pid = None;
        state.exited_tasks = 0;
        state.synced = false;
    }
}

fn init(spank: Spank, ac: c_int, av: *mut *mut c_char) -> c_int {
    let (parsed_config, unknown) = parse(&arguments(ac, av));
    for argument in unknown {
        log::debug(&format!("spank-auks-rs: unknown argument {argument}"));
    }
    update_config(parsed_config);
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
    if spank.remote() {
        remote_init(spank)
    } else {
        0
    }
}

fn set_process_env_if_unset(name: &str, value: &str) {
    if std::env::var_os(name).is_none() {
        unsafe { std::env::set_var(name, value) };
    }
}

fn configured_client(config: &PluginConfig, use_host_ccache: bool) -> Result<Client, String> {
    let path = config
        .conf_file
        .clone()
        .or_else(|| std::env::var_os("AUKS_CONF").map(|value| value.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "/etc/auks/auks.conf".to_owned());
    let parsed = parse_file(&path).map_err(|error| error.to_string())?;
    let client = Client::new(parsed.client);
    Ok(
        match use_host_ccache
            .then_some(config.hostcredcache.as_deref())
            .flatten()
        {
            Some(name) => client.with_ccache(name),
            None => client,
        },
    )
}

fn local_user_init(spank: Spank) -> c_int {
    let plugin_config = config();
    match decide_for_spank(spank, &plugin_config) {
        mode::Mode::Disabled => return 0,
        mode::Mode::Done => {
            log::info("spank-auks-rs: cred forwarding already done");
            return 0;
        }
        mode::Mode::Enabled => {}
    }
    let client = match configured_client(&plugin_config, false) {
        Ok(client) => client,
        Err(error) => {
            log::error(&format!("spank-auks-rs: API init failed: {error}"));
            return -1;
        }
    };
    match client.add_cred(None) {
        Ok(()) => {
            log::info("spank-auks-rs: cred forwarding succeed");
            set_process_env_if_unset("SLURM_SPANK_AUKS", "done");
            0
        }
        Err(auks_client::Error::NoCcache(error)) if !plugin_config.enforced => {
            log::info(&format!("spank-auks-rs: cred forwarding failed: {error}"));
            log::info("spank-auks-rs: no readable credential cache: disabling AUKS support");
            set_process_env_if_unset("SLURM_SPANK_AUKS", "no");
            0
        }
        Err(error) => {
            if matches!(error, auks_client::Error::NoCcache(_)) {
                log::error(&format!(
                    "spank-auks-rs: cred forwarding failed: {error} [enforced]"
                ));
                log::info(
                    "spank-auks-rs: no readable credential cache: considering success but returning error",
                );
                set_process_env_if_unset("SLURM_SPANK_AUKS", "done");
            } else {
                log::error(&format!("spank-auks-rs: cred forwarding failed: {error}"));
            }
            -1
        }
    }
}

fn make_file_ccache(uid: u32, jobid: u32) -> Result<String, String> {
    let template = CString::new(format!("/tmp/krb5cc_{uid}_{jobid}_XXXXXX"))
        .map_err(|error| error.to_string())?;
    let mut bytes = template.into_bytes_with_nul();
    let old_mask = unsafe { libc::umask((libc::S_IRWXG | libc::S_IRWXO) as libc::mode_t) };
    let fd = unsafe { libc::mkstemp(bytes.as_mut_ptr().cast()) };
    let restore = unsafe { libc::umask(old_mask) };
    let _ = restore;
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if unsafe { libc::close(fd) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    CStr::from_bytes_until_nul(&bytes)
        .map(|value| value.to_string_lossy().into_owned())
        .map_err(|error| error.to_string())
}

fn remote_init(spank: Spank) -> c_int {
    let plugin_config = config();
    let mode = decide_for_spank(spank, &plugin_config);
    log::info(&format!("spank-auks-rs: remote_init mode={mode:?}"));
    match mode {
        mode::Mode::Disabled => {
            log::info("spank-auks-rs: mode disabled");
            return 0;
        }
        mode::Mode::Enabled | mode::Mode::Done => {}
    }
    let uid = match spank.job_uid() {
        Ok(value) => value,
        Err(error) => {
            log::error(&format!("spank-auks-rs: failed to get uid: {error}"));
            return -1;
        }
    };
    let gid = match spank.job_gid() {
        Ok(value) => value,
        Err(error) => {
            log::error(&format!("spank-auks-rs: failed to get gid: {error}"));
            return -1;
        }
    };
    let jobid = match spank.job_id() {
        Ok(value) => value,
        Err(error) => {
            log::error(&format!("spank-auks-rs: failed to get jobid: {error}"));
            return -1;
        }
    };
    let client = match configured_client(&plugin_config, true) {
        Ok(client) => client,
        Err(error) => {
            log::error(&format!("spank-auks-rs: API init failed: {error}"));
            return -1;
        }
    };
    let cred = match client.get_cred(uid) {
        Ok(cred) => cred,
        Err(error) => {
            log::error(&format!(
                "spank-auks-rs: unable to unpack auks cred from reply: {error}"
            ));
            return -1;
        }
    };
    let cred_data = cred.data.clone();
    let existing_ccache = spank.getenv("KRB5CCNAME");
    let result = as_user(uid, gid, || -> Result<Option<(String, bool)>, String> {
        if let Some(existing) = existing_ccache
            && let Ok(context) = Context::new()
            && let Ok(cache) = context.resolve_ccache(&existing)
            && cred_blob::get(&context, &cache).is_ok()
        {
            log::info(&format!("spank-auks-rs: user '{uid}' cred found in ccache"));
            return Ok(None);
        }
        let context = Context::new().map_err(|error| error.to_string())?;
        let (name, file_cache) = if plugin_config.force_file_ccache {
            (make_file_ccache(uid, jobid)?, true)
        } else {
            let cache = context
                .new_unique_ccache(None)
                .map_err(|error| error.to_string())?;
            (cache.full_name().map_err(|error| error.to_string())?, false)
        };
        log::info(&format!("spank-auks-rs: new unique ccache is {name}"));
        let cache = context
            .resolve_ccache(&name)
            .map_err(|error| error.to_string())?;
        if let Err(error) = cred_blob::store(&context, &cache, &cred_data) {
            if file_cache && let Ok(path) = CString::new(name.as_str()) {
                unsafe {
                    libc::unlink(path.as_ptr());
                }
            }
            return Err(error.to_string());
        }
        log::info(&format!(
            "spank-auks-rs: user '{uid}' cred stored in ccache {name}"
        ));
        if !file_cache && !plugin_config.no_cc_switch {
            match cache.switch_to() {
                Ok(true) => {}
                Ok(false) => log::error(&format!(
                    "spank-auks-rs: warning: ccache switch is unsupported for {name}"
                )),
                Err(error) => log::error(&format!(
                    "spank-auks-rs: warning: ccache switch to {name} failed: {error}"
                )),
            }
        }
        if plugin_config.spankstackcred {
            unsafe { std::env::set_var("KRB5CCNAME", &name) };
        }
        spank
            .setenv("KRB5CCNAME", &name, true)
            .map_err(|error| format!("unable to set KRB5CCNAME: {error}"))?;
        let config_path = plugin_config
            .conf_file
            .clone()
            .or_else(|| {
                std::env::var_os("AUKS_CONF").map(|value| value.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "/etc/auks/auks.conf".to_owned());
        if let Some(script) = parse_file(config_path)
            .ok()
            .and_then(|parsed| parsed.client.helper_script)
        {
            run_helper(&script, &name, uid, gid)?;
        }
        Ok(Some((name, file_cache)))
    });
    let result = match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            log::error(&format!(
                "spank-auks-rs: remote initialization failed: {error}"
            ));
            return -1;
        }
        Err(error) => {
            log::error(&format!(
                "spank-auks-rs: remote initialization failed: {error}"
            ));
            return -1;
        }
    };
    if let Some((name, file_cache)) = result
        && let Ok(mut state) = STATE.lock()
    {
        state.credcache = Some(name);
        state.file_credcache = file_cache;
    }
    0
}

fn run_helper(script: &str, cache: &str, uid: u32, gid: u32) -> Result<(), String> {
    let script = CString::new(script).map_err(|error| error.to_string())?;
    let cache = CString::new(cache).map_err(|error| error.to_string())?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if pid == 0 {
        unsafe {
            if libc::seteuid(libc::getuid()) != 0
                || libc::setegid(libc::getgid()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                libc::_exit(127);
            }
            libc::setenv(c"KRB5CCNAME".as_ptr(), cache.as_ptr(), 1);
            let argv = [script.as_ptr(), std::ptr::null()];
            libc::execv(script.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(format!("helper exited with status {status}"));
    }
    Ok(())
}

fn sync_files(state: &mut PluginState) {
    if state.synced {
        return;
    }
    if state
        .config
        .sync
        .as_deref()
        .is_some_and(|value| value == "yes" || value == "all")
    {
        log::info("spank-auks-rs: calling sync() to force dirty pages flush");
        unsafe { libc::sync() };
    }
    state.synced = true;
}

fn renewer_init(spank: Spank) -> c_int {
    let plugin_config = config();
    if matches!(
        decide_for_spank(spank, &plugin_config),
        mode::Mode::Disabled
    ) {
        return 0;
    }
    let cache = STATE.lock().ok().and_then(|state| state.credcache.clone());
    let cache_c = cache.as_deref().and_then(|value| CString::new(value).ok());
    let executable =
        CString::new(format!("{}/auks", env!("AUKS_BINDIR"))).expect("valid renewer executable");
    let arg_r = CString::new("-R").expect("valid argument");
    let arg_loop = CString::new("loop").expect("valid argument");
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        log::error("spank-auks-rs: unable to launch renewer process");
        return -1;
    }
    if pid == 0 {
        unsafe {
            let egid = libc::getegid();
            let euid = libc::geteuid();
            if libc::setresgid(egid, egid, egid) != 0 || libc::setresuid(euid, euid, euid) != 0 {
                libc::_exit(1);
            }
            let mut mask = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
            let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if fd >= 0 {
                libc::dup2(fd, libc::STDIN_FILENO);
                libc::dup2(fd, libc::STDOUT_FILENO);
                libc::dup2(fd, libc::STDERR_FILENO);
            }
            if let Some(cache) = cache_c.as_ref() {
                libc::setenv(c"KRB5CCNAME".as_ptr(), cache.as_ptr(), 1);
            }
            if libc::chdir(c"/".as_ptr()) != 0 {
                libc::_exit(1);
            }
            let argv = [
                executable.as_ptr(),
                arg_r.as_ptr(),
                arg_loop.as_ptr(),
                std::ptr::null(),
            ];
            libc::execv(executable.as_ptr(), argv.as_ptr());
            libc::_exit(1);
        }
    }
    if let Ok(mut state) = STATE.lock() {
        state.renewer_pid = Some(pid);
    }
    log::info(&format!(
        "spank-auks-rs: credential renewer launched (pid={pid})"
    ));
    0
}

fn task_exit(spank: Spank) -> c_int {
    let local_tasks = match spank.local_task_count() {
        Ok(value) => value,
        Err(error) => {
            log::error(&format!(
                "spank-auks-rs: failed to get local task count: {error}"
            ));
            return -1;
        }
    };
    let uid = match spank.job_uid() {
        Ok(value) => value,
        Err(error) => {
            log::error(&format!("spank-auks-rs: failed to get uid: {error}"));
            return -1;
        }
    };
    let gid = match spank.job_gid() {
        Ok(value) => value,
        Err(error) => {
            log::error(&format!("spank-auks-rs: failed to get gid: {error}"));
            return -1;
        }
    };
    let mut state = match STATE.lock() {
        Ok(state) => state,
        Err(_) => return -1,
    };
    state.exited_tasks += 1;
    let Some(pid) = state.renewer_pid else {
        return 0;
    };
    if state.exited_tasks != local_tasks {
        return 0;
    }
    log::info(&format!(
        "spank-auks-rs: all tasks exited, killing credential renewer (pid={pid})"
    ));
    let result = as_user(uid, gid, || {
        sync_files(&mut state);
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    });
    state.renewer_pid = None;
    if let Err(error) = result {
        log::error(&format!("spank-auks-rs: unable to stop renewer: {error}"));
        return -1;
    }
    0
}

fn remote_exit(spank: Spank) -> c_int {
    let (name, _file_cache) = match STATE.lock().ok().and_then(|state| {
        state
            .credcache
            .clone()
            .map(|name| (name, state.file_credcache))
    }) {
        Some(value) => value,
        None => return 0,
    };
    let uid = match spank.job_uid() {
        Ok(value) => value,
        Err(error) => {
            log::error(&format!("spank-auks-rs: failed to get uid: {error}"));
            return -1;
        }
    };
    let gid = match spank.job_gid() {
        Ok(value) => value,
        Err(error) => {
            log::error(&format!("spank-auks-rs: failed to get gid: {error}"));
            return -1;
        }
    };
    let result = as_user(uid, gid, || {
        let mut state = STATE
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?;
        sync_files(&mut state);
        let context = Context::new().map_err(|error| io::Error::other(error.to_string()))?;
        let cache = context
            .resolve_ccache(&name)
            .map_err(|error| io::Error::other(error.to_string()))?;
        cache
            .destroy()
            .map_err(|error| io::Error::other(error.to_string()))
    });
    if let Err(error) = result {
        log::error(&format!(
            "spank-auks-rs: unable to destroy ccache {name}: {error}"
        ));
        return -1;
    }
    log::info(&format!("spank-auks-rs: Destroyed ccache {name}"));
    if let Ok(mut state) = STATE.lock() {
        state.credcache = None;
        state.file_credcache = false;
    }
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
        if matches!(
            spank.context(),
            sys::SpankContext::S_CTX_LOCAL | sys::SpankContext::S_CTX_ALLOCATOR
        ) {
            local_user_init(spank)
        } else {
            0
        }
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
        if spank.remote() {
            renewer_init(spank)
        } else {
            0
        }
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
        if spank.remote() { task_exit(spank) } else { 0 }
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
        if spank.remote() {
            remote_exit(spank)
        } else {
            0
        }
    })
}
