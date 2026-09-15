#![allow(
    missing_docs,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]

use std::ffi::{c_char, c_int, c_void};

/// Opaque SPANK plugin handle.
pub type spank_t = *mut c_void;

/// SPANK item identifiers.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SpankItem {
    S_JOB_UID,
    S_JOB_GID,
    S_JOB_ID,
    S_JOB_STEPID,
    S_JOB_NNODES,
    S_JOB_NODEID,
    S_JOB_LOCAL_TASK_COUNT,
    S_JOB_TOTAL_TASK_COUNT,
    S_JOB_NCPUS,
    S_JOB_ARGV,
    S_JOB_ENV,
    S_TASK_ID,
    S_TASK_GLOBAL_ID,
    S_TASK_EXIT_STATUS,
    S_TASK_PID,
    S_JOB_PID_TO_GLOBAL_ID,
    S_JOB_PID_TO_LOCAL_ID,
    S_JOB_LOCAL_TO_GLOBAL_ID,
    S_JOB_GLOBAL_TO_LOCAL_ID,
    S_JOB_SUPPLEMENTARY_GIDS,
    S_SLURM_VERSION,
    S_SLURM_VERSION_MAJOR,
    S_SLURM_VERSION_MINOR,
    S_SLURM_VERSION_MICRO,
    S_STEP_CPUS_PER_TASK,
    S_JOB_ALLOC_CORES,
    S_JOB_ALLOC_MEM,
    S_STEP_ALLOC_CORES,
    S_STEP_ALLOC_MEM,
    S_SLURM_RESTART_COUNT,
    S_JOB_ARRAY_ID,
    S_JOB_ARRAY_TASK_ID,
}

/// SPANK execution contexts.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SpankContext {
    S_CTX_ERROR,
    S_CTX_LOCAL,
    S_CTX_REMOTE,
    S_CTX_ALLOCATOR,
    S_CTX_SLURMD,
    S_CTX_JOB_SCRIPT,
}

/// SPANK option callback.
pub type spank_opt_cb_f = Option<unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int>;

/// ABI-compatible SPANK option descriptor.
#[repr(C)]
pub struct spank_option {
    pub name: *mut c_char,
    pub arginfo: *mut c_char,
    pub usage: *mut c_char,
    pub has_arg: c_int,
    pub val: c_int,
    pub cb: spank_opt_cb_f,
}

/// Successful SPANK operation.
pub const ESPANK_SUCCESS: c_int = 0;

unsafe extern "C" {
    pub fn spank_option_register(spank: spank_t, option: *mut spank_option) -> c_int;
    pub fn spank_remote(spank: spank_t) -> c_int;
    pub fn spank_context() -> SpankContext;
    pub fn spank_getenv(
        spank: spank_t,
        variable: *const c_char,
        buffer: *mut c_char,
        length: c_int,
    ) -> c_int;
    pub fn spank_setenv(
        spank: spank_t,
        variable: *const c_char,
        value: *const c_char,
        overwrite: c_int,
    ) -> c_int;
    pub fn spank_unsetenv(spank: spank_t, variable: *const c_char) -> c_int;
    pub fn spank_strerror(error: c_int) -> *const c_char;
    pub fn spank_get_item(spank: spank_t, item: SpankItem, ...) -> c_int;
    pub fn slurm_info(format: *const c_char, ...);
    pub fn slurm_error(format: *const c_char, ...);
    pub fn slurm_debug(format: *const c_char, ...);
    pub fn slurm_debug2(format: *const c_char, ...);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_layout_matches_slurm_on_x86_64() {
        assert_eq!(std::mem::size_of::<spank_option>(), 40);
    }
}
