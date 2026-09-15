use std::ffi::{CString, c_int};

use auks_spank_sys as sys;

/// A borrowed SPANK handle.
#[derive(Clone, Copy)]
pub struct Spank(sys::spank_t);

impl Spank {
    /// Wraps a handle received from Slurm.
    pub unsafe fn from_raw(raw: sys::spank_t) -> Self {
        Self(raw)
    }

    /// Returns whether the plugin is running remotely.
    pub fn remote(self) -> bool {
        unsafe { sys::spank_remote(self.0) != 0 }
    }

    /// Returns the current SPANK context.
    pub fn context(self) -> sys::SpankContext {
        unsafe { sys::spank_context() }
    }

    /// Reads an environment variable from the job environment.
    pub fn getenv(self, name: &str) -> Option<String> {
        let name = CString::new(name).ok()?;
        let mut buffer = vec![0_i8; 256];
        let status = unsafe {
            sys::spank_getenv(
                self.0,
                name.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as c_int,
            )
        };
        (status == sys::ESPANK_SUCCESS).then(|| {
            unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        })
    }

    /// Sets an environment variable in the job environment.
    pub fn setenv(self, name: &str, value: &str, overwrite: bool) -> Result<(), c_int> {
        let name = CString::new(name).map_err(|_| -1)?;
        let value = CString::new(value).map_err(|_| -1)?;
        let status = unsafe {
            sys::spank_setenv(self.0, name.as_ptr(), value.as_ptr(), i32::from(overwrite))
        };
        (status == sys::ESPANK_SUCCESS).then_some(()).ok_or(status)
    }

    fn item_u32(self, item: sys::SpankItem) -> Result<u32, c_int> {
        let mut value = 0;
        let status = unsafe { sys::spank_get_item(self.0, item, &mut value as *mut u32) };
        (status == sys::ESPANK_SUCCESS)
            .then_some(value)
            .ok_or(status)
    }

    fn item_i32(self, item: sys::SpankItem) -> Result<i32, c_int> {
        let mut value = 0;
        let status = unsafe { sys::spank_get_item(self.0, item, &mut value as *mut i32) };
        (status == sys::ESPANK_SUCCESS)
            .then_some(value)
            .ok_or(status)
    }

    /// Returns the job UID.
    pub fn job_uid(self) -> Result<u32, c_int> {
        self.item_u32(sys::SpankItem::S_JOB_UID)
    }

    /// Returns the job GID.
    pub fn job_gid(self) -> Result<u32, c_int> {
        self.item_u32(sys::SpankItem::S_JOB_GID)
    }

    /// Returns the Slurm job ID.
    pub fn job_id(self) -> Result<u32, c_int> {
        self.item_u32(sys::SpankItem::S_JOB_ID)
    }

    /// Returns the number of local tasks.
    pub fn local_task_count(self) -> Result<u32, c_int> {
        self.item_u32(sys::SpankItem::S_JOB_LOCAL_TASK_COUNT)
    }

    /// Returns the task exit status.
    pub fn task_exit_status(self) -> Result<i32, c_int> {
        self.item_i32(sys::SpankItem::S_TASK_EXIT_STATUS)
    }
}

impl From<Spank> for sys::spank_t {
    fn from(value: Spank) -> Self {
        value.0
    }
}

/// Safe wrappers around Slurm's logging callbacks.
pub mod log {
    use super::*;

    fn message(value: &str) -> Option<CString> {
        CString::new(value).ok()
    }

    /// Logs an informational message.
    pub fn info(value: &str) {
        if let Some(value) = message(value) {
            unsafe { sys::slurm_info(c"%s".as_ptr(), value.as_ptr()) };
        }
    }

    /// Logs an error message.
    pub fn error(value: &str) {
        if let Some(value) = message(value) {
            unsafe { sys::slurm_error(c"%s".as_ptr(), value.as_ptr()) };
        }
    }

    /// Logs a debug message.
    pub fn debug(value: &str) {
        if let Some(value) = message(value) {
            unsafe { sys::slurm_debug(c"%s".as_ptr(), value.as_ptr()) };
        }
    }
}
