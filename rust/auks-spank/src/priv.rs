use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

/// Runs a closure with only the effective user and group changed.
pub fn as_user<T>(
    uid: libc::uid_t,
    gid: libc::gid_t,
    function: impl FnOnce() -> T,
) -> io::Result<T> {
    if unsafe { libc::syscall(libc::SYS_setresgid, -1_i64, gid as i64, -1_i64) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::syscall(libc::SYS_setresuid, -1_i64, uid as i64, -1_i64) } != 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::setegid(libc::getgid());
        }
        return Err(error);
    }
    let result = catch_unwind(AssertUnwindSafe(function));
    let uid_result = unsafe { libc::seteuid(libc::getuid()) };
    let gid_result = unsafe { libc::setegid(libc::getgid()) };
    if uid_result != 0 {
        return Err(io::Error::last_os_error());
    }
    if gid_result != 0 {
        return Err(io::Error::last_os_error());
    }
    match result {
        Ok(value) => Ok(value),
        Err(payload) => resume_unwind(payload),
    }
}
