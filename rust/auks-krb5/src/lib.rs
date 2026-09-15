//! Safe MIT Kerberos wrappers used by the staged AUKS migration.
//!
//! Authenticated streams, renewal, address deletion, and cross-realm buffer
//! operations remain Phase 2/3 work.

use std::ffi::{CStr, CString, NulError};
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::ptr;
use std::slice;

use auks_krb5_sys as sys;
use thiserror::Error;

/// A failure returned by MIT Kerberos.
#[derive(Debug, Error)]
#[error("{op} failed ({code}): {message}")]
pub struct Error {
    /// MIT Kerberos error code, or `-1` for a non-Kerberos input error.
    pub code: i32,
    /// Human-readable MIT Kerberos error text.
    pub message: String,
    /// Operation that failed.
    pub op: &'static str,
}

impl Error {
    fn input(op: &'static str, error: impl Into<String>) -> Self {
        Self {
            code: -1,
            message: error.into(),
            op,
        }
    }

    /// Returns whether this error originated in MIT Kerberos.
    pub fn is_krb5(&self) -> bool {
        self.code != -1
    }
}

/// The result type returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Enables sequence numbers on an authentication context.
pub const AUTH_CONTEXT_DO_SEQUENCE: u32 = sys::KRB5_AUTH_CONTEXT_DO_SEQUENCE;

fn c_string(value: &str, op: &'static str) -> Result<CString> {
    CString::new(value).map_err(|error: NulError| Error::input(op, error.to_string()))
}

fn check(context: sys::krb5_context, code: sys::krb5_error_code, op: &'static str) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    let message = unsafe {
        let ptr = sys::krb5_get_error_message(context, code);
        if ptr.is_null() {
            format!("Kerberos error {code}")
        } else {
            let text = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            sys::krb5_free_error_message(context, ptr);
            text
        }
    };
    Err(Error { code, message, op })
}

fn bytes(data: &sys::krb5_data) -> &[u8] {
    if data.data.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data.data.cast::<u8>(), data.length as usize) }
    }
}

struct DataContents<'c> {
    context: &'c Context,
    data: sys::krb5_data,
}

impl<'c> DataContents<'c> {
    fn new(context: &'c Context) -> Self {
        Self {
            context,
            data: sys::krb5_data::default(),
        }
    }
}

impl Drop for DataContents<'_> {
    fn drop(&mut self) {
        unsafe {
            sys::krb5_free_data_contents(self.context.raw(), &mut self.data);
        }
    }
}

/// An owned MIT Kerberos context.
pub struct Context {
    raw: sys::krb5_context,
}

impl Context {
    /// Initializes a Kerberos context.
    pub fn new() -> Result<Self> {
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                ptr::null_mut(),
                sys::krb5_init_context(&mut raw),
                "krb5_init_context",
            )?;
        }
        Ok(Self { raw })
    }

    fn raw(&self) -> sys::krb5_context {
        self.raw
    }

    /// Parses a principal name.
    pub fn parse_name<'c>(&'c self, name: &str) -> Result<Principal<'c>> {
        let name = c_string(name, "krb5_parse_name")?;
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                self.raw,
                sys::krb5_parse_name(self.raw, name.as_ptr(), &mut raw),
                "krb5_parse_name",
            )?;
        }
        Ok(Principal { context: self, raw })
    }

    /// Opens the default credential cache.
    pub fn default_ccache<'c>(&'c self) -> Result<Ccache<'c>> {
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                self.raw,
                sys::krb5_cc_default(self.raw, &mut raw),
                "krb5_cc_default",
            )?;
        }
        Ok(Ccache { context: self, raw })
    }

    /// Resolves a credential cache by full name.
    pub fn resolve_ccache<'c>(&'c self, name: &str) -> Result<Ccache<'c>> {
        let name = c_string(name, "krb5_cc_resolve")?;
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                self.raw,
                sys::krb5_cc_resolve(self.raw, name.as_ptr(), &mut raw),
                "krb5_cc_resolve",
            )?;
        }
        Ok(Ccache { context: self, raw })
    }

    /// Creates a unique credential cache, optionally selecting its type.
    pub fn new_unique_ccache<'c>(&'c self, cache_type: Option<&str>) -> Result<Ccache<'c>> {
        let default_type;
        let cache_type = match cache_type {
            Some(value) => Some(value),
            None => {
                let default_cache = self.default_ccache()?;
                default_type = default_cache.type_name().to_owned();
                Some(default_type.as_str())
            }
        };
        let cache_type = cache_type.map(|value| c_string(value, "krb5_cc_new_unique"));
        let cache_type = cache_type.transpose()?;
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                self.raw,
                sys::krb5_cc_new_unique(
                    self.raw,
                    cache_type
                        .as_ref()
                        .map_or(ptr::null(), |value| value.as_ptr()),
                    ptr::null(),
                    &mut raw,
                ),
                "krb5_cc_new_unique",
            )?;
        }
        Ok(Ccache { context: self, raw })
    }

    /// Creates an authentication context.
    pub fn auth_context<'c>(&'c self) -> Result<AuthContext<'c>> {
        AuthContext::new(self)
    }

    /// Converts a principal to the local operating-system account name.
    pub fn aname_to_localname(&self, principal: &Principal<'_>) -> Result<String> {
        aname_to_localname(self, principal)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { sys::krb5_free_context(self.raw) };
        }
    }
}

/// An owned Kerberos principal tied to its context.
pub struct Principal<'c> {
    context: &'c Context,
    raw: sys::krb5_principal,
}

impl<'c> Principal<'c> {
    /// Returns the MIT Kerberos principal name.
    pub fn unparse(&self) -> Result<String> {
        let mut output = ptr::null_mut();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_unparse_name(self.context.raw(), self.raw, &mut output),
                "krb5_unparse_name",
            )?;
            let value = CStr::from_ptr(output).to_string_lossy().into_owned();
            sys::krb5_free_string(self.context.raw(), output);
            Ok(value)
        }
    }

    /// Returns the principal realm.
    pub fn realm(&self) -> Result<String> {
        unsafe {
            let realm = &(*self.raw).realm;
            Ok(String::from_utf8_lossy(bytes(realm)).into_owned())
        }
    }

    /// Copies this principal with `krb5_copy_principal`.
    pub fn copy(&self) -> Result<Self> {
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_copy_principal(self.context.raw(), self.raw, &mut raw),
                "krb5_copy_principal",
            )?;
        }
        Ok(Self {
            context: self.context,
            raw,
        })
    }
}

impl Drop for Principal<'_> {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { sys::krb5_free_principal(self.context.raw(), self.raw) };
        }
    }
}

/// An owned Kerberos credential cache.
pub struct Ccache<'c> {
    context: &'c Context,
    raw: sys::krb5_ccache,
}

impl<'c> Ccache<'c> {
    /// Returns the full cache name.
    pub fn full_name(&self) -> Result<String> {
        let mut output = ptr::null_mut();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_cc_get_full_name(self.context.raw(), self.raw, &mut output),
                "krb5_cc_get_full_name",
            )?;
            let value = CStr::from_ptr(output).to_string_lossy().into_owned();
            sys::krb5_free_string(self.context.raw(), output);
            Ok(value)
        }
    }

    /// Returns the cache type.
    pub fn type_name(&self) -> &str {
        unsafe {
            CStr::from_ptr(sys::krb5_cc_get_type(self.context.raw(), self.raw))
                .to_str()
                .unwrap_or("")
        }
    }

    /// Returns the cache principal.
    pub fn principal(&self) -> Result<Principal<'c>> {
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_cc_get_principal(self.context.raw(), self.raw, &mut raw),
                "krb5_cc_get_principal",
            )?;
        }
        Ok(Principal {
            context: self.context,
            raw,
        })
    }

    /// Initializes the cache for a principal.
    pub fn initialize(&self, principal: &Principal<'_>) -> Result<()> {
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_cc_initialize(self.context.raw(), self.raw, principal.raw),
                "krb5_cc_initialize",
            )
        }
    }

    /// Stores a credential in the cache.
    pub fn store(&self, credential: &Creds<'_>) -> Result<()> {
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_cc_store_cred(self.context.raw(), self.raw, credential.raw()),
                "krb5_cc_store_cred",
            )
        }
    }

    /// Destroys this cache.
    pub fn destroy(mut self) -> Result<()> {
        let code = unsafe { sys::krb5_cc_destroy(self.context.raw(), self.raw) };
        if code == 0 {
            self.raw = ptr::null_mut();
            Ok(())
        } else {
            check(self.context.raw(), code, "krb5_cc_destroy")
        }
    }

    /// Switches the default cache when the cache type supports collections.
    pub fn switch_to(&self) -> Result<bool> {
        let cache_type = c_string(self.type_name(), "krb5_cc_support_switch")?;
        let supported =
            unsafe { sys::krb5_cc_support_switch(self.context.raw(), cache_type.as_ptr()) != 0 };
        if !supported {
            return Ok(false);
        }
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_cc_switch(self.context.raw(), self.raw),
                "krb5_cc_switch",
            )?;
        }
        Ok(true)
    }

    /// Starts iterating credentials in this cache.
    pub fn creds(&self) -> Result<CredsIter<'c>> {
        let mut cursor = ptr::null_mut();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_cc_start_seq_get(self.context.raw(), self.raw, &mut cursor),
                "krb5_cc_start_seq_get",
            )?;
        }
        Ok(CredsIter {
            context: self.context,
            cache: self.raw,
            cursor,
            finished: false,
        })
    }
}

impl Drop for Ccache<'_> {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                let _ = sys::krb5_cc_close(self.context.raw(), self.raw);
            }
        }
    }
}

/// Ticket lifetime fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketTimes {
    /// Time at which the ticket was authenticated.
    pub authtime: i64,
    /// Ticket start time.
    pub start: i64,
    /// Ticket expiration time.
    pub end: i64,
    /// Latest time at which the ticket may be renewed.
    pub renew_till: i64,
}

/// A credential copied from a credential cache.
pub struct Creds<'c> {
    context: &'c Context,
    value: Box<sys::krb5_creds>,
}

impl Creds<'_> {
    fn raw(&self) -> *mut sys::krb5_creds {
        self.value.as_ref() as *const _ as *mut _
    }

    /// Returns the client principal.
    pub fn client(&self) -> Result<Principal<'_>> {
        let source = unsafe { self.value.client.as_ref() }.ok_or_else(|| {
            Error::input("krb5_creds.client", "credential has no client principal")
        })?;
        let _ = source;
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_copy_principal(self.context.raw(), self.value.client, &mut raw),
                "krb5_copy_principal",
            )?;
        }
        Ok(Principal {
            context: self.context,
            raw,
        })
    }

    /// Returns the server principal.
    pub fn server(&self) -> Result<Principal<'_>> {
        if self.value.server.is_null() {
            return Err(Error::input(
                "krb5_creds.server",
                "credential has no server principal",
            ));
        }
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_copy_principal(self.context.raw(), self.value.server, &mut raw),
                "krb5_copy_principal",
            )?;
        }
        Ok(Principal {
            context: self.context,
            raw,
        })
    }

    /// Returns ticket lifetime fields.
    pub fn times(&self) -> TicketTimes {
        let value = self.value.times;
        TicketTimes {
            authtime: value.authtime.into(),
            start: value.starttime.into(),
            end: value.endtime.into(),
            renew_till: value.renew_till.into(),
        }
    }

    /// Returns ticket flags.
    pub fn flags(&self) -> u32 {
        self.value.ticket_flags as u32
    }

    /// Returns whether the ticket carries network addresses.
    pub fn has_addresses(&self) -> bool {
        !self.value.addresses.is_null()
    }

    /// Returns whether this is `krbtgt/realm@realm`.
    pub fn is_tgt(&self, realm: &str) -> bool {
        self.server()
            .and_then(|principal| principal.unparse())
            .is_ok_and(|name| name == format!("krbtgt/{realm}@{realm}"))
    }

    fn is_crossrealm_tgt(&self, realm: &str) -> bool {
        self.server()
            .and_then(|principal| principal.unparse())
            .is_ok_and(|name| {
                name.strip_prefix("krbtgt/")
                    .and_then(|name| name.split_once('@'))
                    .is_some_and(|(target_realm, service_realm)| {
                        service_realm == realm && target_realm != realm
                    })
            })
    }
}

impl Drop for Creds<'_> {
    fn drop(&mut self) {
        unsafe {
            sys::krb5_free_cred_contents(self.context.raw(), self.raw());
        }
    }
}

/// Credential-cache iterator.
pub struct CredsIter<'c> {
    context: &'c Context,
    cache: sys::krb5_ccache,
    cursor: sys::krb5_cc_cursor,
    finished: bool,
}

impl<'c> Iterator for CredsIter<'c> {
    type Item = Result<Creds<'c>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let mut value = Box::new(sys::krb5_creds::default());
        let code = unsafe {
            sys::krb5_cc_next_cred(
                self.context.raw(),
                self.cache,
                &mut self.cursor,
                value.as_mut(),
            )
        };
        if code == sys::KRB5_CC_END {
            self.finish();
            return None;
        }
        if code != 0 {
            self.finish();
            return Some(Err(error_for(self.context, code, "krb5_cc_next_cred")));
        }
        Some(Ok(Creds {
            context: self.context,
            value,
        }))
    }
}

impl CredsIter<'_> {
    fn finish(&mut self) {
        if !self.finished {
            unsafe {
                let _ = sys::krb5_cc_end_seq_get(self.context.raw(), self.cache, &mut self.cursor);
            }
            self.finished = true;
        }
    }
}

impl Drop for CredsIter<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

/// An owned authentication context.
pub struct AuthContext<'c> {
    context: &'c Context,
    raw: sys::krb5_auth_context,
}

impl<'c> AuthContext<'c> {
    fn new(context: &'c Context) -> Result<Self> {
        let mut raw = ptr::null_mut();
        unsafe {
            check(
                context.raw(),
                sys::krb5_auth_con_init(context.raw(), &mut raw),
                "krb5_auth_con_init",
            )?;
        }
        Ok(Self { context, raw })
    }

    /// Sets authentication-context flags.
    pub fn set_flags(&mut self, flags: u32) -> Result<()> {
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_auth_con_setflags(self.context.raw(), self.raw, flags as i32),
                "krb5_auth_con_setflags",
            )
        }
    }

    /// Sets IPv4 addresses used by the authentication context.
    pub fn set_addrs(&mut self, local: Ipv4Addr, remote: Ipv4Addr) -> Result<()> {
        let local_contents = local.octets();
        let remote_contents = remote.octets();
        let mut local_addr = sys::krb5_address {
            addrtype: sys::ADDRTYPE_INET as i32,
            length: local_contents.len() as u32,
            contents: local_contents.as_ptr() as *mut u8,
            ..sys::krb5_address::default()
        };
        let mut remote_addr = sys::krb5_address {
            addrtype: sys::ADDRTYPE_INET as i32,
            length: remote_contents.len() as u32,
            contents: remote_contents.as_ptr() as *mut u8,
            ..sys::krb5_address::default()
        };
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_auth_con_setaddrs(
                    self.context.raw(),
                    self.raw,
                    &mut local_addr,
                    &mut remote_addr,
                ),
                "krb5_auth_con_setaddrs",
            )
        }
    }

    /// Sets the dummy IPv4 addresses used for NAT traversal.
    pub fn set_dummy_addrs(&mut self) -> Result<()> {
        let contents = *b"dummy";
        let mut local_addr = sys::krb5_address {
            addrtype: libc_af_inet(),
            length: contents.len() as u32,
            contents: contents.as_ptr() as *mut u8,
            ..sys::krb5_address::default()
        };
        let mut remote_addr = sys::krb5_address {
            addrtype: libc_af_inet(),
            length: contents.len() as u32,
            contents: contents.as_ptr() as *mut u8,
            ..sys::krb5_address::default()
        };
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_auth_con_setaddrs(
                    self.context.raw(),
                    self.raw,
                    &mut local_addr,
                    &mut remote_addr,
                ),
                "krb5_auth_con_setaddrs",
            )
        }
    }

    /// Performs mutual Kerberos authentication over a file descriptor.
    pub fn sendauth(
        &mut self,
        fd: &mut RawFd,
        client: &Principal<'_>,
        server: &Principal<'_>,
        ccache: &Ccache<'_>,
    ) -> Result<()> {
        let version = CString::new("0.1").expect("literal has no NUL");
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_sendauth(
                    self.context.raw(),
                    &mut self.raw,
                    fd as *mut RawFd as sys::krb5_pointer,
                    version.as_ptr() as *mut _,
                    client.raw,
                    server.raw,
                    (sys::AP_OPTS_MUTUAL_REQUIRED | sys::AP_OPTS_USE_SUBKEY) as i32,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ccache.raw,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                "krb5_sendauth",
            )
        }
    }

    /// Wraps plaintext in a Kerberos privacy message.
    pub fn mk_priv(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let input = sys::krb5_data {
            length: plaintext.len() as u32,
            data: plaintext.as_ptr() as *mut _,
            ..sys::krb5_data::default()
        };
        let mut output = DataContents::new(self.context);
        let mut replay = sys::krb5_replay_data::default();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_mk_priv(
                    self.context.raw(),
                    self.raw,
                    &input,
                    &mut output.data,
                    &mut replay,
                ),
                "krb5_mk_priv",
            )?;
            Ok(bytes(&output.data).to_vec())
        }
    }

    /// Unwraps a Kerberos privacy message.
    pub fn rd_priv(&self, cipher: &[u8]) -> Result<Vec<u8>> {
        let input = sys::krb5_data {
            length: cipher.len() as u32,
            data: cipher.as_ptr() as *mut _,
            ..sys::krb5_data::default()
        };
        let mut output = DataContents::new(self.context);
        let mut replay = sys::krb5_replay_data::default();
        unsafe {
            check(
                self.context.raw(),
                sys::krb5_rd_priv(
                    self.context.raw(),
                    self.raw,
                    &input,
                    &mut output.data,
                    &mut replay,
                ),
                "krb5_rd_priv",
            )?;
            Ok(bytes(&output.data).to_vec())
        }
    }
}

impl Drop for AuthContext<'_> {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                let _ = sys::krb5_auth_con_free(self.context.raw(), self.raw);
            }
        }
    }
}

fn error_for(context: &Context, code: sys::krb5_error_code, op: &'static str) -> Error {
    check(context.raw(), code, op).expect_err("nonzero Kerberos code must produce an error")
}

fn libc_af_inet() -> i32 {
    2
}

/// Writes a Kerberos-framed message to a file descriptor.
pub fn write_message(context: &Context, fd: &mut RawFd, data: &[u8]) -> Result<()> {
    let mut message = sys::krb5_data {
        length: data.len() as u32,
        data: data.as_ptr() as *mut _,
        ..sys::krb5_data::default()
    };
    unsafe {
        check(
            context.raw(),
            sys::krb5_write_message(
                context.raw(),
                fd as *mut RawFd as sys::krb5_pointer,
                &mut message,
            ),
            "krb5_write_message",
        )
    }
}

/// Reads a Kerberos-framed message from a file descriptor.
pub fn read_message(context: &Context, fd: &mut RawFd) -> Result<Vec<u8>> {
    let mut message = DataContents::new(context);
    unsafe {
        check(
            context.raw(),
            sys::krb5_read_message(
                context.raw(),
                fd as *mut RawFd as sys::krb5_pointer,
                &mut message.data,
            ),
            "krb5_read_message",
        )?;
        Ok(bytes(&message.data).to_vec())
    }
}

/// Converts a principal to its local operating-system account name.
pub fn aname_to_localname(context: &Context, principal: &Principal<'_>) -> Result<String> {
    let mut output = vec![0_i8; 256];
    unsafe {
        check(
            context.raw(),
            sys::krb5_aname_to_localname(
                context.raw(),
                principal.raw,
                output.len() as i32,
                output.as_mut_ptr(),
            ),
            "krb5_aname_to_localname",
        )?;
        Ok(CStr::from_ptr(output.as_ptr())
            .to_string_lossy()
            .into_owned())
    }
}

/// Serialized Kerberos credential helpers.
pub mod cred_blob {
    use super::*;

    struct TgtCreds<'c> {
        context: &'c Context,
        ptr: *mut *mut sys::krb5_creds,
    }

    impl<'c> TgtCreds<'c> {
        fn new(context: &'c Context, ptr: *mut *mut sys::krb5_creds) -> Self {
            Self { context, ptr }
        }
    }

    impl Drop for TgtCreds<'_> {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe {
                    sys::krb5_free_tgt_creds(self.context.raw(), self.ptr);
                }
            }
        }
    }

    /// Credential metadata extracted from a KRB-CRED blob.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BlobInfo {
        /// Unparsed client principal.
        pub principal: String,
        /// Earliest credential start time.
        pub start: i64,
        /// Earliest credential end time.
        pub end: i64,
        /// Latest renewal deadline.
        pub renew_till: i64,
        /// Whether the first credential has no network addresses.
        pub addressless: bool,
        /// Whether the blob contains more than one credential.
        pub crossrealm: bool,
    }

    fn copy_data(
        context: &Context,
        data: *mut sys::krb5_data,
        op: &'static str,
    ) -> Result<Vec<u8>> {
        if data.is_null() {
            return Err(Error::input(op, "Kerberos returned a null data pointer"));
        }
        let result = unsafe { bytes(&*data).to_vec() };
        unsafe { sys::krb5_free_data(context.raw(), data) };
        Ok(result)
    }

    /// Serializes TGT credentials from a cache.
    pub fn get(context: &Context, cache: &Ccache<'_>) -> Result<Vec<u8>> {
        let principal = cache.principal()?;
        let realm = principal.realm()?;
        let credentials = cache.creds()?;
        let mut owned = Vec::new();
        for item in credentials {
            let item = item?;
            if item.is_tgt(&realm) || item.is_crossrealm_tgt(&realm) {
                owned.push(item);
            }
        }
        let local = owned
            .iter()
            .find(|credential| credential.is_tgt(&realm))
            .ok_or_else(|| Error::input("cred_blob::get", "no local TGT in cache"))?;
        let mut pointers = vec![local.raw()];
        pointers.extend(
            owned
                .iter()
                .map(Creds::raw)
                .filter(|pointer| *pointer != local.raw()),
        );
        pointers.push(ptr::null_mut());
        let mut auth = context.auth_context()?;
        auth.set_flags(0)?;
        let mut output = ptr::null_mut();
        unsafe {
            check(
                context.raw(),
                sys::krb5_mk_ncred(
                    context.raw(),
                    auth.raw,
                    pointers.as_mut_ptr(),
                    &mut output,
                    &mut sys::krb5_replay_data::default(),
                ),
                "krb5_mk_ncred",
            )?;
        }
        copy_data(context, output, "krb5_mk_ncred")
    }

    /// Obtains and serializes a forwarded credential from a KDC.
    pub fn get_fwd(context: &Context, server: &str, cache: &Ccache<'_>) -> Result<Vec<u8>> {
        let server = c_string(server, "krb5_fwd_tgt_creds")?;
        let principal = cache.principal()?;
        let mut auth = context.auth_context()?;
        auth.set_flags(sys::KRB5_AUTH_CONTEXT_RET_TIME)?;
        let mut forwarded = DataContents::new(context);
        unsafe {
            check(
                context.raw(),
                sys::krb5_fwd_tgt_creds(
                    context.raw(),
                    auth.raw,
                    server.as_ptr(),
                    principal.raw,
                    ptr::null_mut(),
                    cache.raw,
                    sys::AP_OPTS_MUTUAL_REQUIRED as i32,
                    &mut forwarded.data,
                ),
                "krb5_fwd_tgt_creds",
            )?;
            auth.set_flags(0)?;
        }
        let mut output_creds = ptr::null_mut();
        let mut replay = sys::krb5_replay_data::default();
        unsafe {
            check(
                context.raw(),
                sys::krb5_rd_cred(
                    context.raw(),
                    auth.raw,
                    &mut forwarded.data,
                    &mut output_creds,
                    &mut replay,
                ),
                "krb5_rd_cred",
            )?;
        }
        let output_creds = TgtCreds::new(context, output_creds);
        serialize_one(context, &mut auth, &output_creds)
    }

    /// Stores every credential in a KRB-CRED blob into a cache.
    pub fn store(context: &Context, cache: &Ccache<'_>, blob: &[u8]) -> Result<()> {
        let mut auth = context.auth_context()?;
        auth.set_flags(0)?;
        let mut data = sys::krb5_data {
            magic: 0,
            length: blob.len() as u32,
            data: blob.as_ptr() as *mut _,
        };
        let mut credentials = ptr::null_mut();
        let mut replay = sys::krb5_replay_data::default();
        unsafe {
            check(
                context.raw(),
                sys::krb5_rd_cred(
                    context.raw(),
                    auth.raw,
                    &mut data,
                    &mut credentials,
                    &mut replay,
                ),
                "krb5_rd_cred",
            )?;
            let credentials = TgtCreds::new(context, credentials);
            if credentials.ptr.is_null() || (*credentials.ptr).is_null() {
                return Err(Error::input("krb5_rd_cred", "credential list is empty"));
            }
            check(
                context.raw(),
                sys::krb5_cc_initialize(context.raw(), cache.raw, (**credentials.ptr).client),
                "krb5_cc_initialize",
            )?;
            let mut item = credentials.ptr;
            while !(*item).is_null() {
                check(
                    context.raw(),
                    sys::krb5_cc_store_cred(context.raw(), cache.raw, *item),
                    "krb5_cc_store_cred",
                )?;
                item = item.add(1);
            }
        }
        Ok(())
    }

    /// Parses metadata from a KRB-CRED blob.
    pub fn parse(context: &Context, blob: &[u8]) -> Result<BlobInfo> {
        let mut auth = context.auth_context()?;
        auth.set_flags(0)?;
        let mut data = sys::krb5_data {
            magic: 0,
            length: blob.len() as u32,
            data: blob.as_ptr() as *mut _,
        };
        let mut credentials = ptr::null_mut();
        let mut replay = sys::krb5_replay_data::default();
        unsafe {
            check(
                context.raw(),
                sys::krb5_rd_cred(
                    context.raw(),
                    auth.raw,
                    &mut data,
                    &mut credentials,
                    &mut replay,
                ),
                "krb5_rd_cred",
            )?;
            let credentials = TgtCreds::new(context, credentials);
            if credentials.ptr.is_null() || (*credentials.ptr).is_null() {
                return Err(Error::input("krb5_rd_cred", "credential list is empty"));
            }
            let first = &**credentials.ptr;
            let principal = Principal {
                context,
                raw: {
                    let mut raw = ptr::null_mut();
                    check(
                        context.raw(),
                        sys::krb5_copy_principal(context.raw(), first.client, &mut raw),
                        "krb5_copy_principal",
                    )?;
                    raw
                },
            };
            let name = principal.unparse()?;
            let mut start = i64::from(first.times.starttime);
            let mut end = i64::from(first.times.endtime);
            let mut renew_till = i64::from(first.times.renew_till);
            let mut count = 0;
            let mut item = credentials.ptr;
            while !(*item).is_null() {
                let value = &**item;
                start = start.min(i64::from(value.times.starttime));
                end = end.min(i64::from(value.times.endtime));
                renew_till = renew_till.max(i64::from(value.times.renew_till));
                count += 1;
                item = item.add(1);
            }
            let result = BlobInfo {
                principal: name,
                start,
                end,
                renew_till,
                addressless: first.addresses.is_null(),
                crossrealm: count > 1,
            };
            Ok(result)
        }
    }

    fn serialize_one(
        context: &Context,
        auth: &mut AuthContext<'_>,
        credentials: &TgtCreds<'_>,
    ) -> Result<Vec<u8>> {
        if credentials.ptr.is_null() || unsafe { (*credentials.ptr).is_null() } {
            return Err(Error::input("krb5_mk_1cred", "credential list is empty"));
        }
        auth.set_flags(0)?;
        let mut output = ptr::null_mut();
        let mut replay = sys::krb5_replay_data::default();
        unsafe {
            check(
                context.raw(),
                sys::krb5_mk_1cred(
                    context.raw(),
                    auth.raw,
                    *credentials.ptr,
                    &mut output,
                    &mut replay,
                ),
                "krb5_mk_1cred",
            )?;
        }
        copy_data(context, output, "krb5_mk_1cred")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_roundtrip() {
        let context = Context::new().expect("MIT Kerberos context should initialize");
        drop(context);
    }

    #[test]
    fn principal_roundtrip() {
        let context = Context::new().unwrap();
        let principal = context.parse_name("user@EXAMPLE.COM").unwrap();
        assert_eq!(principal.unparse().unwrap(), "user@EXAMPLE.COM");
        assert_eq!(principal.realm().unwrap(), "EXAMPLE.COM");
    }

    #[test]
    fn unique_file_cache_can_be_destroyed() {
        let context = Context::new().unwrap();
        let path = std::env::temp_dir().join(format!("auks-krb5-test-{}-cc", std::process::id()));
        unsafe {
            std::env::set_var("KRB5CCNAME", format!("FILE:{}", path.display()));
        }
        let cache = context.new_unique_ccache(Some("FILE")).unwrap();
        let name = cache.full_name().unwrap();
        assert!(name.starts_with("FILE:"));
        let principal = context.parse_name("user@EXAMPLE.COM").unwrap();
        cache.initialize(&principal).unwrap();
        let cache_path = std::path::Path::new(name.strip_prefix("FILE:").unwrap());
        assert!(cache_path.exists());
        cache.destroy().unwrap();
        assert!(!cache_path.exists());
        unsafe {
            std::env::remove_var("KRB5CCNAME");
        }
    }

    #[test]
    fn garbage_blob_is_rejected() {
        let context = Context::new().unwrap();
        let error = cred_blob::parse(&context, b"garbage").unwrap_err();
        assert!(!error.message.is_empty());
    }

    #[test]
    #[ignore = "requires a krb5.conf auth_to_local rule for root@ATHENA.MIT.EDU"]
    fn root_maps_to_local_name() {
        let context = Context::new().unwrap();
        let principal = context.parse_name("root@ATHENA.MIT.EDU").unwrap();
        let name = aname_to_localname(&context, &principal).unwrap();
        assert_eq!(name, "root");
    }
}

#[cfg(test)]
#[cfg(feature = "kdc")]
mod kdc_tests {
    #[test]
    #[ignore = "requires the compose KDC fixture"]
    fn get_roundtrip() {}

    #[test]
    #[ignore = "requires the compose KDC fixture"]
    fn store_roundtrip() {}
}
