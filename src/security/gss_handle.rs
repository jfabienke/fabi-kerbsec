//! Owned GSS-API handles for the initiator side
//!
//! [`ClientCtx`] owns a security context together with the target name and
//! credentials it was created for, and releases all three when dropped.

use std::ptr;
use std::time::Duration;

use super::gss_iov::{gss_error, take_gss_buffer};
use crate::error::{Error, Result};
use crate::ffi;

/// A borrowed byte slice as an input `gss_buffer_desc` (GSS-API only reads it)
const fn input_buffer(bytes: &[u8]) -> ffi::gss_buffer_desc {
    ffi::gss_buffer_desc {
        length: bytes.len(),
        value: bytes.as_ptr().cast_mut().cast(),
    }
}

const fn empty_buffer() -> ffi::gss_buffer_desc {
    ffi::gss_buffer_desc {
        length: 0,
        value: ptr::null_mut(),
    }
}

/// An imported name, released on drop
struct Name(ffi::gss_name_t);

impl Name {
    /// Import `principal` (`service/host@REALM`) as a Kerberos principal name
    fn krb5_principal(principal: &str) -> Result<Self> {
        let mut buf = input_buffer(principal.as_bytes());
        let (mut minor, mut name) = (0, ffi::GSS_C_NO_NAME);
        // SAFETY: `buf` points into `principal`, which outlives the call; the name
        // type is a static OID; `name` receives a handle we own from here on.
        let major = unsafe {
            ffi::gss_import_name(
                &mut minor,
                &mut buf,
                ffi::GSS_KRB5_NT_PRINCIPAL_NAME.as_ptr(),
                &mut name,
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            return Err(gss_error(major, minor));
        }
        Ok(Self(name))
    }
}

impl Drop for Name {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: the handle came from gss_import_name and is released only here.
        unsafe { ffi::gss_release_name(&mut minor, &mut self.0) };
    }
}

/// Initiator credentials, released on drop
struct Cred(ffi::gss_cred_id_t);

impl Cred {
    /// The default initiator credentials (the process's ticket cache or client
    /// keytab), requested for `lifetime`
    fn initiate(lifetime: Duration) -> Result<Self> {
        let time_req =
            ffi::OM_uint32::try_from(lifetime.as_secs()).unwrap_or(ffi::GSS_C_INDEFINITE);
        let (mut minor, mut cred) = (0, ffi::GSS_C_NO_CREDENTIAL);
        // SAFETY: the optional outputs are null; `cred` receives a handle we own.
        let major = unsafe {
            ffi::gss_acquire_cred(
                &mut minor,
                ffi::GSS_C_NO_NAME,
                time_req,
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &mut cred,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            return Err(gss_error(major, minor));
        }
        Ok(Self(cred))
    }
}

impl Drop for Cred {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: the handle came from gss_acquire_cred and is released only here.
        unsafe { ffi::gss_release_cred(&mut minor, &mut self.0) };
    }
}

/// A Kerberos initiator context with the name and credentials it uses
pub struct ClientCtx {
    ctx: ffi::gss_ctx_id_t,
    target: Name,
    cred: Cred,
    req_flags: u32,
    complete: bool,
}

// SAFETY: GSS-API handles are not tied to the thread that created them. A
// `ClientCtx` is used through `&mut` for every call that changes context state,
// and `Context` (its only owner outside this module) is `!Sync`, so two threads
// never use the handles at once. (The raw-pointer fields are why the type is
// not `Send` automatically.)
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for ClientCtx {}

impl ClientCtx {
    /// Prepare a context to `target_principal` with `req_flags` (`GSS_C_*_FLAG`),
    /// using the default initiator credentials
    ///
    /// # Errors
    ///
    /// [`Error::GssUnavailable`] if the GSS-API library cannot be loaded; a GSS
    /// error if the name is invalid or no credentials are available.
    pub fn new(target_principal: &str, req_flags: u32, cred_lifetime: Duration) -> Result<Self> {
        ffi::api().map_err(|e| Error::GssUnavailable(e.to_owned()))?;
        Ok(Self {
            ctx: ffi::GSS_C_NO_CONTEXT,
            target: Name::krb5_principal(target_principal)?,
            cred: Cred::initiate(cred_lifetime)?,
            req_flags,
            complete: false,
        })
    }

    /// One `gss_init_sec_context` leg
    ///
    /// `input` is the peer's token (`None` on the first leg). Returns the token to
    /// send, if any. `channel_bindings` is the application data of the channel
    /// bindings (e.g. TLS channel binding data).
    ///
    /// # Errors
    ///
    /// A GSS error if the mechanism rejects the exchange.
    pub fn step(
        &mut self,
        input: Option<&[u8]>,
        channel_bindings: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        if self.complete {
            return Ok(None);
        }
        let mut bindings = ffi::gss_channel_bindings_struct {
            initiator_addrtype: ffi::GSS_C_AF_UNSPEC,
            initiator_address: empty_buffer(),
            acceptor_addrtype: ffi::GSS_C_AF_UNSPEC,
            acceptor_address: empty_buffer(),
            application_data: channel_bindings.map_or_else(empty_buffer, input_buffer),
        };
        let bindings_ptr = if channel_bindings.is_some() {
            ptr::addr_of_mut!(bindings)
        } else {
            ffi::GSS_C_NO_CHANNEL_BINDINGS
        };
        let mut input_token = input.map(input_buffer);
        let input_ptr = input_token
            .as_mut()
            .map_or(ffi::GSS_C_NO_BUFFER, ptr::from_mut);
        let mut output = empty_buffer();
        let mut minor = 0;

        // SAFETY: the bindings and input token point into slices that outlive the
        // call and are only read; the name, credentials and mechanism OID stay
        // valid for the context's life; `self.ctx` is created or advanced in
        // place; `output` is allocated by GSS and released by take_gss_buffer.
        let major = unsafe {
            ffi::gss_init_sec_context(
                &mut minor,
                self.cred.0,
                &mut self.ctx,
                self.target.0,
                ffi::GSS_MECH_KRB5.as_ptr(),
                self.req_flags,
                ffi::GSS_C_INDEFINITE,
                bindings_ptr,
                input_ptr,
                ptr::null_mut(),
                &mut output,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        let token = take_gss_buffer(&mut output);
        if ffi::is_error(major) {
            return Err(gss_error(major, minor));
        }
        self.complete = major & ffi::GSS_S_CONTINUE_NEEDED == 0;
        Ok((!token.is_empty()).then_some(token))
    }

    /// Whether the last leg completed the handshake
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// The flags the mechanism negotiated (`gss_inquire_context`)
    ///
    /// # Errors
    ///
    /// A GSS error if the context cannot be inquired (e.g. before the first leg).
    pub fn flags(&self) -> Result<u32> {
        let (mut minor, mut flags) = (0, 0);
        // SAFETY: only `ctx_flags` is requested; every other output is null.
        let major = unsafe {
            ffi::gss_inquire_context(
                &mut minor,
                self.ctx,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut flags,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            return Err(gss_error(major, minor));
        }
        Ok(flags)
    }

    /// The raw context handle, null before the first leg
    ///
    /// The handle stays owned by `self`: use it only while borrowing `self`, and
    /// never delete it.
    #[must_use]
    pub const fn raw_ctx(&self) -> ffi::gss_ctx_id_t {
        self.ctx
    }
}

impl Drop for ClientCtx {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            let mut minor = 0;
            // SAFETY: the handle came from gss_init_sec_context and is deleted only
            // here. The name and credentials are released after this, as fields.
            unsafe { ffi::gss_delete_sec_context(&mut minor, &mut self.ctx, ffi::GSS_C_NO_BUFFER) };
        }
    }
}
