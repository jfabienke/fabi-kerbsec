//! Minimal FFI bindings for GSS-API IOV operations
//!
//! This module provides the bare minimum FFI definitions needed for
//! IOV (Input/Output Vector) operations in GSS-API. We avoid bindgen
//! to keep the build simple and control exactly what we expose.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use libc::{c_int, c_uint, c_void, size_t};

// GSS-API types

/// GSS-API unsigned 32-bit integer type
pub type OM_uint32 = c_uint;

/// GSS-API Quality of Protection type
pub type gss_qop_t = OM_uint32;

/// GSS-API security context handle
pub type gss_ctx_id_t = *mut c_void;

/// GSS-API name handle
pub type gss_name_t = *mut c_void;

/// GSS-API credential handle
pub type gss_cred_id_t = *mut c_void;

/// GSS-API Object Identifier pointer
pub type gss_OID = *mut gss_OID_desc;

/// GSS-API Object Identifier descriptor
#[repr(C)]
pub struct gss_OID_desc {
    /// Length of the OID in bytes
    pub length: OM_uint32,
    /// Pointer to the OID octets
    pub elements: *mut c_void,
}

/// GSS-API buffer descriptor for passing data
#[repr(C)]
pub struct gss_buffer_desc {
    /// Length of the buffer in bytes
    pub length: size_t,
    /// Pointer to the buffer data
    pub value: *mut c_void,
}

/// Pointer to a GSS-API buffer descriptor
pub type gss_buffer_t = *mut gss_buffer_desc;

// IOV buffer types

/// Empty IOV buffer type
pub const GSS_IOV_BUFFER_TYPE_EMPTY: c_uint = 0;
/// Data IOV buffer type (message to protect)
pub const GSS_IOV_BUFFER_TYPE_DATA: c_uint = 1;
/// Header IOV buffer type (protection header)
pub const GSS_IOV_BUFFER_TYPE_HEADER: c_uint = 2;
/// Mechanism parameters IOV buffer type
pub const GSS_IOV_BUFFER_TYPE_MECH_PARAMS: c_uint = 3;
/// Trailer IOV buffer type (protection trailer)
pub const GSS_IOV_BUFFER_TYPE_TRAILER: c_uint = 7;
/// Padding IOV buffer type
pub const GSS_IOV_BUFFER_TYPE_PADDING: c_uint = 9;
/// Stream IOV buffer type
pub const GSS_IOV_BUFFER_TYPE_STREAM: c_uint = 10;
/// Sign-only IOV buffer type (included in MIC but not encrypted)
pub const GSS_IOV_BUFFER_TYPE_SIGN_ONLY: c_uint = 11;

// Flags for IOV buffer types

/// Request GSS to allocate buffer space
pub const GSS_IOV_BUFFER_FLAG_ALLOCATE: c_uint = 0x0001_0000;
/// Buffer was allocated by GSS
pub const GSS_IOV_BUFFER_FLAG_ALLOCATED: c_uint = 0x0002_0000;

// IOV buffer descriptor

/// GSS-API IOV buffer descriptor for scatter-gather operations
#[repr(C)]
pub struct gss_iov_buffer_desc {
    /// Buffer type and flags (OR'd together)
    pub type_: OM_uint32,
    /// The actual buffer data
    pub buffer: gss_buffer_desc,
}

/// Pointer to an IOV buffer descriptor
pub type gss_iov_buffer_t = *mut gss_iov_buffer_desc;

// Context flags

/// Delegate credentials to remote peer
pub const GSS_C_DELEG_FLAG: OM_uint32 = 1;
/// Request mutual authentication
pub const GSS_C_MUTUAL_FLAG: OM_uint32 = 2;
/// Enable replay detection
pub const GSS_C_REPLAY_FLAG: OM_uint32 = 4;
/// Enable sequence checking
pub const GSS_C_SEQUENCE_FLAG: OM_uint32 = 8;
/// Enable confidentiality (encryption)
pub const GSS_C_CONF_FLAG: OM_uint32 = 16;
/// Enable integrity protection
pub const GSS_C_INTEG_FLAG: OM_uint32 = 32;
/// Anonymous authentication
pub const GSS_C_ANON_FLAG: OM_uint32 = 64;
/// Protection services available
pub const GSS_C_PROT_READY_FLAG: OM_uint32 = 128;
/// Transferable context
pub const GSS_C_TRANS_FLAG: OM_uint32 = 256;
/// DCE-style context (critical for DCE/RPC)
pub const GSS_C_DCE_STYLE: OM_uint32 = 0x1000;

// Status codes

/// GSS operation completed successfully
pub const GSS_S_COMPLETE: OM_uint32 = 0;
/// GSS operation needs continuation
pub const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;

// Error handling

/// GSS-API error code type
pub const GSS_C_GSS_CODE: c_int = 1;
/// Mechanism-specific error code type
pub const GSS_C_MECH_CODE: c_int = 2;
/// Null OID value - represents `GSS_C_NO_OID` in GSS-API
///
/// Using `std::ptr::null_mut()` is the idiomatic way to create null pointers in Rust.
pub const GSS_C_NO_OID: gss_OID = std::ptr::null_mut();
/// Null buffer value - represents `GSS_C_NO_BUFFER` in GSS-API
pub const GSS_C_NO_BUFFER: gss_buffer_t = std::ptr::null_mut();

// QOP values

/// Default quality of protection
pub const GSS_C_QOP_DEFAULT: gss_qop_t = 0;

// External functions - IOV operations (Linux only)
#[cfg(target_os = "linux")]
extern "C" {
    /// Wrap a message using IOV (Input/Output Vector) buffers
    ///
    /// This function provides zero-copy message protection by operating
    /// directly on scatter-gather buffers.
    pub fn gss_wrap_iov(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        conf_req_flag: c_int,
        qop_req: gss_qop_t,
        conf_state: *mut c_int,
        iov: gss_iov_buffer_t,
        iov_count: c_int,
    ) -> OM_uint32;

    /// Unwrap a message using IOV (Input/Output Vector) buffers
    ///
    /// This function provides zero-copy message verification by operating
    /// directly on scatter-gather buffers.
    pub fn gss_unwrap_iov(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        conf_state: *mut c_int,
        qop_state: *mut gss_qop_t,
        iov: gss_iov_buffer_t,
        iov_count: c_int,
    ) -> OM_uint32;

    /// Calculate maximum input size for wrap operation
    ///
    /// Given a maximum output size, returns the maximum input size
    /// that will not exceed the output limit when wrapped.
    pub fn gss_wrap_size_limit(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        conf_req_flag: c_int,
        qop_req: gss_qop_t,
        req_output_size: OM_uint32,
        max_input_size: *mut OM_uint32,
    ) -> OM_uint32;
}

// External functions - Available on all platforms
extern "C" {
    /// Display a GSS-API status code as a human-readable string
    ///
    /// # Parameters
    /// - `minor_status`: Mechanism-specific status code
    /// - `status_value`: Status value to be converted
    /// - `status_type`: `GSS_C_GSS_CODE` or `GSS_C_MECH_CODE`
    /// - `mech_type`: Mechanism type (NULL for default)
    /// - `message_context`: Message context for multi-part messages
    /// - `status_string`: Output buffer for status string
    pub fn gss_display_status(
        minor_status: *mut OM_uint32,
        status_value: OM_uint32,
        status_type: c_int,
        mech_type: gss_OID,
        message_context: *mut OM_uint32,
        status_string: gss_buffer_t,
    ) -> OM_uint32;

    /// Release a GSS-API buffer
    ///
    /// # Parameters
    /// - `minor_status`: Mechanism-specific status code
    /// - `buffer`: Buffer to be released
    pub fn gss_release_buffer(
        minor_status: *mut OM_uint32,
        buffer: gss_buffer_t,
    ) -> OM_uint32;

    /// Inquire about a security context
    ///
    /// This function obtains information about a security context.
    /// Used to verify actual negotiated flags (delegation, mutual auth, etc.)
    ///
    /// # Parameters
    /// - `minor_status`: Mechanism-specific status code (output)
    /// - `context_handle`: The security context to query
    /// - `src_name`: Source name (may be NULL)
    /// - `targ_name`: Target name (may be NULL)
    /// - `lifetime_rec`: Remaining lifetime in seconds (may be NULL)
    /// - `mech_type`: Mechanism OID (may be NULL)
    /// - `ctx_flags`: Negotiated context flags (output, may be NULL)
    /// - `locally_initiated`: Whether context was initiated locally (may be NULL)
    /// - `open`: Whether context is fully established (may be NULL)
    pub fn gss_inquire_context(
        minor_status: *mut OM_uint32,
        context_handle: gss_ctx_id_t,
        src_name: *mut gss_name_t,
        targ_name: *mut gss_name_t,
        lifetime_rec: *mut OM_uint32,
        mech_type: *mut gss_OID,
        ctx_flags: *mut OM_uint32,
        locally_initiated: *mut c_int,
        open: *mut c_int,
    ) -> OM_uint32;

    /// Release a GSS-API name
    ///
    /// # Parameters
    /// - `minor_status`: Mechanism-specific status code
    /// - `name`: Name to be released
    pub fn gss_release_name(
        minor_status: *mut OM_uint32,
        name: *mut gss_name_t,
    ) -> OM_uint32;

    /// Export credentials for delegation
    ///
    /// # Parameters
    /// - `minor_status`: Mechanism-specific status code
    /// - `cred_handle`: Credential handle to export
    /// - `cred_token`: Output buffer for exported credential
    pub fn gss_export_cred(
        minor_status: *mut OM_uint32,
        cred_handle: gss_cred_id_t,
        cred_token: gss_buffer_t,
    ) -> OM_uint32;

    /// Import credentials from exported token
    ///
    /// # Parameters
    /// - `minor_status`: Mechanism-specific status code
    /// - `cred_token`: Input buffer with exported credential
    /// - `cred_handle`: Output credential handle
    pub fn gss_import_cred(
        minor_status: *mut OM_uint32,
        cred_token: gss_buffer_t,
        cred_handle: *mut gss_cred_id_t,
    ) -> OM_uint32;

    /// Acquire credentials from a keytab
    ///
    /// Note: This is a MIT Kerberos extension, not standard GSS-API.
    /// Use `krb5_gss_register_acceptor_identity` or set `KRB5_KTNAME` env var.
    pub fn gss_acquire_cred(
        minor_status: *mut OM_uint32,
        desired_name: gss_name_t,
        time_req: OM_uint32,
        desired_mechs: *mut gss_OID_set_desc,
        cred_usage: c_int,
        output_cred_handle: *mut gss_cred_id_t,
        actual_mechs: *mut *mut gss_OID_set_desc,
        time_rec: *mut OM_uint32,
    ) -> OM_uint32;

    /// Release a credential handle
    pub fn gss_release_cred(
        minor_status: *mut OM_uint32,
        cred_handle: *mut gss_cred_id_t,
    ) -> OM_uint32;
}

/// GSS-API OID set descriptor
#[repr(C)]
pub struct gss_OID_set_desc {
    /// Number of OIDs in the set
    pub count: size_t,
    /// Pointer to array of OID descriptors
    pub elements: gss_OID,
}

// Credential usage constants
/// Credential can be used to initiate contexts
pub const GSS_C_INITIATE: c_int = 1;
/// Credential can be used to accept contexts
pub const GSS_C_ACCEPT: c_int = 2;
/// Credential can be used for both initiate and accept
pub const GSS_C_BOTH: c_int = 0;

/// Check if IOV operations are available on this platform
///
/// IOV is only available on Linux with MIT Kerberos.
/// macOS GSS.framework doesn't expose IOV functions.
#[must_use] pub const fn has_iov_support() -> bool {
    cfg!(target_os = "linux")
}