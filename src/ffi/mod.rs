//! GSS-API declarations, resolved from the system library at run time
//!
//! kerbsec declares the RFC 2744 functions it calls (plus the MIT/Heimdal IOV
//! extensions) by hand and loads them with `dlopen` the first time one is used.
//! Building needs no Kerberos headers, bindgen or libclang, and a program that
//! never uses Kerberos runs on a host without the library.
//!
//! The library is the first of these that loads:
//! - the path or soname in `KERBSEC_GSSAPI_LIBRARY` ([`LIBRARY_ENV`]), when set;
//! - Linux: `libgssapi_krb5.so.2` (MIT Kerberos), then `libgssapi.so.3` (Heimdal);
//! - macOS: `GSS.framework`.
//!
//! Each `gss_*` function here has the C signature and calls through the loaded
//! table. When the library (or an optional function) is missing it returns
//! [`GSS_S_UNAVAILABLE`], so callers handle it like any other GSS failure;
//! [`api`] says why loading failed.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::ffi::OsString;
use std::ptr;
use std::sync::OnceLock;

use libc::{c_int, c_uint, c_void, size_t};
use libloading::Library;

// GSS-API types

/// GSS-API unsigned 32-bit integer type
pub type OM_uint32 = c_uint;

/// GSS-API Quality of Protection type
pub type gss_qop_t = OM_uint32;

/// GSS-API credential usage (`GSS_C_INITIATE`, `GSS_C_ACCEPT`, `GSS_C_BOTH`)
pub type gss_cred_usage_t = c_int;

/// GSS-API security context handle
pub type gss_ctx_id_t = *mut c_void;

/// GSS-API name handle
pub type gss_name_t = *mut c_void;

/// GSS-API credential handle
pub type gss_cred_id_t = *mut c_void;

/// GSS-API Object Identifier pointer
pub type gss_OID = *mut gss_OID_desc;

/// GSS-API OID set pointer
pub type gss_OID_set = *mut gss_OID_set_desc;

/// Pointer to a GSS-API buffer descriptor
pub type gss_buffer_t = *mut gss_buffer_desc;

/// Pointer to channel bindings
pub type gss_channel_bindings_t = *mut gss_channel_bindings_struct;

/// Pointer to an IOV buffer descriptor
pub type gss_iov_buffer_t = *mut gss_iov_buffer_desc;

// Structs. Apple's gssapi.h wraps them in `#pragma pack(push, 2)` on Intel Macs
// (for compatibility with MIT Kerberos on PowerPC), not on Apple silicon, so the
// ones with padding in their natural layout take `packed(2)` there.
// `gss_buffer_desc` has no padding: its layout is the same either way.

/// GSS-API Object Identifier descriptor
#[cfg_attr(all(target_os = "macos", target_arch = "x86_64"), repr(C, packed(2)))]
#[cfg_attr(not(all(target_os = "macos", target_arch = "x86_64")), repr(C))]
pub struct gss_OID_desc {
    /// Length of the OID in bytes
    pub length: OM_uint32,
    /// Pointer to the OID octets
    pub elements: *mut c_void,
}

/// GSS-API set of OIDs
#[cfg_attr(all(target_os = "macos", target_arch = "x86_64"), repr(C, packed(2)))]
#[cfg_attr(not(all(target_os = "macos", target_arch = "x86_64")), repr(C))]
pub struct gss_OID_set_desc {
    /// Number of OIDs in the set
    pub count: size_t,
    /// The OIDs
    pub elements: gss_OID,
}

/// GSS-API buffer descriptor for passing data
#[repr(C)]
pub struct gss_buffer_desc {
    /// Length of the buffer in bytes
    pub length: size_t,
    /// Pointer to the buffer data
    pub value: *mut c_void,
}

/// GSS-API channel bindings (RFC 2744 section 3.11)
#[cfg_attr(all(target_os = "macos", target_arch = "x86_64"), repr(C, packed(2)))]
#[cfg_attr(not(all(target_os = "macos", target_arch = "x86_64")), repr(C))]
pub struct gss_channel_bindings_struct {
    /// Initiator address type (`GSS_C_AF_*`)
    pub initiator_addrtype: OM_uint32,
    /// Initiator address
    pub initiator_address: gss_buffer_desc,
    /// Acceptor address type (`GSS_C_AF_*`)
    pub acceptor_addrtype: OM_uint32,
    /// Acceptor address
    pub acceptor_address: gss_buffer_desc,
    /// Application data, e.g. TLS channel binding data
    pub application_data: gss_buffer_desc,
}

/// GSS-API IOV buffer descriptor for scatter-gather operations
///
/// Only used where the IOV functions exist (Linux). Apple's headers
/// `#pragma pack(2)` this struct on Intel Macs, so this layout would be wrong there.
#[repr(C)]
pub struct gss_iov_buffer_desc {
    /// Buffer type and flags (OR'd together)
    pub type_: OM_uint32,
    /// The actual buffer data
    pub buffer: gss_buffer_desc,
}

// Layouts the C ABI requires, checked at compile time for every target
const _: () = {
    use std::mem::{offset_of, size_of};
    let word = size_of::<usize>();

    assert!(size_of::<OM_uint32>() == 4);
    assert!(size_of::<gss_buffer_desc>() == 2 * word);
    assert!(offset_of!(gss_buffer_desc, value) == word);

    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
    {
        assert!(size_of::<gss_OID_desc>() == 2 * word);
        assert!(offset_of!(gss_OID_desc, elements) == word);
        assert!(size_of::<gss_OID_set_desc>() == 2 * word);
        // Each address type is padded to the alignment of the buffer after it
        assert!(size_of::<gss_channel_bindings_struct>() == 8 * word);
        assert!(offset_of!(gss_channel_bindings_struct, acceptor_addrtype) == 3 * word);
        assert!(offset_of!(gss_channel_bindings_struct, application_data) == 6 * word);
        assert!(offset_of!(gss_iov_buffer_desc, buffer) == word);
        assert!(size_of::<gss_iov_buffer_desc>() == 3 * word);
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        assert!(size_of::<gss_OID_desc>() == 12);
        assert!(offset_of!(gss_OID_desc, elements) == 4);
        assert!(size_of::<gss_OID_set_desc>() == 16);
        assert!(size_of::<gss_channel_bindings_struct>() == 56);
        assert!(offset_of!(gss_channel_bindings_struct, acceptor_addrtype) == 20);
        assert!(offset_of!(gss_channel_bindings_struct, application_data) == 40);
    }
};

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

// Credential usage

/// Credentials for initiating and accepting
pub const GSS_C_BOTH: gss_cred_usage_t = 0;
/// Credentials for initiating contexts
pub const GSS_C_INITIATE: gss_cred_usage_t = 1;
/// Credentials for accepting contexts
pub const GSS_C_ACCEPT: gss_cred_usage_t = 2;

/// Lifetime value meaning "as long as possible"
pub const GSS_C_INDEFINITE: OM_uint32 = 0xffff_ffff;

/// Unspecified channel-binding address type
pub const GSS_C_AF_UNSPEC: OM_uint32 = 0;

// Status codes

/// GSS operation completed successfully
pub const GSS_S_COMPLETE: OM_uint32 = 0;
/// GSS operation needs continuation
pub const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
/// Low 16 bits of a major status: supplementary information (duplicate, old,
/// unsequenced or gap token) rather than an error
pub const GSS_C_SUPPLEMENTARY_MASK: OM_uint32 = 0xffff;
/// Routine error "the operation or option is unavailable" (RFC 2744). The `gss_*`
/// functions here also return it when the library or the function is missing.
pub const GSS_S_UNAVAILABLE: OM_uint32 = 16 << 16;

/// `GSS_ERROR()`: whether a major status carries a calling or routine error
#[must_use]
pub const fn is_error(major: OM_uint32) -> bool {
    major & !GSS_C_SUPPLEMENTARY_MASK != 0
}

// Error handling

/// GSS-API error code type
pub const GSS_C_GSS_CODE: c_int = 1;
/// Mechanism-specific error code type
pub const GSS_C_MECH_CODE: c_int = 2;

// Null handles

/// `GSS_C_NO_OID`
pub const GSS_C_NO_OID: gss_OID = ptr::null_mut();
/// `GSS_C_NO_OID_SET`
pub const GSS_C_NO_OID_SET: gss_OID_set = ptr::null_mut();
/// `GSS_C_NO_BUFFER`
pub const GSS_C_NO_BUFFER: gss_buffer_t = ptr::null_mut();
/// `GSS_C_NO_NAME`
pub const GSS_C_NO_NAME: gss_name_t = ptr::null_mut();
/// `GSS_C_NO_CREDENTIAL`
pub const GSS_C_NO_CREDENTIAL: gss_cred_id_t = ptr::null_mut();
/// `GSS_C_NO_CONTEXT`
pub const GSS_C_NO_CONTEXT: gss_ctx_id_t = ptr::null_mut();
/// `GSS_C_NO_CHANNEL_BINDINGS`
pub const GSS_C_NO_CHANNEL_BINDINGS: gss_channel_bindings_t = ptr::null_mut();

// QOP values

/// Default quality of protection
pub const GSS_C_QOP_DEFAULT: gss_qop_t = 0;

// OIDs

/// An OID in static memory, to pass where GSS-API takes a `gss_OID`
pub struct StaticOid(gss_OID_desc);

// SAFETY: the descriptor and the octets it points to are immutable statics, and
// GSS-API only reads an OID passed in.
unsafe impl Sync for StaticOid {}

impl StaticOid {
    const fn new(der_value: &'static [u8]) -> Self {
        Self(gss_OID_desc {
            #[allow(clippy::cast_possible_truncation)] // OID values are a few bytes
            length: der_value.len() as OM_uint32,
            elements: der_value.as_ptr().cast_mut().cast(),
        })
    }

    /// The `gss_OID` to pass to GSS-API (which never writes through it)
    #[must_use]
    pub const fn as_ptr(&'static self) -> gss_OID {
        ptr::from_ref(&self.0).cast_mut()
    }
}

/// The Kerberos v5 mechanism, 1.2.840.113554.1.2.2 (RFC 1964)
pub static GSS_MECH_KRB5: StaticOid = StaticOid::new(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");

/// Kerberos principal name type, 1.2.840.113554.1.2.2.1 (`GSS_KRB5_NT_PRINCIPAL_NAME`)
pub static GSS_KRB5_NT_PRINCIPAL_NAME: StaticOid =
    StaticOid::new(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01");

// Loading

/// Environment variable naming the GSS-API library to load instead of the
/// platform defaults (a path, or a soname the dynamic loader can find)
pub const LIBRARY_ENV: &str = "KERBSEC_GSSAPI_LIBRARY";

/// Libraries to try, in order, when [`LIBRARY_ENV`] is unset
#[cfg(target_os = "linux")]
const DEFAULT_LIBRARIES: &[&str] = &["libgssapi_krb5.so.2", "libgssapi.so.3"];
#[cfg(target_os = "macos")]
const DEFAULT_LIBRARIES: &[&str] = &["/System/Library/Frameworks/GSS.framework/GSS"];
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const DEFAULT_LIBRARIES: &[&str] = &["libgssapi_krb5.so.2", "libgssapi.so.3", "libgssapi.so"];

static GSS_API: OnceLock<Result<GssApi, String>> = OnceLock::new();

/// The loaded GSS-API library, loading it on first use
///
/// # Errors
///
/// Says which libraries were tried and why each failed to load, or which
/// required function the loaded one lacks.
pub fn api() -> Result<&'static GssApi, &'static str> {
    GSS_API.get_or_init(load).as_ref().map_err(String::as_str)
}

fn load() -> Result<GssApi, String> {
    let candidates: Vec<OsString> = std::env::var_os(LIBRARY_ENV).map_or_else(
        || DEFAULT_LIBRARIES.iter().map(OsString::from).collect(),
        |library| vec![library],
    );
    let mut failures = Vec::new();
    for candidate in &candidates {
        // SAFETY: loading runs the library's initializers. These are the system
        // GSS-API implementations (or the one the user named), which are made to
        // be loaded into any process.
        match unsafe { Library::new(candidate) } {
            // SAFETY: the library is a GSS-API implementation, so its functions
            // have the RFC 2744 signatures declared below.
            Ok(library) => {
                return unsafe { GssApi::resolve(library) }
                    .map_err(|missing| format!("{} lacks {missing}", candidate.to_string_lossy()))
            }
            Err(e) => {
                // libloading's message is generic ("dlopen failed"); the loader's
                // own text is the source.
                let reason = std::error::Error::source(&e)
                    .map_or_else(|| e.to_string(), ToString::to_string);
                failures.push(format!("{}: {reason}", candidate.to_string_lossy()));
            }
        }
    }
    Err(format!(
        "no GSS-API library could be loaded ({}); install MIT Kerberos \
         (libgssapi-krb5-2 on Debian/Ubuntu, krb5-libs on Fedora/RHEL) or set {LIBRARY_ENV}",
        failures.join("; ")
    ))
}

/// Declares the GSS-API functions: the table [`GssApi`] holds, how it is filled
/// from the library, and a `gss_*` function with the C signature for each.
macro_rules! gss_api {
    (
        required {
            $( $(#[$attr:meta])* fn $name:ident($($arg:ident: $ty:ty),* $(,)?); )*
        }
        optional {
            $( $(#[$oattr:meta])* fn $oname:ident($($oarg:ident: $oty:ty),* $(,)?); )*
        }
    ) => {
        /// The loaded GSS-API library and the functions kerbsec calls
        pub struct GssApi {
            $( $name: unsafe extern "C" fn($($ty),*) -> OM_uint32, )*
            $( $oname: Option<unsafe extern "C" fn($($oty),*) -> OM_uint32>, )*
            // Never unloaded: the function pointers above point into it.
            _library: Library,
        }

        impl GssApi {
            /// Look up every function in `library`; `Err` names a missing required one.
            ///
            /// # Safety
            ///
            /// `library` must be a GSS-API implementation, so that the symbols have
            /// the signatures declared here.
            unsafe fn resolve(library: Library) -> Result<Self, &'static str> {
                Ok(Self {
                    $(
                        $name: *library
                            .get::<unsafe extern "C" fn($($ty),*) -> OM_uint32>(stringify!($name))
                            .map_err(|_| stringify!($name))?,
                    )*
                    $(
                        $oname: library
                            .get::<unsafe extern "C" fn($($oty),*) -> OM_uint32>(stringify!($oname))
                            .ok()
                            .map(|f| *f),
                    )*
                    _library: library,
                })
            }
        }

        $(
            $(#[$attr])*
            ///
            /// Returns [`GSS_S_UNAVAILABLE`] if the GSS-API library could not be loaded.
            ///
            /// # Safety
            ///
            /// As for the C function: every pointer must be valid for the reads and
            /// writes GSS-API makes through it.
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn $name($($arg: $ty),*) -> OM_uint32 {
                match api() {
                    Ok(gss) => (gss.$name)($($arg),*),
                    Err(_) => GSS_S_UNAVAILABLE,
                }
            }
        )*

        $(
            $(#[$oattr])*
            ///
            /// Returns [`GSS_S_UNAVAILABLE`] if the GSS-API library could not be
            /// loaded or does not provide this function.
            ///
            /// # Safety
            ///
            /// As for the C function: every pointer must be valid for the reads and
            /// writes GSS-API makes through it.
            #[allow(clippy::too_many_arguments)]
            pub unsafe fn $oname($($oarg: $oty),*) -> OM_uint32 {
                match api().ok().and_then(|gss| gss.$oname) {
                    Some(f) => f($($oarg),*),
                    None => GSS_S_UNAVAILABLE,
                }
            }
        )*
    };
}

gss_api! {
    required {
        /// Import a name (`gss_import_name`)
        fn gss_import_name(
            minor_status: *mut OM_uint32,
            input_name_buffer: gss_buffer_t,
            input_name_type: gss_OID,
            output_name: *mut gss_name_t,
        );

        /// Release a GSS-API name
        fn gss_release_name(minor_status: *mut OM_uint32, name: *mut gss_name_t);

        /// Acquire credentials, e.g. the default initiator credentials from the
        /// ticket cache (`gss_acquire_cred`)
        fn gss_acquire_cred(
            minor_status: *mut OM_uint32,
            desired_name: gss_name_t,
            time_req: OM_uint32,
            desired_mechs: gss_OID_set,
            cred_usage: gss_cred_usage_t,
            output_cred_handle: *mut gss_cred_id_t,
            actual_mechs: *mut gss_OID_set,
            time_rec: *mut OM_uint32,
        );

        /// Release a credential handle
        fn gss_release_cred(minor_status: *mut OM_uint32, cred_handle: *mut gss_cred_id_t);

        /// One initiator leg of context establishment (`gss_init_sec_context`)
        fn gss_init_sec_context(
            minor_status: *mut OM_uint32,
            initiator_cred_handle: gss_cred_id_t,
            context_handle: *mut gss_ctx_id_t,
            target_name: gss_name_t,
            mech_type: gss_OID,
            req_flags: OM_uint32,
            time_req: OM_uint32,
            input_chan_bindings: gss_channel_bindings_t,
            input_token: gss_buffer_t,
            actual_mech_type: *mut gss_OID,
            output_token: gss_buffer_t,
            ret_flags: *mut OM_uint32,
            time_rec: *mut OM_uint32,
        );

        /// One acceptor leg of context establishment (`gss_accept_sec_context`)
        fn gss_accept_sec_context(
            minor_status: *mut OM_uint32,
            context_handle: *mut gss_ctx_id_t,
            acceptor_cred_handle: gss_cred_id_t,
            input_token_buffer: gss_buffer_t,
            input_chan_bindings: gss_channel_bindings_t,
            src_name: *mut gss_name_t,
            mech_type: *mut gss_OID,
            output_token: gss_buffer_t,
            ret_flags: *mut OM_uint32,
            time_rec: *mut OM_uint32,
            delegated_cred_handle: *mut gss_cred_id_t,
        );

        /// Delete a security context
        fn gss_delete_sec_context(
            minor_status: *mut OM_uint32,
            context_handle: *mut gss_ctx_id_t,
            output_token: gss_buffer_t,
        );

        /// Inquire about a security context
        ///
        /// Returns information about a security context, including the
        /// negotiated flags, which say what protection was actually agreed
        /// (e.g. whether delegation succeeded).
        fn gss_inquire_context(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            src_name: *mut gss_name_t,
            targ_name: *mut gss_name_t,
            lifetime_rec: *mut OM_uint32,
            mech_type: *mut gss_OID,
            ctx_flags: *mut OM_uint32,
            locally_initiated: *mut c_int,
            open: *mut c_int,
        );

        /// Query the maximum input size whose wrapped output fits in
        /// `req_output_size` (`gss_wrap_size_limit`)
        fn gss_wrap_size_limit(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            conf_req_flag: c_int,
            qop_req: gss_qop_t,
            req_output_size: OM_uint32,
            max_input_size: *mut OM_uint32,
        );

        /// Wrap (sign/encrypt) a message into a single token (`gss_wrap`)
        ///
        /// `conf_state` reports whether confidentiality was actually applied, which
        /// may be false even when `conf_req_flag` was set.
        fn gss_wrap(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            conf_req_flag: c_int,
            qop_req: gss_qop_t,
            input_message_buffer: gss_buffer_t,
            conf_state: *mut c_int,
            output_message_buffer: gss_buffer_t,
        );

        /// Verify and/or decrypt a wrapped token (`gss_unwrap`)
        ///
        /// `conf_state` reports whether the token was encrypted.
        fn gss_unwrap(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            input_message_buffer: gss_buffer_t,
            output_message_buffer: gss_buffer_t,
            conf_state: *mut c_int,
            qop_state: *mut gss_qop_t,
        );

        /// Compute a MIC (integrity token) over a message (`gss_get_mic`)
        fn gss_get_mic(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            qop_req: gss_qop_t,
            message_buffer: gss_buffer_t,
            message_token: gss_buffer_t,
        );

        /// Check a MIC over a message (`gss_verify_mic`)
        fn gss_verify_mic(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            message_buffer: gss_buffer_t,
            token_buffer: gss_buffer_t,
            qop_state: *mut gss_qop_t,
        );

        /// Display a GSS-API status code as text (`gss_display_status`)
        ///
        /// `status_type` is `GSS_C_GSS_CODE` or `GSS_C_MECH_CODE`; call again while
        /// `message_context` is non-zero for further messages.
        fn gss_display_status(
            minor_status: *mut OM_uint32,
            status_value: OM_uint32,
            status_type: c_int,
            mech_type: gss_OID,
            message_context: *mut OM_uint32,
            status_string: gss_buffer_t,
        );

        /// Release a buffer GSS-API allocated
        fn gss_release_buffer(minor_status: *mut OM_uint32, buffer: gss_buffer_t);

        /// Create an empty OID set
        fn gss_create_empty_oid_set(minor_status: *mut OM_uint32, oid_set: *mut gss_OID_set);

        /// Add an OID to a set
        fn gss_add_oid_set_member(
            minor_status: *mut OM_uint32,
            member_oid: gss_OID,
            oid_set: *mut gss_OID_set,
        );

        /// Release an OID set
        fn gss_release_oid_set(minor_status: *mut OM_uint32, set: *mut gss_OID_set);
    }
    optional {
        /// Wrap (sign/encrypt) message data in IOV buffers (`gss_wrap_iov`; MIT
        /// and Heimdal, not exported by Apple's GSS.framework)
        ///
        /// Separate header, data and trailer buffers allow DCE/RPC framing.
        fn gss_wrap_iov(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            conf_req_flag: c_int,
            qop_req: gss_qop_t,
            conf_state: *mut c_int,
            iov: gss_iov_buffer_t,
            iov_count: c_int,
        );

        /// Verify and/or decrypt message data protected with `gss_wrap_iov`
        fn gss_unwrap_iov(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            conf_state: *mut c_int,
            qop_state: *mut gss_qop_t,
            iov: gss_iov_buffer_t,
            iov_count: c_int,
        );

        /// Fill in the `HEADER`, `PADDING` and `TRAILER` lengths `gss_wrap_iov`
        /// needs for the given `DATA` and `SIGN_ONLY` buffers
        fn gss_wrap_iov_length(
            minor_status: *mut OM_uint32,
            context_handle: gss_ctx_id_t,
            conf_req_flag: c_int,
            qop_req: gss_qop_t,
            conf_state: *mut c_int,
            iov: gss_iov_buffer_t,
            iov_count: c_int,
        );
    }
}

/// Whether DCE/RPC IOV protection is available
///
/// Needs Linux, the `iov` feature, and a GSS-API library with the IOV functions
/// (MIT Kerberos and Heimdal have them; Apple's GSS.framework does not export them).
#[must_use]
#[allow(clippy::missing_const_for_fn)] // only const where it is always false
pub fn has_iov_support() -> bool {
    #[cfg(all(target_os = "linux", feature = "iov"))]
    {
        api().is_ok_and(|gss| {
            gss.gss_wrap_iov.is_some()
                && gss.gss_unwrap_iov.is_some()
                && gss.gss_wrap_iov_length.is_some()
        })
    }
    #[cfg(not(all(target_os = "linux", feature = "iov")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_oids_hold_the_der_values() {
        // SAFETY: the descriptors point at static byte strings of these lengths.
        let (mech, name) = unsafe {
            let mech = &*GSS_MECH_KRB5.as_ptr();
            let name = &*GSS_KRB5_NT_PRINCIPAL_NAME.as_ptr();
            (
                std::slice::from_raw_parts(mech.elements.cast::<u8>(), mech.length as usize),
                std::slice::from_raw_parts(name.elements.cast::<u8>(), name.length as usize),
            )
        };
        assert_eq!(mech, b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");
        assert_eq!(
            &name[..9],
            mech,
            "the name type sits under the mechanism OID"
        );
        assert_eq!(name[9], 1);
    }

    #[test]
    fn error_check_ignores_supplementary_bits() {
        assert!(!is_error(GSS_S_COMPLETE));
        assert!(!is_error(GSS_S_CONTINUE_NEEDED));
        assert!(is_error(GSS_S_UNAVAILABLE));
        assert!(is_error(GSS_S_UNAVAILABLE | 0x2));
    }
}
