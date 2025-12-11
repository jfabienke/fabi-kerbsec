//! Safe wrappers for GSS-API IOV operations
//!
//! This module provides safe Rust wrappers around the GSS-API IOV
//! (Input/Output Vector) functions for zero-copy message protection.
//!
//! # Platform Support
//!
//! - **Linux**: Full native IOV support via `gss_wrap_iov`/`gss_unwrap_iov`
//! - **macOS/Other**: Falls back to regular `gss_wrap`/`gss_unwrap` with
//!   estimated header/trailer sizes

use crate::error::{Error, Result};
use crate::security::IovWrap;
use bytes::Bytes;
use libgssapi::context::ClientCtx;
#[cfg(target_os = "linux")]
use crate::ffi;
#[cfg(target_os = "linux")]
use std::ptr;
#[cfg(target_os = "linux")]
use std::slice;

#[cfg(all(feature = "trace", target_os = "linux"))]
use tracing::{debug, error};

#[cfg(feature = "trace")]
use tracing::{instrument, warn};

/// Maximum sizes for IOV buffers based on RFC 4121 and common cipher suites.
/// These are generous upper bounds to handle all supported encryption types.
#[cfg(target_os = "linux")]
mod buffer_sizes {
    /// Maximum GSS header size (token header + encryption IV)
    /// AES-256 with 16-byte IV + GSS header overhead
    pub const MAX_HEADER_SIZE: usize = 256;

    /// Maximum padding size for block ciphers (AES block size = 16)
    pub const MAX_PADDING_SIZE: usize = 256;

    /// Maximum trailer size (checksum/MIC)
    /// SHA-384 based checksums can be up to 48 bytes + overhead
    pub const MAX_TRAILER_SIZE: usize = 256;
}

/// Get the raw GSS context handle from `ClientCtx` using unsafe memory access.
///
/// # Safety
///
/// This function relies on the internal layout of `libgssapi::context::ClientCtx`.
/// The following invariants must hold:
///
/// 1. `ClientCtx` must have `gss_ctx_id_t` as its first field
/// 2. `ClientCtx` must be `#[repr(C)]` or have a compatible layout
/// 3. The context must be initialized (not in an invalid state)
///
/// This is verified against `libgssapi` version 0.9.1. If you upgrade the
/// dependency, verify that the struct layout hasn't changed.
///
/// # Panics
///
/// Panics if the extracted context handle is null, which indicates either:
/// - The context was not properly initialized
/// - The struct layout assumption is incorrect
#[cfg(target_os = "linux")]
unsafe fn get_raw_ctx_handle(ctx: &ClientCtx) -> ffi::gss_ctx_id_t {
    // ClientCtx in libgssapi 0.9.1 has the following layout:
    // pub struct ClientCtx {
    //     ctx: gss_ctx_id_t,  // First field - this is what we need
    //     cred: Option<Cred>,
    //     target: Name,
    //     flags: CtxFlags,
    //     mech: Option<&'static Oid>,
    // }
    //
    // We extract the first field by treating the struct pointer as a pointer
    // to gss_ctx_id_t. This works because:
    // - gss_ctx_id_t is a pointer type (no alignment issues)
    // - It's the first field (offset 0)
    let ctx_ptr = ctx as *const ClientCtx as *const ffi::gss_ctx_id_t;
    let handle = ptr::read(ctx_ptr);

    // Validate that we got a non-null handle
    assert!(
        !handle.is_null(),
        "GSS context handle is null - context may not be initialized or struct layout changed"
    );

    handle
}

/// Wrap a PDU using GSS IOV for zero-copy operation
///
/// This is the real IOV implementation that avoids data copying on Linux.
/// On other platforms, it falls back to regular `gss_wrap` with estimated
/// header/trailer separation.
///
/// # Errors
///
/// Returns an error if:
/// - The GSS context is not established
/// - The wrap operation fails
/// - Buffer allocation fails
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::iov",
    level = "debug",
    skip(ctx),
    fields(conf_req, pdu_len = pdu.len())
))]
pub fn wrap_iov_real(
    ctx: &mut ClientCtx,
    pdu: &[u8],
    conf_req: bool,
) -> Result<IovWrap> {
    // IOV is only available on Linux - use fallback on other platforms
    #[cfg(not(target_os = "linux"))]
    {
        #[cfg(feature = "trace")]
        warn!(target: "kerbsec::iov", "IOV wrap not available on this platform, using fallback");

        wrap_iov_fallback(ctx, pdu, conf_req)
    }

    #[cfg(target_os = "linux")]
    {
        wrap_iov_native(ctx, pdu, conf_req)
    }
}

/// Native IOV wrap implementation for Linux
#[cfg(target_os = "linux")]
fn wrap_iov_native(
    ctx: &mut ClientCtx,
    pdu: &[u8],
    conf_req: bool,
) -> Result<IovWrap> {
    use buffer_sizes::*;

    // SAFETY: We verify the context handle is non-null in get_raw_ctx_handle
    let ctx_handle = unsafe { get_raw_ctx_handle(ctx) };

    // Create IOV buffers with generous sizes based on RFC 4121
    let mut header_buf = vec![0u8; MAX_HEADER_SIZE];
    let mut data_buf = pdu.to_vec();
    let mut padding_buf = vec![0u8; MAX_PADDING_SIZE];
    let mut trailer_buf = vec![0u8; MAX_TRAILER_SIZE];

    let mut iov_descs = [
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_HEADER,
            buffer: ffi::gss_buffer_desc {
                length: header_buf.len(),
                value: header_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_DATA,
            buffer: ffi::gss_buffer_desc {
                length: data_buf.len(),
                value: data_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_PADDING,
            buffer: ffi::gss_buffer_desc {
                length: padding_buf.len(),
                value: padding_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_TRAILER,
            buffer: ffi::gss_buffer_desc {
                length: trailer_buf.len(),
                value: trailer_buf.as_mut_ptr().cast(),
            },
        },
    ];

    let mut minor_status: ffi::OM_uint32 = 0;
    let mut conf_state: libc::c_int = 0;

    // SAFETY: All buffers are valid and properly sized
    let major_status = unsafe {
        ffi::gss_wrap_iov(
            &mut minor_status,
            ctx_handle,
            i32::from(conf_req),
            ffi::GSS_C_QOP_DEFAULT,
            &mut conf_state,
            iov_descs.as_mut_ptr(),
            iov_descs.len() as libc::c_int,
        )
    };

    if major_status != ffi::GSS_S_COMPLETE {
        #[cfg(feature = "trace")]
        error!(
            target: "kerbsec::iov",
            major = format_args!("{:#x}", major_status),
            minor = format_args!("{:#x}", minor_status),
            "gss_wrap_iov failed"
        );
        return Err(gss_error(major_status, minor_status));
    }

    // Extract the actual used lengths (GSS updates these in-place)
    let header_len = iov_descs[0].buffer.length;
    let payload_len = iov_descs[1].buffer.length;
    let trailer_len = iov_descs[3].buffer.length;

    // Validate that GSS didn't try to write beyond our buffers
    if header_len > MAX_HEADER_SIZE
        || payload_len > data_buf.len()
        || trailer_len > MAX_TRAILER_SIZE
    {
        return Err(Error::Iov(format!(
            "GSS returned unexpected sizes: header={header_len}, payload={payload_len}, trailer={trailer_len}"
        )));
    }

    header_buf.truncate(header_len);
    data_buf.truncate(payload_len);
    trailer_buf.truncate(trailer_len);

    let header = Bytes::from(header_buf);
    let payload = Bytes::from(data_buf);
    let trailer = Bytes::from(trailer_buf);

    #[cfg(feature = "trace")]
    debug!(
        target: "kerbsec::iov",
        conf = (conf_state != 0),
        pdu_len = pdu.len(),
        header_len = header.len(),
        payload_len = payload.len(),
        trailer_len = trailer.len(),
        "wrap_iov completed"
    );

    Ok(IovWrap {
        header,
        payload,
        trailer,
        conf: conf_state != 0,
    })
}

/// Fallback wrap implementation for platforms without IOV support (macOS, etc.)
///
/// Uses regular `gss_wrap` and estimates header/trailer split based on
/// typical GSS token structure.
#[cfg(not(target_os = "linux"))]
fn wrap_iov_fallback(
    ctx: &mut ClientCtx,
    pdu: &[u8],
    conf_req: bool,
) -> Result<IovWrap> {
    use libgssapi::context::SecurityContext;

    // Use regular wrap - this returns the complete wrapped token
    let wrapped = ctx.wrap(conf_req, pdu).map_err(|e| {
        Error::Iov(format!("GSS wrap failed: {e}"))
    })?;

    let wrapped_bytes = wrapped.to_vec();

    // For the fallback, we put everything in the header and leave
    // payload/trailer empty. The caller needs to handle this appropriately.
    // This is because we can't reliably split the token without IOV support.
    //
    // Alternative: We could try to parse the GSS token structure (RFC 4121)
    // but that's fragile and mechanism-dependent.

    #[cfg(feature = "trace")]
    warn!(
        target: "kerbsec::iov",
        wrapped_len = wrapped_bytes.len(),
        "fallback wrap: entire token in header, payload/trailer empty"
    );

    Ok(IovWrap {
        header: Bytes::from(wrapped_bytes),
        payload: Bytes::new(),
        trailer: Bytes::new(),
        conf: conf_req,
    })
}

/// Unwrap a token using GSS IOV
///
/// # Errors
///
/// Returns an error if:
/// - The GSS context is not established
/// - The unwrap operation fails (e.g., integrity check failure)
/// - The token format is invalid
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::iov",
    level = "debug",
    skip(ctx),
    fields(
        header_len = header.len(),
        data_len = data.len(),
        trailer_len = trailer.len()
    )
))]
pub fn unwrap_iov_real(
    ctx: &mut ClientCtx,
    header: &[u8],
    data: &[u8],
    trailer: &[u8],
) -> Result<Vec<u8>> {
    // IOV is only available on Linux - use fallback on other platforms
    #[cfg(not(target_os = "linux"))]
    {
        #[cfg(feature = "trace")]
        warn!(target: "kerbsec::iov", "IOV unwrap not available on this platform, using fallback");

        unwrap_iov_fallback(ctx, header, data, trailer)
    }

    #[cfg(target_os = "linux")]
    {
        unwrap_iov_native(ctx, header, data, trailer)
    }
}

/// Native IOV unwrap implementation for Linux
#[cfg(target_os = "linux")]
fn unwrap_iov_native(
    ctx: &mut ClientCtx,
    header: &[u8],
    data: &[u8],
    trailer: &[u8],
) -> Result<Vec<u8>> {
    // SAFETY: We verify the context handle is non-null in get_raw_ctx_handle
    let ctx_handle = unsafe { get_raw_ctx_handle(ctx) };

    // Reconstruct IOV buffers from the provided slices
    let mut header_buf = header.to_vec();
    let mut data_buf = data.to_vec();
    let mut padding_buf: Vec<u8> = Vec::new(); // Padding is typically empty for unwrap
    let mut trailer_buf = trailer.to_vec();

    let mut iov_descs = [
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_HEADER,
            buffer: ffi::gss_buffer_desc {
                length: header_buf.len(),
                value: header_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_DATA,
            buffer: ffi::gss_buffer_desc {
                length: data_buf.len(),
                value: data_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_PADDING,
            buffer: ffi::gss_buffer_desc {
                length: padding_buf.len(),
                value: padding_buf.as_mut_ptr().cast(),
            },
        },
        ffi::gss_iov_buffer_desc {
            type_: ffi::GSS_IOV_BUFFER_TYPE_TRAILER,
            buffer: ffi::gss_buffer_desc {
                length: trailer_buf.len(),
                value: trailer_buf.as_mut_ptr().cast(),
            },
        },
    ];

    let mut minor_status: ffi::OM_uint32 = 0;
    let mut conf_state: libc::c_int = 0;
    let mut qop_state: ffi::gss_qop_t = 0;

    // SAFETY: All buffers are valid and properly initialized
    let major_status = unsafe {
        ffi::gss_unwrap_iov(
            &mut minor_status,
            ctx_handle,
            &mut conf_state,
            &mut qop_state,
            iov_descs.as_mut_ptr(),
            iov_descs.len() as libc::c_int,
        )
    };

    if major_status != ffi::GSS_S_COMPLETE {
        #[cfg(feature = "trace")]
        error!(
            target: "kerbsec::iov",
            major = format_args!("{:#x}", major_status),
            minor = format_args!("{:#x}", minor_status),
            "gss_unwrap_iov failed"
        );
        return Err(gss_error(major_status, minor_status));
    }

    #[cfg(feature = "trace")]
    debug!(
        target: "kerbsec::iov",
        plaintext_len = data_buf.len(),
        conf = (conf_state != 0),
        "unwrap_iov completed"
    );

    // Return the unwrapped data
    Ok(data_buf)
}

/// Fallback unwrap implementation for platforms without IOV support
#[cfg(not(target_os = "linux"))]
fn unwrap_iov_fallback(
    ctx: &mut ClientCtx,
    header: &[u8],
    data: &[u8],
    trailer: &[u8],
) -> Result<Vec<u8>> {
    use libgssapi::context::SecurityContext;

    // Reconstruct the complete token by concatenating header + data + trailer
    // This is the inverse of what wrap_iov_fallback produces
    let mut token = Vec::with_capacity(header.len() + data.len() + trailer.len());
    token.extend_from_slice(header);
    token.extend_from_slice(data);
    token.extend_from_slice(trailer);

    // Use regular unwrap
    let unwrapped = ctx.unwrap(&token).map_err(|e| {
        Error::Iov(format!("GSS unwrap failed: {e}"))
    })?;

    #[cfg(feature = "trace")]
    warn!(
        target: "kerbsec::iov",
        token_len = token.len(),
        unwrapped_len = unwrapped.len(),
        "fallback unwrap: reassembled token"
    );

    Ok(unwrapped.to_vec())
}

/// Get accurate wrap size limit using GSS-API
///
/// Given a maximum output (wrapped) size, calculates the maximum input
/// message size that can be wrapped without exceeding the limit.
///
/// # Arguments
///
/// * `ctx` - The GSS security context
/// * `conf_req` - Whether confidentiality (encryption) is requested
/// * `max_wrapped` - Maximum size of the wrapped output
///
/// # Returns
///
/// Maximum message size that can be wrapped, or an error if the query fails.
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::iov",
    level = "debug",
    skip(ctx),
    fields(conf_req, max_wrapped)
))]
pub fn wrap_size_limit_real(
    ctx: &ClientCtx,
    conf_req: bool,
    max_wrapped: usize,
) -> Result<usize> {
    // Use conservative estimates on non-Linux platforms
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ctx; // Suppress unused variable warning
        // Return conservative estimate based on typical GSS overhead
        Ok(if conf_req {
            max_wrapped.saturating_sub(60) // Privacy: header + encryption padding + trailer
        } else {
            max_wrapped.saturating_sub(32) // Integrity: header + MIC
        })
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: We verify the context handle is non-null in get_raw_ctx_handle
        let ctx_handle = unsafe { get_raw_ctx_handle(ctx) };

        let mut minor_status: ffi::OM_uint32 = 0;
        let mut max_input_size: ffi::OM_uint32 = 0;

        // SAFETY: All pointers are valid
        let major_status = unsafe {
            ffi::gss_wrap_size_limit(
                &mut minor_status,
                ctx_handle,
                i32::from(conf_req),
                ffi::GSS_C_QOP_DEFAULT,
                max_wrapped as ffi::OM_uint32,
                &mut max_input_size,
            )
        };

        if major_status != ffi::GSS_S_COMPLETE {
            #[cfg(feature = "trace")]
            error!(
                target: "kerbsec::iov",
                major = format_args!("{:#x}", major_status),
                minor = format_args!("{:#x}", minor_status),
                "gss_wrap_size_limit failed"
            );
            return Err(gss_error(major_status, minor_status));
        }

        #[cfg(feature = "trace")]
        debug!(
            target: "kerbsec::iov",
            max_input = max_input_size,
            "wrap_size_limit calculated"
        );

        Ok(max_input_size as usize)
    }
}

/// Convert GSS error to our Error type
#[cfg(target_os = "linux")]
fn gss_error(major: ffi::OM_uint32, minor: ffi::OM_uint32) -> Error {
    let text = display_gss_status(major, minor);

    #[cfg(feature = "trace")]
    error!(
        target: "kerbsec::iov",
        major = format_args!("{:#x}", major),
        minor = format_args!("{:#x}", minor),
        %text,
        "GSS IOV error"
    );

    Error::Gss { major, minor, text }
}

/// Get human-readable error message from GSS status codes
#[cfg(target_os = "linux")]
fn display_gss_status(major: ffi::OM_uint32, minor: ffi::OM_uint32) -> String {
    let mut messages = Vec::new();

    // Display major status
    if let Some(msg) = display_status_code(major, ffi::GSS_C_GSS_CODE) {
        messages.push(msg);
    }

    // Display minor status
    if minor != 0 {
        if let Some(msg) = display_status_code(minor, ffi::GSS_C_MECH_CODE) {
            messages.push(msg);
        }
    }

    if messages.is_empty() {
        format!("GSS error {:#x}/{:#x}", major, minor)
    } else {
        messages.join(": ")
    }
}

/// Display a single status code
///
/// Converts a GSS-API status code to a human-readable string.
/// Properly releases the GSS buffer to avoid memory leaks.
#[cfg(target_os = "linux")]
fn display_status_code(code: ffi::OM_uint32, status_type: libc::c_int) -> Option<String> {
    // SAFETY: All pointers are valid and properly initialized
    unsafe {
        let mut minor_status: ffi::OM_uint32 = 0;
        let mut message_context: ffi::OM_uint32 = 0;
        let mut status_string = ffi::gss_buffer_desc {
            length: 0,
            value: ptr::null_mut(),
        };

        let major = ffi::gss_display_status(
            &mut minor_status,
            code,
            status_type,
            ffi::GSS_C_NO_OID,
            &mut message_context,
            &mut status_string,
        );

        if major != ffi::GSS_S_COMPLETE {
            // No buffer was allocated on failure, nothing to release
            return None;
        }

        // Extract the message if the buffer contains valid data
        let result = if !status_string.value.is_null() && status_string.length > 0 {
            let bytes = slice::from_raw_parts(
                status_string.value.cast::<u8>(),
                status_string.length,
            );
            Some(String::from_utf8_lossy(bytes).into_owned())
        } else {
            None
        };

        // IMPORTANT: Always release the buffer, even if we didn't extract a message.
        // GSS may have allocated memory that needs to be freed.
        // This fixes the memory leak when status_string.value is null or length is 0.
        ffi::gss_release_buffer(&mut minor_status, &mut status_string);

        result
    }
}
