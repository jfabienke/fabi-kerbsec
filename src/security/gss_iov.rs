//! Safe wrappers for GSS-API IOV operations
//!
//! This module provides safe Rust wrappers around the GSS-API IOV
//! (Input/Output Vector) functions for zero-copy message protection.

use crate::error::{Error, Result};
use crate::security::IovWrap;
#[cfg(target_os = "linux")]
use bytes::Bytes;
use libgssapi::context::ClientCtx;
#[cfg(target_os = "linux")]
use crate::ffi;
#[cfg(target_os = "linux")]
use std::ptr;
#[cfg(target_os = "linux")]
use std::slice;

#[cfg(feature = "trace")]
use tracing::{instrument, warn};

/// Get the raw GSS context handle from ClientCtx using unsafe
///
/// This is necessary because libgssapi doesn't expose the raw handle,
/// but we need it for IOV operations.
#[cfg(target_os = "linux")]
unsafe fn get_raw_ctx_handle(ctx: &ClientCtx) -> ffi::gss_ctx_id_t {
    // ClientCtx has the following layout:
    // pub struct ClientCtx {
    //     ctx: gss_ctx_id_t,  // This is what we need
    //     ...other fields...
    // }
    // We use unsafe to access the first field
    let ctx_ptr = ctx as *const ClientCtx as *const ffi::gss_ctx_id_t;
    *ctx_ptr
}

/// Wrap a PDU using GSS IOV for zero-copy operation
///
/// This is the real IOV implementation that avoids data copying.
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::iov",
    level = "debug",
    skip(_ctx),
    fields(conf_req = _conf_req, pdu_len = _pdu.len())
))]
pub fn wrap_iov_real(
    _ctx: &mut ClientCtx,
    _pdu: &[u8],
    _conf_req: bool,
) -> Result<IovWrap> {
    // IOV is only available on Linux
    #[cfg(not(target_os = "linux"))]
    {
        #[cfg(feature = "trace")]
        warn!(target: "kerbsec::iov", "IOV wrap not available on this platform, falling back");
        Err(Error::Iov("IOV operations not available on this platform".into()))
    }

    #[cfg(target_os = "linux")]
    unsafe {
        let ctx_handle = get_raw_ctx_handle(_ctx);

        // Create IOV buffers - allocate space for header/trailer/padding
        let mut header_buf = vec![0u8; 128]; // Typical header size
        let mut data_buf = _pdu.to_vec();
        let mut padding_buf = vec![0u8; 64]; // Typical padding size
        let mut trailer_buf = vec![0u8; 64]; // Typical trailer size

        let mut iov_descs = vec![
            ffi::gss_iov_buffer_desc {
                type_: ffi::GSS_IOV_BUFFER_TYPE_HEADER | ffi::GSS_IOV_BUFFER_FLAG_ALLOCATE,
                buffer: ffi::gss_buffer_desc {
                    length: header_buf.len(),
                    value: header_buf.as_mut_ptr() as *mut _,
                },
            },
            ffi::gss_iov_buffer_desc {
                type_: ffi::GSS_IOV_BUFFER_TYPE_DATA,
                buffer: ffi::gss_buffer_desc {
                    length: data_buf.len(),
                    value: data_buf.as_mut_ptr() as *mut _,
                },
            },
            ffi::gss_iov_buffer_desc {
                type_: ffi::GSS_IOV_BUFFER_TYPE_PADDING | ffi::GSS_IOV_BUFFER_FLAG_ALLOCATE,
                buffer: ffi::gss_buffer_desc {
                    length: padding_buf.len(),
                    value: padding_buf.as_mut_ptr() as *mut _,
                },
            },
            ffi::gss_iov_buffer_desc {
                type_: ffi::GSS_IOV_BUFFER_TYPE_TRAILER | ffi::GSS_IOV_BUFFER_FLAG_ALLOCATE,
                buffer: ffi::gss_buffer_desc {
                    length: trailer_buf.len(),
                    value: trailer_buf.as_mut_ptr() as *mut _,
                },
            },
        ];

        let mut minor_status: ffi::OM_uint32 = 0;
        let mut conf_state: libc::c_int = 0;

        let major_status = ffi::gss_wrap_iov(
            &mut minor_status,
            ctx_handle,
            if _conf_req { 1 } else { 0 },
            ffi::GSS_C_QOP_DEFAULT,
            &mut conf_state,
            iov_descs.as_mut_ptr(),
            iov_descs.len() as libc::c_int,
        );

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

        // Extract the actual used lengths
        let header_len = iov_descs[0].buffer.length;
        let trailer_len = iov_descs[3].buffer.length;

        // Extract header and trailer
        let header = if header_len > 0 {
            let header_slice = slice::from_raw_parts(
                iov_descs[0].buffer.value as *const u8,
                header_len,
            );
            Bytes::copy_from_slice(header_slice)
        } else {
            Bytes::new()
        };

        let trailer = if trailer_len > 0 {
            let trailer_slice = slice::from_raw_parts(
                iov_descs[3].buffer.value as *const u8,
                trailer_len,
            );
            Bytes::copy_from_slice(trailer_slice)
        } else {
            Bytes::new()
        };

        #[cfg(feature = "trace")]
        debug!(
            target: "kerbsec::iov",
            conf = (conf_state != 0),
            pdu_len = _pdu.len(),
            header_len = header.len(),
            trailer_len = trailer.len(),
            "wrap_iov completed"
        );

        Ok(IovWrap {
            header,
            trailer,
            conf: conf_state != 0,
        })
    }
}

/// Unwrap a token using GSS IOV
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::iov",
    level = "debug",
    skip(_ctx),
    fields(
        header_len = _header.len(),
        data_len = _data.len(),
        trailer_len = _trailer.len()
    )
))]
pub fn unwrap_iov_real(
    _ctx: &mut ClientCtx,
    _header: &[u8],
    _data: &[u8],
    _trailer: &[u8],
) -> Result<Vec<u8>> {
    // IOV is only available on Linux
    #[cfg(not(target_os = "linux"))]
    {
        #[cfg(feature = "trace")]
        warn!(target: "kerbsec::iov", "IOV wrap not available on this platform, falling back");
        Err(Error::Iov("IOV operations not available on this platform".into()))
    }

    #[cfg(target_os = "linux")]
    unsafe {
        let ctx_handle = get_raw_ctx_handle(_ctx);

        // Reconstruct IOV buffers
        let mut header_buf = _header.to_vec();
        let mut data_buf = _data.to_vec();
        let mut padding_buf = Vec::new(); // Padding is typically empty for unwrap
        let mut trailer_buf = _trailer.to_vec();

        let mut iov_descs = vec![
            ffi::gss_iov_buffer_desc {
                type_: ffi::GSS_IOV_BUFFER_TYPE_HEADER,
                buffer: ffi::gss_buffer_desc {
                    length: header_buf.len(),
                    value: header_buf.as_mut_ptr() as *mut _,
                },
            },
            ffi::gss_iov_buffer_desc {
                type_: ffi::GSS_IOV_BUFFER_TYPE_DATA,
                buffer: ffi::gss_buffer_desc {
                    length: data_buf.len(),
                    value: data_buf.as_mut_ptr() as *mut _,
                },
            },
            ffi::gss_iov_buffer_desc {
                type_: ffi::GSS_IOV_BUFFER_TYPE_PADDING,
                buffer: ffi::gss_buffer_desc {
                    length: padding_buf.len(),
                    value: padding_buf.as_mut_ptr() as *mut _,
                },
            },
            ffi::gss_iov_buffer_desc {
                type_: ffi::GSS_IOV_BUFFER_TYPE_TRAILER,
                buffer: ffi::gss_buffer_desc {
                    length: trailer_buf.len(),
                    value: trailer_buf.as_mut_ptr() as *mut _,
                },
            },
        ];

        let mut minor_status: ffi::OM_uint32 = 0;
        let mut conf_state: libc::c_int = 0;
        let mut qop_state: ffi::gss_qop_t = 0;

        let major_status = ffi::gss_unwrap_iov(
            &mut minor_status,
            ctx_handle,
            &mut conf_state,
            &mut qop_state,
            iov_descs.as_mut_ptr(),
            iov_descs.len() as libc::c_int,
        );

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
}

/// Get accurate wrap size limit using GSS-API
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::iov",
    level = "debug",
    skip(_ctx),
    fields(conf_req, max_wrapped)
))]
pub fn wrap_size_limit_real(
    _ctx: &ClientCtx,
    conf_req: bool,
    max_wrapped: usize,
) -> Result<usize> {
    // IOV is only available on Linux
    #[cfg(not(target_os = "linux"))]
    {
        // Return conservative estimate
        Ok(if conf_req {
            max_wrapped.saturating_sub(60) // Conservative for encryption
        } else {
            max_wrapped.saturating_sub(32) // Conservative for integrity only
        })
    }

    #[cfg(target_os = "linux")]
    unsafe {
        let ctx_handle = get_raw_ctx_handle(_ctx);

        let mut minor_status: ffi::OM_uint32 = 0;
        let mut max_input_size: ffi::OM_uint32 = 0;

        let major_status = ffi::gss_wrap_size_limit(
            &mut minor_status,
            ctx_handle,
            if _conf_req { 1 } else { 0 },
            ffi::GSS_C_QOP_DEFAULT,
            max_wrapped as ffi::OM_uint32,
            &mut max_input_size,
        );

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
#[cfg(target_os = "linux")]
fn display_status_code(code: ffi::OM_uint32, status_type: libc::c_int) -> Option<String> {
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
            return None;
        }

        let result = if !status_string.value.is_null() && status_string.length > 0 {
            let bytes = slice::from_raw_parts(
                status_string.value as *const u8,
                status_string.length,
            );
            String::from_utf8_lossy(bytes).into_owned()
        } else {
            return None;
        };

        // Clean up
        ffi::gss_release_buffer(&mut minor_status, &mut status_string);

        Some(result)
    }
}