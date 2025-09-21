//! kerbsec - Minimal MIT-licensed Kerberos (GSS-API) for DCE/RPC on Unix
//!
//! This crate provides a Kerberos RFC 4121 security context for DCE/RPC transports
//! by leveraging the system GSS-API (MIT Kerberos or Heimdal).
//!
//! Transport-agnostic: users handle RPC framing, kerbsec handles GSS tokens.

pub mod config;
pub mod context;
pub mod error;

#[cfg(feature = "dns")]
pub mod dns;

#[cfg(all(unix, feature = "iov"))]
pub mod ffi;

#[cfg(feature = "ccache")]
pub mod ccache;

#[cfg(feature = "channel-bindings")]
pub mod channel_bindings;

pub mod security;

// Re-exports
pub use config::{AuthLevel, ChannelBindings, KerberosConfig, KerberosConfigBuilder};
pub use context::Context;
pub use error::{Error, Result};
pub use security::{IovWrap, Oid, KRB5_MECH_OID};
