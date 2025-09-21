//! Error types for kerbsec operations
//!
//! This module defines the error types used throughout kerbsec.
//! All errors implement standard error traits and provide detailed
//! context about what went wrong during Kerberos operations.

use thiserror::Error;

/// Errors that can occur during Kerberos operations
#[derive(Error, Debug)]
pub enum Error {
    /// GSS-API errors with major/minor codes
    #[error("GSS error: {major:#x}/{minor:#x}: {text}")]
    Gss {
        /// GSS major status code
        major: u32,
        /// GSS minor status code
        minor: u32,
        /// Human-readable error description
        text: String,
    },

    /// DNS resolution failures
    #[cfg(feature = "dns")]
    #[error("DNS error: {0}")]
    Dns(#[from] anyhow::Error),

    /// IP target requires explicit SPN override
    #[error("Target is an IP address; SPN override is required")]
    IpTargetRequiresSpnOverride,

    /// DNS canonicalization failed
    #[error("Could not canonicalize FQDN for {0}")]
    CanonicalizationFailed(String),

    /// GSS context not established
    #[error("Handshake not established")]
    NotEstablished,

    /// Token format error
    #[error("Invalid token shape")]
    TokenShape,

    /// IOV operations not available
    #[error("IOV operation failed: {0}")]
    Iov(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// System I/O errors
    #[error("System error: {0}")]
    System(#[from] std::io::Error),

    /// Credential cache errors
    #[cfg(feature = "ccache")]
    #[error("Credential cache error: {text}")]
    Ccache {
        /// Human-readable error description
        text: String,
    },

    /// Channel binding errors
    #[cfg(feature = "channel-bindings")]
    #[error("Channel binding error: {0}")]
    ChannelBinding(String),

    /// No delegated credentials available
    #[error("No delegated credentials available")]
    NoDelegatedCredentials,

    /// Feature not yet implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// Result type alias for operations that may return an Error
pub type Result<T> = std::result::Result<T, Error>;
