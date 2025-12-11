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

    // =========================================================================
    // Windows AD specific errors
    // =========================================================================
    /// Clock skew error - client and server clocks differ by more than allowed
    ///
    /// Windows AD default: 5 minutes (300 seconds).
    /// This error occurs when the time difference between client and KDC
    /// exceeds the maximum allowed skew.
    ///
    /// # Resolution
    /// - Sync client clock with NTP server
    /// - Check domain controller time synchronization
    /// - Consider increasing `MaxClockSkew` via Group Policy (not recommended)
    #[error("Clock skew too great: client and server clocks differ by more than {max_skew_secs} seconds")]
    ClockSkew {
        /// Maximum allowed skew in seconds (typically 300)
        max_skew_secs: u32,
    },

    /// SPN not found in Active Directory
    ///
    /// The Service Principal Name (SPN) is not registered for the target
    /// service in Active Directory.
    ///
    /// # Resolution
    /// - Register SPN using `setspn -S service/hostname account`
    /// - Check for duplicate SPNs: `setspn -X`
    /// - Verify DNS name matches SPN hostname
    #[error("SPN not found: {spn} (check AD SPN registration with 'setspn -L account')")]
    SpnNotFound {
        /// The SPN that was not found
        spn: String,
    },

    /// Unsupported encryption type
    ///
    /// The KDC and client could not agree on an encryption type.
    /// This typically happens when:
    /// - Client only supports AES but service account only has RC4 keys
    /// - Domain functional level doesn't support requested encryption
    #[error("No common encryption type: client supports {client_etypes:?}, server requires {server_etypes:?}")]
    EncryptionTypeMismatch {
        /// Encryption types supported by client
        client_etypes: Vec<u16>,
        /// Encryption types required by server (if known)
        server_etypes: Vec<u16>,
    },

    /// Delegation was requested but not granted by the KDC
    ///
    /// This can occur when:
    /// - Service account not trusted for delegation in AD
    /// - Constrained delegation not configured for target service
    /// - User account marked as "sensitive and cannot be delegated"
    #[error("Delegation not granted: {reason}")]
    DelegationDenied {
        /// Reason delegation was denied
        reason: String,
    },

    /// Pre-authentication failed (wrong password or keytab)
    #[error("Pre-authentication failed: {0}")]
    PreAuthFailed(String),

    /// Ticket expired - need to re-authenticate
    #[error("Kerberos ticket expired, re-authentication required")]
    TicketExpired,

    /// KDC unreachable
    #[error("Cannot contact KDC for realm {realm}: {details}")]
    KdcUnreachable {
        /// The Kerberos realm
        realm: String,
        /// Additional details
        details: String,
    },
}

/// Result type alias for operations that may return an Error
pub type Result<T> = std::result::Result<T, Error>;
