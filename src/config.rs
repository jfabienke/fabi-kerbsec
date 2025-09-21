//! Configuration types and builder for Kerberos contexts
//!
//! This module provides the configuration structures needed to establish
//! Kerberos security contexts for DCE/RPC authentication. The primary
//! entry point is [`KerberosConfigBuilder`] which provides a fluent API
//! for constructing configurations with sensible defaults.
//!
//! # Example
//!
//! ```no_run
//! use kerbsec::{KerberosConfig, AuthLevel};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = KerberosConfig::builder()
//!     .realm("CORP.EXAMPLE.COM")
//!     .target_host("server.example.com")
//!     .default_auth(AuthLevel::Privacy)
//!     .build_async()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use std::net::SocketAddr;
use std::time::Duration;

#[cfg(feature = "trace")]
use tracing::{debug, instrument, warn};

/// Authentication protection level for Kerberos/GSS operations
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum AuthLevel {
    /// Message Integrity Code (MIC) only - authenticates but doesn't encrypt
    Integrity,
    /// Seal + MIC - both encrypts and authenticates messages
    #[default]
    Privacy,
}

/// Channel bindings for mutual authentication
///
/// This supports both legacy address-based bindings and modern TLS-based bindings.
/// When the channel-bindings feature is enabled, this wraps the enhanced implementation.
#[derive(Clone, Debug, Default)]
pub struct ChannelBindings {
    /// Address of the context initiator (client)
    pub initiator_addr: Option<SocketAddr>,
    /// Address of the context acceptor (server)
    pub acceptor_addr: Option<SocketAddr>,
    /// Optional application-specific binding data
    pub application_data: Option<Vec<u8>>,

    /// Enhanced TLS channel bindings (when feature enabled)
    #[cfg(feature = "channel-bindings")]
    pub tls_bindings: Option<crate::channel_bindings::ChannelBindings>,
}

impl ChannelBindings {
    /// Create channel bindings from TLS data
    #[cfg(feature = "channel-bindings")]
    #[must_use] pub fn from_tls(tls_bindings: crate::channel_bindings::ChannelBindings) -> Self {
        Self {
            initiator_addr: tls_bindings.initiator_addr,
            acceptor_addr: tls_bindings.acceptor_addr,
            application_data: tls_bindings
                .application_data
                .as_ref()
                .map(|buf| buf.as_ref().to_vec()),
            tls_bindings: Some(tls_bindings),
        }
    }

    /// Get the channel binding data for GSS-API
    #[must_use] pub fn get_gss_data(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "channel-bindings")]
        if let Some(ref tls) = self.tls_bindings {
            if let Some(ref data) = tls.application_data {
                return Some(data.as_ref().to_vec());
            }
        }

        self.application_data.clone()
    }
}

/// Kerberos configuration for GSS context
#[derive(Clone, Debug)]
pub struct KerberosConfig {
    /// Kerberos realm (e.g., "EXAMPLE.COM")
    pub realm: String,
    /// Target server's fully-qualified domain name (canonicalized via DNS)
    pub target_fqdn: String,
    /// Override Service Principal Name (required for IP address targets)
    pub spn_override: Option<String>,
    /// Default authentication level for wrapped messages
    pub default_auth: AuthLevel,
    /// Timeout for DNS resolution operations
    pub dns_timeout: Duration,
    /// Timeout for GSS-API operations
    pub gss_timeout: Duration,
    /// Path to Kerberos credential cache (honors KRB5CCNAME environment variable)
    pub kccache: Option<String>,
    /// Optional channel bindings for enhanced security
    pub channel_bindings: Option<ChannelBindings>,
    /// Enable GSS_C_DCE_STYLE flag for DCE/RPC compatibility
    ///
    /// When enabled, this flag:
    /// - Disables GSS sequence number checking (DCE has its own)
    /// - Allows out-of-order message processing
    /// - Prevents GSS replay cache from interfering with DCE/RPC
    ///
    /// Default: true (recommended for DCE/RPC)
    pub enable_dce_style: bool,
    /// Enable credential delegation (GSS_C_DELEG_FLAG)
    ///
    /// When enabled, allows the server to impersonate the client
    /// for accessing other services (S4U2Self/S4U2Proxy scenarios).
    ///
    /// Default: false (for security)
    pub enable_delegation: bool,
    /// Require mutual authentication (GSS_C_MUTUAL_FLAG)
    ///
    /// Already enabled by default for security, but exposed
    /// for cases where you might need to disable it (not recommended).
    ///
    /// Default: true
    pub require_mutual_auth: bool,
}

impl KerberosConfig {
    /// Create a builder for fluent configuration
    #[must_use]
    pub fn builder() -> KerberosConfigBuilder {
        KerberosConfigBuilder::default()
    }
}

/// Builder for `KerberosConfig` with sensible defaults
#[derive(Debug)]
pub struct KerberosConfigBuilder {
    realm: Option<String>,
    target_host: Option<String>,
    spn_override: Option<String>,
    default_auth: AuthLevel,
    dns_timeout: Duration,
    gss_timeout: Duration,
    kccache: Option<String>,
    channel_bindings: Option<ChannelBindings>,
    enable_dce_style: bool,
    enable_delegation: bool,
    require_mutual_auth: bool,
}

impl Default for KerberosConfigBuilder {
    fn default() -> Self {
        Self {
            realm: None,
            target_host: None,
            spn_override: None,
            default_auth: AuthLevel::Privacy,
            dns_timeout: Duration::from_secs(5),
            gss_timeout: Duration::from_secs(30),
            kccache: None,
            channel_bindings: None,
            enable_dce_style: true,  // Default true for DCE/RPC
            enable_delegation: false,  // Default false for security
            require_mutual_auth: true,  // Default true for security
        }
    }
}

impl KerberosConfigBuilder {
    /// Create a new builder with defaults
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Kerberos realm
    #[must_use]
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Set the target hostname (will be canonicalized)
    #[must_use]
    pub fn target_host(mut self, host: impl Into<String>) -> Self {
        self.target_host = Some(host.into());
        self
    }

    /// Override the SPN (required for IP addresses)
    #[must_use]
    pub fn spn_override(mut self, spn: Option<String>) -> Self {
        self.spn_override = spn;
        self
    }

    /// Set the default authentication level
    #[must_use]
    pub const fn default_auth(mut self, level: AuthLevel) -> Self {
        self.default_auth = level;
        self
    }

    /// Set the DNS resolution timeout
    #[must_use]
    pub const fn dns_timeout(mut self, timeout: Duration) -> Self {
        self.dns_timeout = timeout;
        self
    }

    /// Set the GSS-API operation timeout
    #[must_use]
    pub const fn gss_timeout(mut self, timeout: Duration) -> Self {
        self.gss_timeout = timeout;
        self
    }

    /// Set the credential cache path
    #[must_use]
    pub fn kccache(mut self, path: Option<String>) -> Self {
        self.kccache = path;
        self
    }

    /// Set channel bindings
    #[must_use]
    pub fn channel_bindings(mut self, cb: Option<ChannelBindings>) -> Self {
        self.channel_bindings = cb;
        self
    }

    /// Enable or disable GSS_C_DCE_STYLE flag
    ///
    /// When enabled (default), this flag:
    /// - Disables GSS sequence number checking (DCE has its own)
    /// - Allows out-of-order message processing
    /// - Prevents GSS replay cache from interfering with DCE/RPC
    ///
    /// You should only disable this if you're not using DCE/RPC.
    #[must_use]
    pub const fn dce_style(mut self, enable: bool) -> Self {
        self.enable_dce_style = enable;
        self
    }

    /// Enable credential delegation (GSS_C_DELEG_FLAG)
    ///
    /// When enabled, allows the server to impersonate the client
    /// for accessing other services (S4U2Self/S4U2Proxy scenarios).
    ///
    /// # Security Warning
    ///
    /// Only enable delegation when you trust the server completely,
    /// as it allows the server to act on your behalf.
    #[must_use]
    pub const fn delegation(mut self, enable: bool) -> Self {
        self.enable_delegation = enable;
        self
    }

    /// Require mutual authentication (GSS_C_MUTUAL_FLAG)
    ///
    /// Enabled by default for security. Only disable if you have
    /// a specific reason and understand the security implications.
    #[must_use]
    pub const fn mutual_auth(mut self, require: bool) -> Self {
        self.require_mutual_auth = require;
        self
    }

    /// Build config synchronously (requires canonicalized FQDN)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing
    /// - IP address target is used without SPN override
    #[cfg_attr(feature = "trace", instrument(
        target = "kerbsec::config",
        level = "debug",
        skip_all
    ))]
    pub fn build(self) -> Result<KerberosConfig> {
        let realm = self
            .realm
            .ok_or_else(|| Error::Config("realm is required".into()))?;
        let target_fqdn = self
            .target_host
            .ok_or_else(|| Error::Config("target_host is required".into()))?;

        // Check if target is IP and requires override
        if target_fqdn.parse::<std::net::IpAddr>().is_ok() && self.spn_override.is_none() {
            #[cfg(feature = "trace")]
            warn!(target: "kerbsec::config", target = %target_fqdn, "IP target requires SPN override");
            return Err(Error::IpTargetRequiresSpnOverride);
        }

        let config = KerberosConfig {
            realm: realm.clone(),
            target_fqdn: target_fqdn.clone(),
            spn_override: self.spn_override,
            default_auth: self.default_auth,
            dns_timeout: self.dns_timeout,
            gss_timeout: self.gss_timeout,
            kccache: self.kccache.or_else(|| std::env::var("KRB5CCNAME").ok()),
            channel_bindings: self.channel_bindings,
            enable_dce_style: self.enable_dce_style,
            enable_delegation: self.enable_delegation,
            require_mutual_auth: self.require_mutual_auth,
        };

        #[cfg(feature = "trace")]
        debug!(
            target: "kerbsec::config",
            realm = %realm,
            fqdn = %target_fqdn,
            has_spn_override = config.spn_override.is_some(),
            auth_level = ?config.default_auth,
            has_ccache = config.kccache.is_some(),
            "config built successfully"
        );

        Ok(config)
    }

    /// Build with async DNS canonicalization
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing
    /// - IP address target is used without SPN override
    /// - DNS canonicalization fails
    #[cfg(feature = "dns")]
    #[cfg_attr(feature = "trace", instrument(
        target = "kerbsec::config",
        level = "debug",
        skip_all
    ))]
    pub async fn build_async(self) -> Result<KerberosConfig> {
        use crate::dns::resolver::canonicalize_fqdn;

        let realm = self
            .realm
            .ok_or_else(|| Error::Config("realm is required".into()))?;
        let target_host = self
            .target_host
            .ok_or_else(|| Error::Config("target_host is required".into()))?;

        // Canonicalize via DNS (CNAME → A/AAAA)
        let target_fqdn = canonicalize_fqdn(&target_host, self.dns_timeout).await?;

        // Check if target is IP and requires override
        if target_fqdn.parse::<std::net::IpAddr>().is_ok() && self.spn_override.is_none() {
            #[cfg(feature = "trace")]
            warn!(target: "kerbsec::config", target = %target_fqdn, "IP target requires SPN override");
            return Err(Error::IpTargetRequiresSpnOverride);
        }

        let config = KerberosConfig {
            realm: realm.clone(),
            target_fqdn: target_fqdn.clone(),
            spn_override: self.spn_override,
            default_auth: self.default_auth,
            dns_timeout: self.dns_timeout,
            gss_timeout: self.gss_timeout,
            kccache: self.kccache.or_else(|| std::env::var("KRB5CCNAME").ok()),
            channel_bindings: self.channel_bindings,
            enable_dce_style: self.enable_dce_style,
            enable_delegation: self.enable_delegation,
            require_mutual_auth: self.require_mutual_auth,
        };

        #[cfg(feature = "trace")]
        debug!(
            target: "kerbsec::config",
            realm = %realm,
            target_host = %target_host,
            canonical_fqdn = %target_fqdn,
            has_spn_override = config.spn_override.is_some(),
            auth_level = ?config.default_auth,
            has_ccache = config.kccache.is_some(),
            "config built with DNS canonicalization"
        );

        Ok(config)
    }
}
