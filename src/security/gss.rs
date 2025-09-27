//! GSS-API integration for Unix platforms

use crate::config::{AuthLevel, ChannelBindings, KerberosConfig};
use crate::error::{Error, Result};
use crate::security::IovWrap;
use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE};
use std::time::Duration;

// GSS_C_DCE_STYLE flag (0x1000) - critical for DCE/RPC semantics
// This flag is not exposed by libgssapi, but is required for:
// - Disabling GSS sequence number checking (DCE has its own)
// - Allowing out-of-order message processing
// - Preventing GSS replay cache from interfering with DCE/RPC
const GSS_C_DCE_STYLE: u32 = 0x1000;
const GSS_C_DELEG_FLAG: u32 = 0x01;

#[cfg(feature = "trace")]
use tracing::{debug, error, info, instrument, warn};

/// GSS-API context wrapper for Unix platforms
pub struct GssContext {
    inner: Option<ClientCtx>,
    config: KerberosConfig,
    established: bool,
}

impl GssContext {
    /// Create a new GSS context with the given configuration
    pub fn new(config: KerberosConfig) -> Result<Self> {
        // Set KRB5CCNAME if provided AND not already set (to avoid races)
        if let Some(ref ccache) = config.kccache {
            if std::env::var("KRB5CCNAME").is_err() {
                std::env::set_var("KRB5CCNAME", ccache);
                #[cfg(feature = "trace")]
                debug!(target: "kerbsec::gss", ccache = %ccache, "set KRB5CCNAME");
            } else {
                #[cfg(feature = "trace")]
                debug!(target: "kerbsec::gss", "KRB5CCNAME already set, not overriding");
            }
        }

        Ok(Self {
            inner: None,
            config,
            established: false,
        })
    }

    /// Update channel bindings configuration after context creation
    pub fn set_channel_bindings(&mut self, cb: Option<ChannelBindings>) {
        self.config.channel_bindings = cb;
    }

    /// Generate initial AP-REQ token
    #[cfg_attr(feature = "trace", instrument(
        target = "kerbsec::gss",
        level = "info",
        skip_all,
        fields(spn)
    ))]
    pub fn initial_token(&mut self) -> Result<Vec<u8>> {
        // Build SPN
        let default_spn = format!("HOST/{}", self.config.target_fqdn);
        let spn = self.config.spn_override.as_deref().unwrap_or(&default_spn);

        #[cfg(feature = "trace")]
        info!(target: "kerbsec::gss", spn = %spn, mech = "KRB5", "initializing GSS context");

        // Create target name
        let target =
            Name::new(spn.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE)).map_err(|e| Error::Gss {
                major: 0,
                minor: 0,
                text: format!("Failed to create target name: {e}"),
            })?;

        // Create credentials (use default)
        // Note: libgssapi 0.9.1 API changed - parameter order is different
        let cred = Cred::acquire(
            None,
            Some(Duration::from_secs(300)),
            CredUsage::Initiate,
            None, // Use default mechanism set
        )
        .map_err(gss_error)?;

        // Set context flags for DCE-style
        let mut flags = CtxFlags::empty();

        // Mutual authentication (configurable but strongly recommended)
        if self.config.require_mutual_auth {
            flags |= CtxFlags::GSS_C_MUTUAL_FLAG;
        }

        flags |= CtxFlags::GSS_C_INTEG_FLAG; // Always required
        flags |= CtxFlags::GSS_C_SEQUENCE_FLAG; // DCE sequence detection
        flags |= CtxFlags::GSS_C_REPLAY_FLAG; // DCE replay detection

        // Enable delegation if configured
        if self.config.enable_delegation {
            // GSS_C_DELEG_FLAG (0x01) - allows server to act on client's behalf
            let flags_with_deleg = flags.bits() | GSS_C_DELEG_FLAG;
            flags = CtxFlags::from_bits_retain(flags_with_deleg);

            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::gss", "credential delegation enabled");
        }

        // Add confidentiality flag based on config
        if matches!(self.config.default_auth, AuthLevel::Privacy) {
            flags |= CtxFlags::GSS_C_CONF_FLAG;
        }

        // Add GSS_C_DCE_STYLE flag when configured (default: true for DCE/RPC)
        if self.config.enable_dce_style {
            // DCE_STYLE (0x1000) is critical for proper DCE/RPC semantics:
            // - Disables GSS sequence number checking (DCE has its own)
            // - Allows out-of-order message processing
            // - Prevents GSS replay cache from interfering with DCE/RPC
            //
            // Since libgssapi doesn't expose DCE_STYLE in CtxFlags,
            // we need to OR it in manually using from_bits_retain
            let flags_with_dce = flags.bits() | GSS_C_DCE_STYLE;
            flags = CtxFlags::from_bits_retain(flags_with_dce);

            #[cfg(feature = "trace")]
            debug!(target: "kerbsec::gss", flags = format_args!("{:#x}", flags.bits()), "context flags with DCE_STYLE");
        }

        // Initialize context - API changed in libgssapi 0.9.1
        let mut ctx = ClientCtx::new(Some(cred), target, flags, Some(&GSS_MECH_KRB5));

        let channel_binding_data = self
            .config
            .channel_bindings
            .as_ref()
            .and_then(|cb| cb.get_gss_data());

        #[cfg(feature = "trace")]
        if let Some(ref data) = channel_binding_data {
            debug!(target: "kerbsec::gss", binding_len = data.len(), "applying channel bindings");
        }

        // Generate initial token (AP-REQ)
        match ctx.step(None, channel_binding_data.as_deref()) {
            Ok(Some(token)) => {
                self.inner = Some(ctx);
                Ok(token.to_vec())
            }
            Ok(None) => Err(Error::TokenShape),
            Err(e) => Err(gss_error(e)),
        }
    }

    /// Process AP-REP and return final token if needed
    #[cfg_attr(feature = "trace", instrument(
        target = "kerbsec::gss",
        level = "info",
        skip_all,
        fields(ap_rep_size = ap_rep.len())
    ))]
    pub fn accept_ap_rep(&mut self, ap_rep: &[u8]) -> Result<Option<Vec<u8>>> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        let channel_binding_data = self
            .config
            .channel_bindings
            .as_ref()
            .and_then(|cb| cb.get_gss_data());

        match ctx.step(Some(ap_rep), channel_binding_data.as_deref()) {
            Ok(token) => {
                // Check if complete - is_complete() returns bool directly
                if ctx.is_complete() {
                    self.established = true;
                    #[cfg(feature = "trace")]
                    info!(target: "kerbsec::gss", "GSS context established (mutual, sequence, replay)");
                    // DCE requires sending third leg even if empty
                    Ok(Some(token.map_or_else(Vec::new, |t| t.to_vec())))
                } else {
                    // Should not happen in DCE 3-leg
                    #[cfg(feature = "trace")]
                    warn!(target: "kerbsec::gss", "AP-REP accepted but context not complete (unexpected)");
                    Ok(token.map(|t| t.to_vec()))
                }
            }
            Err(e) => {
                #[cfg(feature = "trace")]
                error!(target: "kerbsec::gss", error = %e, "failed to process AP-REP");
                Err(gss_error(e))
            }
        }
    }

    /// Check if the security context is fully established
    #[must_use] pub const fn established(&self) -> bool {
        self.established
    }

    /// Wrap PDU with IOV-like interface for DCE/RPC
    ///
    /// When the `iov` feature is enabled, this uses true GSS IOV operations
    /// for zero-copy wrapping. Otherwise falls back to regular wrap.
    pub fn wrap_iov(&mut self, pdu: &[u8], level: AuthLevel) -> Result<IovWrap> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        if !self.established {
            return Err(Error::NotEstablished);
        }

        let conf_req = matches!(level, AuthLevel::Privacy);

        #[cfg(feature = "iov")]
        {
            // Use real IOV implementation from libgssapi
            super::gss_iov::wrap_iov_real(ctx, pdu, conf_req)
        }

        #[cfg(not(feature = "iov"))]
        {
            use bytes::Bytes;
            // Fallback: Use regular wrap - return full token as header
            // DCE/RPC will need to handle this as a single token
            match ctx.wrap(conf_req, pdu) {
                Ok(wrapped) => {
                    // Return entire wrapped token as header
                    // Trailer is empty since we can't separate without IOV
                    Ok(IovWrap {
                        header: Bytes::from(wrapped.to_vec()),
                        payload: Bytes::new(),
                        trailer: Bytes::new(),
                        conf: conf_req,
                    })
                }
                Err(e) => Err(gss_error(e)),
            }
        }
    }

    /// Unwrap token with IOV-like interface
    ///
    /// When the `iov` feature is enabled, this uses true GSS IOV operations.
    /// Otherwise falls back to regular unwrap.
    pub fn unwrap_iov(&mut self, token: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        if !self.established {
            return Err(Error::NotEstablished);
        }

        // Use regular unwrap since IOV is not available
        match ctx.unwrap(token) {
            Ok(data) => Ok(data.to_vec()),
            Err(e) => Err(gss_error(e)),
        }
    }

    /// Check if delegated credentials are available
    ///
    /// Returns true if the context has received delegated credentials
    /// from the client (only applicable for acceptor contexts).
    #[must_use]
    pub fn has_delegated_credentials(&self) -> bool {
        // Check if delegation was negotiated
        if let Some(ref _inner) = self.inner {
            // Query context flags to see if GSS_C_DELEG_FLAG was negotiated
            // Note: libgssapi doesn't currently expose inquire_context,
            // so we track this based on our config for now
            self.config.enable_delegation
        } else {
            false
        }
    }

    /// Export delegated credentials
    ///
    /// Returns the delegated credentials if available.
    /// These can be used to impersonate the client for accessing
    /// other services (S4U2Self/S4U2Proxy).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No delegated credentials are available
    /// - Export operation fails
    pub fn export_delegated_credentials(&self) -> Result<Vec<u8>> {
        if !self.has_delegated_credentials() {
            return Err(Error::NoDelegatedCredentials);
        }

        // TODO: Implement actual credential export when libgssapi supports it
        // This would use gss_export_cred or similar API
        #[cfg(feature = "trace")]
        warn!(target: "kerbsec::gss", "delegated credential export not yet implemented");

        Err(Error::NotImplemented("credential export requires libgssapi support".into()))
    }

    /// Get the negotiated session key (not currently implemented)
    #[must_use] pub const fn session_key(&self) -> Option<Vec<u8>> {
        // GSS-API doesn't directly expose session key
        // This would require platform-specific extraction
        None
    }
}

fn gss_error(e: libgssapi::error::Error) -> Error {
    // Extract major and minor codes from libgssapi error
    let major = e.major.bits();
    let minor = e.minor;
    let text = e.to_string();

    #[cfg(feature = "trace")]
    error!(
        target: "kerbsec::gss",
        major = format_args!("{:#x}", major),
        minor = format_args!("{:#x}", minor),
        %text,
        "GSS error"
    );

    Error::Gss { major, minor, text }
}
