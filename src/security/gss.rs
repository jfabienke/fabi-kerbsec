//! GSS-API integration for Unix platforms
//!
//! This module provides the low-level GSS-API wrapper for Unix platforms,
//! supporting both MIT Kerberos and Heimdal implementations.

use crate::config::{AuthLevel, ChannelBindings, KerberosConfig};
use crate::error::{Error, Result};
use crate::security::IovWrap;
use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL};
use std::sync::Once;
use std::time::Duration;

// GSS context flag constants
// These are standard GSS-API flags defined in RFC 2744

/// `GSS_C_DCE_STYLE` flag (0x1000) - critical for DCE/RPC semantics
/// This flag is not exposed by libgssapi, but is required for:
/// - Disabling GSS sequence number checking (DCE has its own)
/// - Allowing out-of-order message processing
/// - Preventing GSS replay cache from interfering with DCE/RPC
const GSS_C_DCE_STYLE: u32 = 0x1000;

/// `GSS_C_DELEG_FLAG` (0x01) - allows server to act on client's behalf
const GSS_C_DELEG_FLAG: u32 = 0x01;

/// `GSS_C_MUTUAL_FLAG` (0x02) - mutual authentication required
const GSS_C_MUTUAL_FLAG: u32 = 0x02;

/// `GSS_C_CONF_FLAG` (0x10) - confidentiality available
const GSS_C_CONF_FLAG: u32 = 0x10;

/// `GSS_C_INTEG_FLAG` (0x20) - integrity available
const GSS_C_INTEG_FLAG: u32 = 0x20;

#[cfg(feature = "trace")]
use tracing::{debug, error, info, instrument, warn};

/// Thread-safe environment variable initialization
static ENV_INIT: Once = Once::new();
static KEYTAB_ENV_INIT: Once = Once::new();

/// GSS-API context wrapper for Unix platforms
pub struct GssContext {
    inner: Option<ClientCtx>,
    config: KerberosConfig,
    established: bool,
    /// Tracks whether delegation was actually negotiated (not just requested)
    delegation_negotiated: bool,
}

impl GssContext {
    /// Create a new GSS context with the given configuration
    ///
    /// # Thread Safety
    ///
    /// The `KRB5CCNAME` environment variable is set only once per process using
    /// `std::sync::Once`. Subsequent calls will not modify the environment.
    /// This is safe because:
    /// 1. The env var is only set once, atomically
    /// 2. We only set it if it wasn't already set
    /// 3. After the first context creation, all contexts use the same ccache
    ///
    /// If you need different contexts to use different credential caches,
    /// set `KRB5CCNAME` before creating the first context, or use the
    /// `KRB5_CLIENT_KTNAME` mechanism for service accounts.
    pub fn new(config: KerberosConfig) -> Result<Self> {
        // Thread-safe environment variable initialization
        // SAFETY: std::sync::Once ensures this runs exactly once per process

        // Set credential cache environment variable
        if let Some(ref ccache) = config.kccache {
            let ccache_clone = ccache.clone();
            ENV_INIT.call_once(|| {
                // Only set if not already set by the environment
                if std::env::var("KRB5CCNAME").is_err() {
                    // SAFETY: This is safe because:
                    // 1. We're inside Once::call_once, so this runs exactly once
                    // 2. No other thread can be modifying env vars at this point
                    //    (or if they are, it's a program-level bug)
                    // 3. The value is valid UTF-8 (came from String)
                    unsafe {
                        std::env::set_var("KRB5CCNAME", &ccache_clone);
                    }
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::gss", ccache = %ccache_clone, "set KRB5CCNAME (once)");
                } else {
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::gss", "KRB5CCNAME already set, not overriding");
                }
            });
        }

        // Set keytab environment variable for service account authentication
        if let Some(ref keytab) = config.keytab {
            let keytab_clone = keytab.clone();
            KEYTAB_ENV_INIT.call_once(|| {
                // KRB5_CLIENT_KTNAME is the standard env var for client keytabs
                if std::env::var("KRB5_CLIENT_KTNAME").is_err() {
                    unsafe {
                        std::env::set_var("KRB5_CLIENT_KTNAME", &keytab_clone);
                    }
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::gss", keytab = %keytab_clone, "set KRB5_CLIENT_KTNAME (once)");
                } else {
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::gss", "KRB5_CLIENT_KTNAME already set, not overriding");
                }
            });
        }

        Ok(Self {
            inner: None,
            config,
            established: false,
            delegation_negotiated: false,
        })
    }

    /// Update channel bindings configuration after context creation
    ///
    /// # Errors
    ///
    /// Returns an error once the handshake has started: the bindings are part of
    /// the first token, so changing them afterwards would make later legs
    /// inconsistent with it.
    pub fn set_channel_bindings(&mut self, cb: Option<ChannelBindings>) -> Result<()> {
        if self.inner.is_some() {
            return Err(Error::HandshakeState(
                "channel bindings must be set before initial_token",
            ));
        }
        self.config.channel_bindings = cb;
        Ok(())
    }

    /// Channel binding data for the GSS calls, rejecting bindings GSS cannot carry
    ///
    /// Only `application_data` is passed to GSS-API; address-only bindings would be
    /// silently dropped, so they are an error rather than "no bindings".
    fn channel_binding_data(&self) -> Result<Option<Vec<u8>>> {
        let Some(cb) = self.config.channel_bindings.as_ref() else {
            return Ok(None);
        };
        cb.get_gss_data().map(Some).ok_or_else(|| {
            Error::Config(
                "channel bindings have no application data; address-only bindings are not supported"
                    .into(),
            )
        })
    }

    /// Generate initial AP-REQ token
    #[cfg_attr(
        feature = "trace",
        instrument(target = "kerbsec::gss", level = "info", skip_all, fields(spn))
    )]
    pub fn initial_token(&mut self) -> Result<Vec<u8>> {
        if self.inner.is_some() {
            return Err(Error::HandshakeState(
                "initial_token already called on this context",
            ));
        }

        let spn = target_principal(&self.config);

        #[cfg(feature = "trace")]
        info!(target: "kerbsec::gss", spn = %spn, mech = "KRB5", "initializing GSS context");

        // Import as a Kerberos principal name. `GSS_NT_HOSTBASED_SERVICE` would be
        // wrong here: it expects `service@host`, so `HOST/fqdn` was read as a bare
        // service name with the *local* hostname appended.
        let target = Name::new(spn.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL)).map_err(gss_error)?;

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

        // Always request confidentiality so a per-call `AuthLevel::Privacy` wrap
        // works on a context whose default is Integrity. Whether a given message is
        // sealed is still decided per call by `conf_req`.
        flags |= CtxFlags::GSS_C_CONF_FLAG;

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

        let channel_binding_data = self.channel_binding_data()?;

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
        if self.established {
            return Err(Error::HandshakeState("context is already established"));
        }
        let channel_binding_data = self.channel_binding_data()?;
        let ctx = self.inner.as_mut().ok_or(Error::HandshakeState(
            "accept_ap_rep called before initial_token",
        ))?;

        let token = match ctx.step(Some(ap_rep), channel_binding_data.as_deref()) {
            Ok(token) => token,
            Err(e) => {
                #[cfg(feature = "trace")]
                error!(target: "kerbsec::gss", error = %e, "failed to process AP-REP");
                return Err(gss_error(e));
            }
        };

        if !ctx.is_complete() {
            // DCE/RPC is a fixed 3-leg exchange; a further round trip means the
            // peer did not behave like one. Don't report it as established.
            #[cfg(feature = "trace")]
            warn!(target: "kerbsec::gss", "AP-REP accepted but context not complete");
            return Err(Error::HandshakeState(
                "context not complete after AP-REP; expected a 3-leg exchange",
            ));
        }

        // Query the flags the mechanism actually negotiated, not what we
        // requested. Failing to learn them is an error: assuming the requested
        // flags were granted would fail open.
        let negotiated_flags = ctx.flags().map_err(gss_error)?.bits();
        if let Err(e) = verify_negotiated_flags(&self.config, negotiated_flags) {
            // Don't leave a context with weaker protection than configured
            // around where it could be wrapped/unwrapped through.
            self.inner = None;
            return Err(e);
        }

        self.established = true;
        self.delegation_negotiated = (negotiated_flags & GSS_C_DELEG_FLAG) != 0;

        #[cfg(feature = "trace")]
        {
            info!(
                target: "kerbsec::gss",
                flags = format_args!("{:#x}", negotiated_flags),
                delegation = self.delegation_negotiated,
                mutual = (negotiated_flags & GSS_C_MUTUAL_FLAG) != 0,
                confidentiality = (negotiated_flags & GSS_C_CONF_FLAG) != 0,
                integrity = (negotiated_flags & GSS_C_INTEG_FLAG) != 0,
                "GSS context established"
            );

            // Delegation is best-effort: warn if requested but not granted
            if self.config.enable_delegation && !self.delegation_negotiated {
                warn!(
                    target: "kerbsec::gss",
                    "delegation was requested but not granted by server"
                );
            }
        }

        // DCE requires sending third leg even if empty
        Ok(Some(token.map_or_else(Vec::new, |t| t.to_vec())))
    }

    /// Check if the security context is fully established
    #[must_use]
    pub const fn established(&self) -> bool {
        self.established
    }

    /// Wrap PDU with IOV-like interface for DCE/RPC
    ///
    /// Uses native GSS IOV on Linux with the `iov` feature, otherwise regular
    /// `gss_wrap`. Requesting [`AuthLevel::Privacy`] fails if the mechanism does
    /// not actually encrypt.
    pub fn wrap_iov(&mut self, pdu: &[u8], level: AuthLevel) -> Result<IovWrap> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        if !self.established {
            return Err(Error::NotEstablished);
        }

        let conf_req = matches!(level, AuthLevel::Privacy);

        super::gss_iov::wrap_iov_real(ctx, pdu, conf_req)
    }

    /// Unwrap a complete `gss_wrap` token
    ///
    /// Concatenated `IovWrap` fragments (header, payload, trailer) are a valid
    /// token. If the context was configured for [`AuthLevel::Privacy`], a token
    /// that was not encrypted is rejected, so a peer cannot downgrade the
    /// session to integrity-only.
    pub fn unwrap_iov(&mut self, token: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.inner.as_mut().ok_or(Error::NotEstablished)?;

        if !self.established {
            return Err(Error::NotEstablished);
        }

        let require_conf = matches!(self.config.default_auth, AuthLevel::Privacy);
        super::gss_iov::unwrap_token(ctx, token, require_conf)
    }

    /// Maximum message size that wraps into at most `max_wrapped` bytes
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotEstablished`] before the handshake completes, or a GSS
    /// error if the mechanism cannot answer.
    pub fn wrap_size_limit(&self, max_wrapped: usize, conf_req: bool) -> Result<usize> {
        let ctx = self.inner.as_ref().ok_or(Error::NotEstablished)?;
        if !self.established {
            return Err(Error::NotEstablished);
        }
        super::gss_iov::wrap_size_limit_real(ctx, conf_req, max_wrapped)
    }

    /// Check if delegated credentials are available
    ///
    /// Returns true if delegation was both requested AND successfully
    /// negotiated during context establishment. This reflects the actual
    /// negotiation state, not just the configuration.
    ///
    /// # Note
    ///
    /// For initiator (client) contexts, this indicates whether the server
    /// accepted the delegation request. For acceptor (server) contexts,
    /// this indicates whether delegated credentials were received.
    #[allow(clippy::missing_const_for_fn)] // Can't be const: accesses self fields through method
    #[must_use]
    pub fn has_delegated_credentials(&self) -> bool {
        // Only return true if:
        // 1. Context is established
        // 2. Delegation was actually negotiated (not just requested)
        self.established && self.delegation_negotiated
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

        Err(Error::NotImplemented(
            "credential export requires libgssapi support".into(),
        ))
    }

    /// Get the negotiated session key (not currently implemented)
    #[must_use]
    pub const fn session_key(&self) -> Option<Vec<u8>> {
        // GSS-API doesn't directly expose session key
        // This would require platform-specific extraction
        None
    }
}

/// The service principal to authenticate to: `spn[@realm]`
///
/// The SPN is the configured override, or `HOST/<fqdn>`. The configured realm is
/// appended unless the SPN already names one.
fn target_principal(config: &KerberosConfig) -> String {
    let spn = config
        .spn_override
        .clone()
        .unwrap_or_else(|| format!("HOST/{}", config.target_fqdn));
    if spn.contains('@') {
        spn
    } else {
        format!("{spn}@{}", config.realm)
    }
}

/// Check the negotiated flags against what the configuration requires.
///
/// Integrity is always required. Mutual authentication, confidentiality (for
/// `AuthLevel::Privacy`) and DCE style are required when configured. Delegation
/// is deliberately not enforced: it is best-effort and reported separately.
const fn verify_negotiated_flags(config: &KerberosConfig, flags: u32) -> Result<()> {
    if flags & GSS_C_INTEG_FLAG == 0 {
        return Err(Error::FlagNotNegotiated("integrity"));
    }
    if config.require_mutual_auth && flags & GSS_C_MUTUAL_FLAG == 0 {
        return Err(Error::FlagNotNegotiated("mutual authentication"));
    }
    if matches!(config.default_auth, AuthLevel::Privacy) && flags & GSS_C_CONF_FLAG == 0 {
        return Err(Error::FlagNotNegotiated("confidentiality"));
    }
    if config.enable_dce_style && flags & GSS_C_DCE_STYLE == 0 {
        return Err(Error::FlagNotNegotiated("DCE style"));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(spn_override: Option<&str>) -> KerberosConfig {
        KerberosConfig::builder()
            .realm("CORP.EXAMPLE.COM")
            .target_host("web.corp.example.com")
            .spn_override(spn_override.map(str::to_owned))
            .build()
            .expect("config")
    }

    #[test]
    fn default_principal_is_host_spn_in_configured_realm() {
        assert_eq!(
            target_principal(&config(None)),
            "HOST/web.corp.example.com@CORP.EXAMPLE.COM"
        );
    }

    #[test]
    fn override_gets_realm_appended() {
        assert_eq!(
            target_principal(&config(Some("HTTP/api.corp.example.com"))),
            "HTTP/api.corp.example.com@CORP.EXAMPLE.COM"
        );
    }

    #[test]
    fn override_with_realm_is_kept() {
        assert_eq!(
            target_principal(&config(Some("cifs/fs.other.example@OTHER.EXAMPLE"))),
            "cifs/fs.other.example@OTHER.EXAMPLE"
        );
    }
}
