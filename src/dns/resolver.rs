//! DNS resolver for FQDN canonicalization and KDC discovery

use crate::error::{Error, Result};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use std::time::Duration;
use tokio::time::timeout;

#[cfg(feature = "trace")]
use tracing::{debug, instrument};

/// Canonicalize hostname to FQDN via DNS (CNAME → A/AAAA)
///
/// # Errors
///
/// Returns an error if:
/// - DNS resolution fails
/// - Timeout occurs
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::dns",
    level = "debug",
    skip(dns_timeout),
    fields(host = %host, timeout_secs = ?dns_timeout.as_secs())
))]
pub async fn canonicalize_fqdn(host: &str, dns_timeout: Duration) -> Result<String> {
    // Check if it's already an IP address - no canonicalization needed
    if host.parse::<std::net::IpAddr>().is_ok() {
        #[cfg(feature = "trace")]
        debug!(target: "kerbsec::dns", "host is IP address, no canonicalization needed");
        return Ok(host.to_string());
    }

    #[cfg(feature = "trace")]
    debug!(target: "kerbsec::dns", "canonicalizing hostname");

    // Perform DNS resolution with timeout
    const MAX_CNAME_DEPTH: u8 = 10;

    let result = timeout(dns_timeout, async {
        // Create resolver using system configuration (/etc/resolv.conf)
        let resolver = Resolver::builder_tokio()
            .map_err(|e| Error::Dns(anyhow::anyhow!("Failed to create resolver builder: {e}")))?
            .build();

        // Chase CNAME chain to find canonical name
        let mut current_name = host.to_string();
        let mut cname_depth = 0;

        while cname_depth < MAX_CNAME_DEPTH {
            if let Ok(cname_response) = resolver.lookup(&current_name, RecordType::CNAME).await {
                if let Some(cname_record) = cname_response.iter().next() {
                    if let Some(cname) = cname_record.as_cname() {
                        current_name = cname.to_ascii().to_lowercase();
                        #[cfg(feature = "trace")]
                        debug!(target: "kerbsec::dns", depth = cname_depth, name = %current_name, "following CNAME chain");
                        cname_depth += 1;
                        continue;
                    }
                }
            }
            break;
        }

        // Now resolve the final name to ensure it exists
        match resolver.lookup_ip(&current_name).await {
            Ok(_) => {
                // Successfully resolved - use the canonical name from CNAME chain
                // Remove trailing dot if present and lowercase
                let canonical = current_name.trim_end_matches('.').to_lowercase();

                #[cfg(feature = "trace")]
                debug!(target: "kerbsec::dns", canonical = %canonical, "canonicalization complete");

                Ok(canonical)
            }
            Err(e) => {
                // If CNAME chain led nowhere, try original host
                if current_name != host && resolver.lookup_ip(host).await.is_ok() {
                        let canonical = host.trim_end_matches('.').to_lowercase();
                        #[cfg(feature = "trace")]
                        debug!(target: "kerbsec::dns", canonical = %canonical, "using original hostname (lowercased)");
                        return Ok(canonical);
                }
                Err(Error::CanonicalizationFailed(format!("{host}: {e}")))
            }
        }
    })
    .await;

    match result {
        Ok(Ok(canonical)) => Ok(canonical),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::CanonicalizationFailed(format!(
            "DNS timeout for {host}"
        ))),
    }
}

/// Discover KDC via DNS SRV records
///
/// # Errors
///
/// Returns an error if:
/// - DNS SRV lookup fails
/// - No KDCs found
/// - Timeout occurs
#[cfg_attr(feature = "trace", instrument(
    target = "kerbsec::dns",
    level = "debug",
    skip(dns_timeout),
    fields(realm = %realm, timeout_secs = ?dns_timeout.as_secs())
))]
pub async fn discover_kdc(realm: &str, dns_timeout: Duration) -> Result<Vec<String>> {
    let srv_name = format!("_kerberos._tcp.{}", realm.to_lowercase());
    #[cfg(feature = "trace")]
    debug!(target: "kerbsec::dns", srv = %srv_name, "looking up KDC via SRV record");

    let result = timeout(dns_timeout, async {
        // Create resolver using system configuration
        let resolver = Resolver::builder_tokio()
            .map_err(|e| Error::Dns(anyhow::anyhow!("Failed to create resolver builder: {e}")))?
            .build();

        match resolver.srv_lookup(&srv_name).await {
            Ok(response) => {
                let kdcs: Vec<String> = response
                    .iter()
                    .map(|srv| format!("{}:{}", srv.target().to_lowercase(), srv.port()))
                    .collect();

                if kdcs.is_empty() {
                    Err(Error::Dns(anyhow::anyhow!(
                        "No KDC found for realm {realm}"
                    )))
                } else {
                    #[cfg(feature = "trace")]
                    debug!(target: "kerbsec::dns", count = kdcs.len(), kdcs = ?kdcs, "discovered KDCs");
                    Ok(kdcs)
                }
            }
            Err(e) => Err(Error::Dns(anyhow::anyhow!("KDC discovery failed: {e}"))),
        }
    })
    .await;

    match result {
        Ok(Ok(kdcs)) => Ok(kdcs),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::Dns(anyhow::anyhow!(
            "DNS timeout discovering KDC for {realm}"
        ))),
    }
}
