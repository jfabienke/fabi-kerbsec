//! Service Principal Name handling

use crate::error::{Error, Result};

/// Build default SPN from FQDN
#[must_use]
pub fn build_spn(fqdn: &str) -> String {
    format!("HOST/{fqdn}")
}

/// Validate that SPN override is provided for IP targets
///
/// # Errors
///
/// Returns an error if target is an IP address without SPN override
pub fn validate_spn_for_target(target: &str, spn_override: Option<&str>) -> Result<String> {
    if target.parse::<std::net::IpAddr>().is_ok() {
        // Target is an IP address
        spn_override
            .map(String::from)
            .ok_or(Error::IpTargetRequiresSpnOverride)
    } else {
        // Target is hostname, use default or override
        Ok(spn_override.map_or_else(|| build_spn(target), String::from))
    }
}
