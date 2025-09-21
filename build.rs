//! Build script for kerbsec
//!
//! Detects and links against GSS-API libraries on Unix platforms.

#[cfg(unix)]
fn main() {
    use pkg_config::Config;

    println!("cargo:rerun-if-changed=build.rs");

    // Try to find GSS-API libraries
    if cfg!(target_os = "linux") {
        // On Linux, try MIT Kerberos first
        if Config::new()
            .atleast_version("1.10")
            .probe("krb5-gssapi").is_err()
        {
            // Fallback to generic gssapi
            if Config::new().probe("gssapi").is_err() {
                // Last resort: manual linking
                println!("cargo:rustc-link-lib=gssapi_krb5");
                println!("cargo:rustc-link-lib=krb5");
            }
        }
    } else if cfg!(target_os = "macos") {
        // macOS has GSS framework
        println!("cargo:rustc-link-lib=framework=GSS");
        // Also link Kerberos framework for completeness
        println!("cargo:rustc-link-lib=framework=Kerberos");
    } else {
        // Other Unix: try generic approach
        if Config::new().probe("gssapi").is_err() {
            println!("cargo:rustc-link-lib=gssapi");
        }
    }

    // Set feature flags based on what we can detect
    #[cfg(feature = "iov")]
    {
        // IOV support detection could go here
        // For now, assume it's available on modern systems
        println!("cargo:rustc-cfg=has_gss_iov");
    }
}

#[cfg(not(unix))]
fn main() {
    // No-op on non-Unix platforms
}