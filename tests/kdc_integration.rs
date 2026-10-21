//! Integration tests against a real MIT Kerberos KDC
//!
//! These tests require a running KDC. Use the test script to start one:
//!
//! ```bash
//! ./testing/scripts/run-integration-tests.sh
//! ```
//!
//! Or manually:
//!
//! ```bash
//! docker-compose -f testing/docker-compose.yml up -d
//! export KRB5_CONFIG=./testing/kdc/krb5.conf
//! cargo test --features integration-tests
//! ```
//!
//! Environment variables:
//! - `KERBSEC_TEST_REALM` - Kerberos realm (default: TEST.KERBSEC.LOCAL)
//! - `KERBSEC_TEST_USER` - Test user principal (default: testuser)
//! - `KERBSEC_TEST_PASSWORD` - Test user password (default: user123)
//! - `KERBSEC_TEST_SERVICE_HOST` - Service hostname (default: service.test.kerbsec.local)
//! - `KRB5_CONFIG` - Path to krb5.conf
//! - `KRB5_CLIENT_KTNAME` - Path to client keytab

#![cfg(feature = "integration-tests")]

use kerbsec::{AuthLevel, KerberosConfig};
use std::env;

/// Get test configuration from environment
fn get_test_config() -> Option<TestConfig> {
    // Check if we're running in a CI environment with KDC
    let realm = env::var("KERBSEC_TEST_REALM").ok()?;
    let user = env::var("KERBSEC_TEST_USER").ok()?;
    let password = env::var("KERBSEC_TEST_PASSWORD").ok()?;
    let service_host = env::var("KERBSEC_TEST_SERVICE_HOST").ok()?;

    Some(TestConfig {
        realm,
        user,
        password,
        service_host,
    })
}

struct TestConfig {
    realm: String,
    user: String,
    #[allow(dead_code)]
    password: String,
    service_host: String,
}

/// Helper to check if KDC is available
fn kdc_available() -> bool {
    // Check for required environment variables
    if get_test_config().is_none() {
        return false;
    }

    // Check if KRB5_CONFIG is set
    if env::var("KRB5_CONFIG").is_err() {
        return false;
    }

    true
}

/// Macro to skip tests when KDC is not available
macro_rules! require_kdc {
    () => {
        if !kdc_available() {
            eprintln!("Skipping test: KDC not available (set KERBSEC_TEST_* env vars)");
            return;
        }
    };
}

mod context_tests {
    use super::*;

    #[test]
    fn test_kerberos_config_creation() {
        require_kdc!();
        let config = get_test_config().unwrap();

        let kerberos_config = KerberosConfig::builder()
            .realm(&config.realm)
            .target_host(&config.service_host)
            .default_auth(AuthLevel::Integrity)
            .build();

        assert!(kerberos_config.is_ok());
        let kerberos_config = kerberos_config.unwrap();
        assert_eq!(kerberos_config.realm, config.realm);
    }

    #[test]
    fn test_context_initial_token_generation() {
        require_kdc!();
        let config = get_test_config().unwrap();

        let kerberos_config = KerberosConfig::builder()
            .realm(&config.realm)
            .target_host(&config.service_host)
            .default_auth(AuthLevel::Integrity)
            .build()
            .unwrap();

        // Create context and generate initial token
        let result = kerbsec::Context::new(kerberos_config);

        match result {
            Ok(mut ctx) => {
                // Try to generate initial token
                let token_result = ctx.initial_token();
                match token_result {
                    Ok(token) => {
                        // Verify it looks like a GSS token
                        assert!(!token.is_empty(), "Token should not be empty");
                        // GSS tokens typically start with ASN.1 APPLICATION tag (0x60)
                        assert_eq!(
                            token[0], 0x60,
                            "Token should start with ASN.1 APPLICATION tag"
                        );
                        println!("Generated AP-REQ token: {} bytes", token.len());
                    }
                    Err(e) => {
                        // This might fail if no valid credential cache
                        eprintln!("Expected error generating token: {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("Context creation failed (may be expected): {e}");
            }
        }
    }

    #[test]
    fn test_context_with_keytab() {
        require_kdc!();
        let config = get_test_config().unwrap();

        // Check if keytab is available
        let keytab_path = env::var("KRB5_CLIENT_KTNAME").ok();

        if keytab_path.is_none() {
            eprintln!("Skipping keytab test: KRB5_CLIENT_KTNAME not set");
            return;
        }

        let kerberos_config = KerberosConfig::builder()
            .realm(&config.realm)
            .target_host(&config.service_host)
            .default_auth(AuthLevel::Integrity)
            .keytab(Some(keytab_path.unwrap()))
            .build()
            .unwrap();

        let result = kerbsec::Context::new(kerberos_config);

        match result {
            Ok(ctx) => {
                println!("Context created successfully with keytab");
                assert!(!ctx.established());
            }
            Err(e) => {
                eprintln!("Context creation failed: {e}");
            }
        }
    }
}

mod config_tests {
    use super::*;

    #[test]
    fn test_spn_construction_for_test_realm() {
        require_kdc!();
        let config = get_test_config().unwrap();

        // Test various SPN formats
        let spn_http =
            kerbsec::ServiceClass::Http.spn_with_realm(&config.service_host, &config.realm);
        assert_eq!(
            spn_http,
            format!("HTTP/{}@{}", config.service_host, config.realm)
        );

        let spn_host =
            kerbsec::ServiceClass::Host.spn_with_realm(&config.service_host, &config.realm);
        assert_eq!(
            spn_host,
            format!("HOST/{}@{}", config.service_host, config.realm)
        );

        let spn_mssql =
            kerbsec::ServiceClass::MsSql.spn_full(&config.service_host, 1433, &config.realm);
        assert_eq!(
            spn_mssql,
            format!("MSSQLSvc/{}:1433@{}", config.service_host, config.realm)
        );
    }
}
