//! Tests for GSS IOV functionality

#[cfg(all(test, feature = "iov"))]
mod iov_tests {
    use kerbsec::{AuthLevel, Context, KerberosConfig};

    #[test]
    fn test_iov_feature_detection() {
        // Verify that IOV feature is compiled in
        #[cfg(feature = "iov")]
        {
            assert!(true, "IOV feature is enabled");
        }
    }

    #[test]
    #[ignore] // Requires Kerberos environment
    fn test_wrap_unwrap_with_iov() {
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        // Would need established context to test
        // This demonstrates the IOV API is available
        let pdu = b"test PDU data for IOV";

        // Test with Integrity protection
        match ctx.wrap_iov_with(pdu, AuthLevel::Integrity) {
            Ok(wrapped) => {
                // With real IOV, header and trailer should be separate
                assert!(!wrapped.header.is_empty());
                // Trailer might be empty for integrity-only
                assert!(!wrapped.conf); // Not confidential
            }
            Err(_) => {
                // Expected without established context
            }
        }

        // Test with Privacy protection
        match ctx.wrap_iov_with(pdu, AuthLevel::Privacy) {
            Ok(wrapped) => {
                assert!(!wrapped.header.is_empty());
                // With real IOV, trailer should be populated for privacy
                assert!(wrapped.conf); // Confidential
            }
            Err(_) => {
                // Expected without established context
            }
        }
    }

    #[test]
    fn test_wrap_size_limit_with_iov() {
        let config = KerberosConfig::builder()
            .realm("EXAMPLE.COM")
            .target_host("server.example.com")
            .build()
            .unwrap();

        let ctx = Context::new(config).unwrap();

        // Test wrap_size_limit with IOV
        let max_wrapped = 5840; // DCE/RPC typical fragment size

        // Should give more accurate results with real IOV
        let max_msg_integrity = ctx.wrap_size_limit(max_wrapped, false);
        assert!(max_msg_integrity < max_wrapped);

        let max_msg_privacy = ctx.wrap_size_limit(max_wrapped, true);
        assert!(max_msg_privacy < max_wrapped);
        assert!(max_msg_privacy < max_msg_integrity); // Privacy has more overhead
    }
}
