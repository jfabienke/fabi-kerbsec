//! Without a loadable GSS-API library, Kerberos fails with a clear error when it
//! is first used, not when the program is linked or loaded.
//!
//! The loaded library is cached for the process, so this is a test binary of its
//! own with a single test.

#![cfg(unix)]

use fabi_kerbsec::{ffi, Context, Error, KerberosConfig};

#[test]
fn missing_library_is_reported_on_first_use() {
    std::env::set_var(ffi::LIBRARY_ENV, "libkerbsec-test-missing.so");

    let config = KerberosConfig::builder()
        .realm("EXAMPLE.COM")
        .target_host("host.example.com")
        .build()
        .expect("config");
    let mut ctx = Context::new(config).expect("creating a context loads nothing");
    let err = ctx.initial_token().expect_err("no library");
    assert!(
        matches!(&err, Error::GssUnavailable(why) if why.contains("libkerbsec-test-missing.so")),
        "{err:?}"
    );
    assert!(!ffi::has_iov_support());
}
