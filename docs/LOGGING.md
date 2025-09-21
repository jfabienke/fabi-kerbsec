# Logging Guide for kerbsec

This document describes the logging capabilities in kerbsec, following the linux-wmi style with structured, feature-gated logging using the `tracing` crate.

## Overview

kerbsec provides comprehensive logging for debugging and monitoring Kerberos authentication flows. All logging is:

- **Feature-gated** behind the `trace` feature flag
- **Structured** with typed fields for filtering and analysis
- **Module-targeted** for granular control
- **Security-conscious** - no secrets are logged

## Enabling Logging

### Build with Trace Feature

```bash
# Enable trace logging
cargo build --features trace

# With all features
cargo build --features trace,dns,runtime,iov
```

### Initialize Logging in Your Application

```rust
#[cfg(feature = "trace")]
{
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kerbsec=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
```

## Logging Targets

kerbsec uses module-specific targets for granular control:

| Target            | Description        | Key Information Logged                                          |
|-------------------|--------------------|-----------------------------------------------------------------|
| `kerbsec::ctx`    | Context operations | Context creation, handshake progress, token generation          |
| `kerbsec::gss`    | GSS-API operations | GSS context establishment, flags, errors with major/minor codes |
| `kerbsec::dns`    | DNS operations     | FQDN canonicalization, CNAME following, KDC discovery           |
| `kerbsec::iov`    | IOV wrap/unwrap    | Message sizes, encryption status, header/trailer lengths        |
| `kerbsec::config` | Configuration      | Config building, validation, DNS canonicalization results       |

## Environment Variables

Control logging levels with the `RUST_LOG` environment variable:

```bash
# Enable all kerbsec logging at debug level
RUST_LOG=kerbsec=debug cargo run

# Enable trace for specific modules
RUST_LOG=kerbsec::gss=trace,kerbsec::iov=debug cargo run

# Mixed configuration
RUST_LOG=kerbsec::ctx=info,kerbsec::dns=warn,kerbsec::iov=trace cargo run

# Enable all at trace level
RUST_LOG=kerbsec=trace cargo run
```

## Logging Levels

Following standard Rust/tracing conventions:

- **ERROR**: GSS-API failures, authentication errors
- **WARN**: Configuration issues (e.g., IP without SPN), platform limitations
- **INFO**: High-level operations (context established, tokens generated)
- **DEBUG**: Detailed operations (wrap/unwrap sizes, DNS lookups)
- **TRACE**: Very detailed debugging (all function entries/exits with parameters)

## Example Output

### Context Creation (INFO level)
```
INFO kerbsec::ctx: creating Kerberos context realm="CONTOSO.COM" fqdn="server.contoso.com" auth=Privacy
INFO kerbsec::ctx: initial token generated token_size=1234
```

### GSS Operations (DEBUG level)
```
DEBUG kerbsec::gss: initializing GSS context spn="HOST/server.contoso.com" mech="KRB5"
DEBUG kerbsec::gss: context flags with DCE_STYLE flags=0x101f
INFO kerbsec::gss: GSS context established (mutual, sequence, replay)
```

### IOV Operations (DEBUG level)
```
DEBUG kerbsec::iov: wrap_iov completed conf=true pdu_len=256 header_len=32 trailer_len=16
DEBUG kerbsec::iov: unwrap_iov completed plaintext_len=256 conf=true
```

### DNS Resolution (DEBUG level)
```
DEBUG kerbsec::dns: canonicalizing hostname host="server" timeout_secs=5
DEBUG kerbsec::dns: following CNAME chain depth=0 name="server.contoso.com"
DEBUG kerbsec::dns: canonicalization complete canonical="server.contoso.com"
```

### Error Logging
```
ERROR kerbsec::gss: GSS error major=0x80000 minor=0x96c73a1f text="No credentials were supplied"
ERROR kerbsec::iov: gss_wrap_iov failed major=0x20000 minor=0x0
```

## Security Considerations

The logging implementation follows strict security guidelines:

### Never Logged
- ❌ Kerberos tickets
- ❌ Session keys
- ❌ Token contents (AP-REQ, AP-REP)
- ❌ Wrapped/unwrapped message data
- ❌ Credential cache contents
- ❌ Passwords or secrets

### Safe to Log
- ✅ Token sizes
- ✅ Operation success/failure
- ✅ Realm names
- ✅ FQDNs and SPNs
- ✅ Error codes
- ✅ Configuration flags
- ✅ Message metadata (sizes, encryption status)

## Structured Fields

Log entries include structured fields for filtering and analysis:

```rust
// Example structured logging
debug!(
    target: "kerbsec::ctx",
    realm = %config.realm,
    fqdn = %config.target_fqdn,
    has_spn_override = config.spn_override.is_some(),
    auth_level = ?config.default_auth,
    "config built successfully"
);
```

This allows filtering with tools like `tokio-console` or structured log aggregators.

## Integration with linux-wmi

When using kerbsec with linux-wmi, both libraries follow the same logging patterns:

```bash
# Enable both kerbsec and linux-wmi logging
RUST_LOG=kerbsec=debug,linux_wmi=debug cargo run

# Focus on authentication issues
RUST_LOG=kerbsec::gss=trace,linux_wmi::auth=trace cargo run
```

## Troubleshooting Common Issues

### No Log Output

1. Ensure the `trace` feature is enabled at build time
2. Initialize a tracing subscriber in your application
3. Set appropriate `RUST_LOG` environment variable

### Too Much Output

Use targeted logging instead of blanket trace:
```bash
# Instead of
RUST_LOG=trace

# Use targeted
RUST_LOG=kerbsec::gss=debug,kerbsec::ctx=info
```

### GSS Errors

Enable trace-level logging for GSS operations:
```bash
RUST_LOG=kerbsec::gss=trace cargo run
```

This will show detailed GSS-API error codes with major/minor status values.

## Performance Considerations

- Logging is completely compiled out when the `trace` feature is disabled
- When enabled but not configured, logging has minimal overhead
- Use `skip_all` on instrument macros to avoid serializing large parameters
- The `instrument` macros use zero-cost abstractions when tracing is disabled

## CI Integration

The CI pipeline includes a dedicated test job for trace logging:

```yaml
- name: Run tests with trace logging enabled
  env:
    RUST_LOG: kerbsec=trace
  run: cargo test --features trace,dns,runtime,iov --verbose
```

This ensures logging doesn't break builds or introduce panics.
