# Security Documentation for kerbsec

## Overview

This document outlines the security design, threat model, and audit findings for kerbsec. The library prioritizes security by delegating cryptographic operations to the system's GSS-API implementation and following defense-in-depth principles.

## Threat Model

### In Scope Threats

1. **Network Attacks**
   - Man-in-the-middle (MITM)
   - Replay attacks
   - Token tampering
   - Downgrade attacks

2. **Authentication Attacks**
   - Credential theft
   - Brute force
   - Pass-the-hash/ticket

3. **Memory Attacks**
   - Memory dumps
   - Side-channel leaks
   - Timing attacks

### Out of Scope

1. **System Compromise**: If the OS is compromised, Kerberos tickets are accessible
2. **KDC Compromise**: Requires infrastructure security beyond this library
3. **Physical Access**: Requires OS-level protections
4. **Cryptographic Breaks**: Relies on system GSS-API implementation

## Security Architecture

### Defense Layers

```
┌───────────────────────────┐
│     Application Layer     │ ← Input validation
├───────────────────────────┤
│     kerbsec Library       │ ← Safe abstractions
├───────────────────────────┤
│     GSS-API (System)      │ ← Cryptography
├───────────────────────────┤
│     Kerberos Protocol     │ ← Authentication
├───────────────────────────┤
│     Network Transport     │ ← TLS (optional)
└───────────────────────────┘
```

### Security Boundaries

- **API Boundary**: All inputs validated before GSS-API calls
- **FFI Boundary**: Unsafe code isolated in `src/ffi/`
- **Platform Boundary**: Platform-specific code in `cfg` blocks
- **Feature Boundary**: Security features cannot be disabled without explicit opt-in

## Logging Security

### Safe Logging Policy

The `trace` feature implements structured logging with strict security policies:

#### Never Logged ❌
- Passwords or passphrases
- Kerberos tickets (TGT, service tickets)
- Session keys or key material
- Full token contents (AP-REQ, AP-REP)
- Wrapped/unwrapped message data
- Credential cache contents

#### Safe to Log ✅
- Token sizes (not contents)
- Operation success/failure status
- Realm and principal names
- FQDNs and SPNs
- Error codes (major/minor)
- Configuration flags
- Message metadata

### Example Safe Logging

```rust
// GOOD: Log metadata only
debug!(
    target: "kerbsec::iov",
    token_size = token.len(),
    encrypted = conf_req,
    "wrapped message"
);

// BAD: Never log sensitive data
// debug!("session_key = {:?}", key); // NEVER DO THIS
```

# Security Audit Checklist

## Secrets and Sensitive Data

### ✅ No Hardcoded Secrets
- [x] No hardcoded passwords, keys, or tokens in source
- [x] No test credentials in examples
- [x] Environment variables used for KRB5CCNAME

### ✅ No Secret Logging
```bash
# Audit for potential secret logging
rg -i "password|secret|key|token" --type rust | grep -v "session_key\|keytab"
```
- [x] No credentials logged at any level
- [x] Session keys never logged
- [x] GSS tokens not logged in full

### ⚠️ Memory Zeroization (TODO)
- [ ] Session keys should be zeroized after use
- [ ] GSS tokens should be cleared from memory
- [ ] Consider using `zeroize` crate for sensitive buffers

```rust
// Recommendation: Add to Cargo.toml
zeroize = { version = "1.7", features = ["derive"] }

// Example usage:
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SessionKey {
    #[zeroize(skip)]
    id: u32,
    key: Vec<u8>,
}
```

## Authentication Security

### ✅ Replay Protection
- [x] Sequence numbers enforced
- [x] Timestamp validation (5 min skew)
- [x] Tests for replay detection

### ✅ Downgrade Prevention
- [x] Auth level cannot be downgraded
- [x] Tests for downgrade scenarios

### ✅ Weak Cipher Control
- [x] RC4 disabled by default
- [x] Requires explicit `allow-weak-crypto` feature
- [x] Tests verify RC4 rejection

## Input Validation

### ✅ SPN Validation
- [x] IP addresses require SPN override
- [x] Invalid SPNs handled gracefully
- [x] Tests for edge cases

### ✅ PDU Parsing
- [x] Length checks before parsing
- [x] Bounds checking on all reads
- [x] No unsafe buffer operations

## Error Handling

### ✅ No Information Leakage
- [x] Generic error messages for auth failures
- [x] No stack traces in production
- [x] No internal paths exposed

### ✅ Fail Secure
- [x] Default to most secure options
- [x] Explicit opt-in for weaker security
- [x] Context not established on any error

## Dependencies

### ✅ Minimal Dependencies
- [x] Only essential crates used
- [x] No unmaintained dependencies
- [x] libgssapi pinned to stable version

### ✅ Supply Chain
```bash
# Check for known vulnerabilities
cargo audit

# Review dependency tree
cargo tree

# Check licenses
cargo license
```

## Platform Security

### ✅ Unix Permissions
- [x] Respects system Kerberos config
- [x] Uses system credential cache
- [x] No custom file permissions set

### ✅ Network Security
- [x] No custom crypto implementation
- [x] Delegates to system GSS-API
- [x] Transport security handled by caller

## Recommendations

### High Priority
1. **Add memory zeroization** for sensitive data
   - Session keys
   - GSS tokens
   - Credential cache data

2. **Add rate limiting** for auth attempts
   - Prevent brute force
   - Log excessive failures

3. **Add audit logging**
   - Authentication events
   - Authorization failures
   - Suspicious patterns

### Medium Priority
1. **Fuzz testing** for PDU parsing
2. **Constant-time comparisons** for MACs
3. **Certificate pinning** support for channel bindings

### Low Priority
1. **FIPS mode** support
2. **HSM integration** for keys
3. **Threat model** documentation

## Security Contacts

Report security vulnerabilities to:
- Private: security@example.com
- Public: GitHub Security Advisories

## Compliance

- **MIT License**: No warranty, use at own risk
- **Export Control**: May be subject to export restrictions
- **No Cryptographic Code**: Uses system GSS-API only

## IOV Security Considerations

### Platform-Specific Security

| Platform    | IOV Support | Security Impact                           |
|-------------|-------------|-------------------------------------------|
| Linux + MIT | Native IOV  | Optimal: Zero-copy reduces attack surface |
| macOS       | Fallback    | Good: One extra copy, still secure        |
| Windows     | Future      | Will use SSPI native functions            |

### FFI Safety

```rust
// All unsafe operations isolated
#[cfg(target_os = "linux")]
unsafe fn wrap_iov_real(...) {
    // Validated inputs
    // Bounded operations
    // Error propagation
}
```

## Cryptographic Security

### Supported Algorithms

| Algorithm           | Status     | Notes                 |
|---------------------|------------|-----------------------|
| AES256-CTS-SHA1     | ✅ Default | Recommended           |
| AES128-CTS-SHA1     | ✅ Enabled | Good performance      |
| AES-SHA2 (RFC 8009) | ✅ Enabled | Modern standard       |
| 3DES                | ⚠️ Allowed | Legacy only           |
| RC4                 | ❌ Disabled | Requires feature flag |
| DES                 | ❌ Disabled | Never allowed         |

### Weak Crypto Prevention

```rust
// RC4 disabled by default
#[cfg(not(feature = "allow-weak-crypto"))]
if uses_rc4(etype) {
    return Err(Error::WeakCrypto);
}
```

## Channel Bindings (Future)

### TLS Integration (v0.2.0)

```rust
// Future: RFC 5929 channel bindings
let cb = ChannelBindings::from_tls(tls_conn)?;
config.channel_bindings(Some(cb));
```

Benefits:
- Prevents token forwarding
- Binds Kerberos to TLS session
- Mitigates MITM attacks

## Security Testing

### Current Test Coverage

- ✅ Replay attack detection
- ✅ Sequence number validation
- ✅ Downgrade prevention
- ✅ Weak cipher rejection
- ✅ SPN validation
- ✅ Clock skew handling

### Future Testing

- [ ] Fuzzing with AFL/LibFuzzer
- [ ] Property-based testing
- [ ] Timing attack analysis
- [ ] Memory safety with Miri

## Incident Response

### Security Issue Handling

1. **Report**: Send to security contact
2. **Triage**: Assess severity (CVSS)
3. **Fix**: Develop patch in private
4. **Disclose**: Coordinate disclosure
5. **Release**: Publish fix with advisory

### Severity Levels

| Level    | Response Time | Example                |
|----------|---------------|-----------------------||
| Critical | 24 hours      | RCE, auth bypass       |
| High     | 7 days        | Privilege escalation   |
| Medium   | 30 days       | Information disclosure |
| Low      | Next release  | Theoretical issues     |

## Audit History

| Date       | Version   | Auditor          | Result                    |
|------------|-----------|------------------|---------------------------|
| 2025-01-21 | 0.1.0     | Self + Community | Pass with recommendations |
| 2024-01-20 | 0.1.0-pre | Self             | Initial review            |

## Security Tools and Commands

### Static Analysis

```bash
# Rust security lints
cargo clippy --all-features -- -D warnings

# Security audit for dependencies
cargo audit

# Check for unsafe code
grep -r "unsafe" src/ --include="*.rs"

# Memory safety with Miri (nightly)
cargo +nightly miri test
```

### Dynamic Analysis

```bash
# Memory leaks
valgrind --leak-check=full cargo test

# Address sanitizer (Linux)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Thread sanitizer
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test
```

### Fuzzing (Future)

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzzer
cargo fuzz run token_parser

# With AFL
cargo afl build
cargo afl fuzz -i in -o out target/debug/fuzz_target
```

### Coverage Analysis

```bash
# Generate coverage report
cargo tarpaulin --all-features --out Html

# With llvm-cov
cargo llvm-cov --html --all-features
```

## Security Checklist for Contributors

### Before Submitting PR

- [ ] No new `unsafe` code without justification
- [ ] No logging of sensitive data
- [ ] Input validation for all public APIs
- [ ] Error messages don't leak information
- [ ] Tests for security-relevant changes
- [ ] Documentation for security implications

### Review Checklist

- [ ] Check for timing vulnerabilities
- [ ] Verify error handling
- [ ] Audit dependencies added
- [ ] Review unsafe blocks
- [ ] Check for panics in hot paths

---

*Last updated: January 2025*
