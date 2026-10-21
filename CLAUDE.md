# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

kerbsec is a lightweight Kerberos security context library for DCE/RPC authentication on Unix platforms. It's a thin wrapper around the system GSS-API (MIT Kerberos or Heimdal) specifically designed for DCE/RPC semantics and optimized for high-performance message protection.

## Key Commands

### Building
```bash
# Standard build
cargo build

# Build with all features
cargo build --all-features

# Build with specific features
cargo build --features dns,runtime,iov,trace

# Release build
cargo build --release
```

### Testing
```bash
# Run all tests
cargo test --all-features

# Run with trace logging enabled
RUST_LOG=kerbsec=debug cargo test --features trace

# Test specific module
cargo test --test integration

# Test with MIT Kerberos tracing
KRB5_TRACE=/tmp/krb5.log cargo test
```

### End-to-end (real KDC)
```bash
# Starts a throwaway MIT KDC on localhost, runs the real 3-leg handshake (tests/e2e_kdc.rs)
# Needs: krb5-kdc krb5-admin-server krb5-user
./scripts/e2e-kdc.sh
```

### Linting & Verification
```bash
# Run clippy lints (configured with pedantic, nursery, cargo lints)
cargo clippy --all-features -- -D warnings

# Check formatting
cargo fmt --check

# Generate docs
cargo doc --all-features --no-deps
```

### Benchmarking
```bash
# Run performance benchmarks
cargo bench

# Generate benchmark report
cargo bench -- --save-baseline main
```

### Running Examples
```bash
# WMI client example with logging
RUST_LOG=kerbsec=debug cargo run --example wmi_client --features trace,dns,runtime
```

## High-Level Architecture

### Core Module Structure
The library implements a layered architecture with platform abstractions:

1. **Context Layer** (`src/context.rs`)
   - Main API entry point via `Context` struct
   - Manages GSS-API security context lifecycle
   - Handles 3-leg DCE/RPC handshake (AP-REQ → AP-REP → third leg)
   - Thread-safe: Send but NOT Sync (movable, not shareable)

2. **Security Abstraction** (`src/security/`)
   - `gss.rs`: Unix GSS-API wrapper interfacing with libgssapi
   - `gss_iov.rs`: Zero-copy IOV operations (Linux-specific via FFI)
   - Platform detection and fallback mechanisms

3. **Configuration** (`src/config.rs`)
   - `KerberosConfig` and builder pattern
   - DNS canonicalization triggers
   - `AuthLevel`: Integrity vs Privacy selection

4. **FFI Layer** (`src/ffi/`)
   - Custom FFI bindings for IOV operations (gss_wrap_iov/gss_unwrap_iov)
   - Required because libgssapi 0.9.1 doesn't expose IOV functions
   - Platform-specific: Linux has native IOV, macOS falls back to regular wrap/unwrap

### Protocol Implementation

The library implements DCE/RPC-specific Kerberos semantics:

1. **DCE-Style Flag**: Manually applies GSS_C_DCE_STYLE (0x1000) via bitwise operations
   - Disables GSS sequence number checking (DCE has its own)
   - Allows out-of-order message processing

2. **IOV Operations**: Zero-copy message protection on Linux
   - Header (16-32 bytes) + Data (unchanged for integrity) + Trailer (12-16 bytes)
   - Fallback to regular wrap/unwrap on macOS

3. **DNS Resolution** (`src/dns/`):
   - Automatic FQDN canonicalization
   - CNAME chasing for proper SPN construction
   - KDC discovery via SRV records

## Feature Flags

- `dns`: DNS canonicalization and KDC discovery (default)
- `runtime`: Async runtime support with tokio (default)
- `iov`: GSS IOV operations for zero-copy (default)
- `ccache`: Credential cache support
- `trace`: Structured logging via tracing

## Platform Differences

### Linux (MIT Kerberos)
- Full native IOV support via custom FFI bindings
- Optimal zero-copy performance
- Direct access to gss_wrap_iov/gss_unwrap_iov

### macOS (Heimdal)
- No IOV support in GSS.framework
- Falls back to regular wrap/unwrap with header/trailer estimation
- Performance still good but not optimal

## Critical Implementation Details

1. **GSS_C_DCE_STYLE Flag**: Critical for DCE/RPC - manually applied since libgssapi doesn't expose it
2. **Thread Safety**: Context is Send but NOT Sync (enforced by a `PhantomData<Cell<()>>` marker; libgssapi's own context claims Sync) - cannot be shared between threads
3. **Confidentiality is verified, not assumed**: wrap/unwrap read the real `conf_state`; Privacy that was not applied/present is `Error::ConfidentialityNotProvided`. Negotiated flags are checked after the handshake.
4. **Memory Management**: Zero-copy on Linux IOV, one allocation on macOS fallback
5. **Error Handling**: Structured errors with GSS major/minor codes preserved

## Dependencies

### System Requirements
- **Ubuntu/Debian**: `libkrb5-dev libgssapi-krb5-2`
- **macOS**: System Kerberos (Heimdal) or `brew install krb5` for MIT
- **RHEL/Fedora**: `krb5-devel`

### Key Rust Dependencies
- `libgssapi = "=0.9.1"`: Exact version pinned for security. Vendored in `vendor/libgssapi`
  (via `[patch.crates-io]`) with a single addition, `ClientCtx::raw_ctx()`, so our FFI can
  observe `conf_state` without reading private struct layout. Re-apply it when upgrading.
- `hickory-resolver`: DNS operations
- `tokio`: Async runtime
- `tracing`: Structured logging