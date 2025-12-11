# kerbsec Integration Testing

This directory contains the infrastructure for running integration tests against a real MIT Kerberos KDC.

## Quick Start

```bash
# Run all integration tests
./testing/scripts/run-integration-tests.sh

# Keep containers running after tests (for debugging)
./testing/scripts/run-integration-tests.sh --keep-running --verbose
```

## Architecture

```
testing/
├── docker-compose.yml      # Container orchestration
├── kdc/
│   ├── Dockerfile          # MIT KDC container
│   ├── Dockerfile.client   # Kerberos client container
│   ├── init-kdc.sh         # KDC initialization script
│   ├── krb5.conf           # Client Kerberos configuration
│   └── kdc.conf            # KDC server configuration
├── scripts/
│   └── run-integration-tests.sh  # Test runner script
└── README.md
```

## Test Realm Configuration

| Setting | Value |
|---------|-------|
| Realm | `TEST.KERBSEC.LOCAL` |
| KDC Host | `kdc.test.kerbsec.local` |
| Service Host | `service.test.kerbsec.local` |

### Test Principals

| Principal | Password/Keytab |
|-----------|-----------------|
| `admin/admin@TEST.KERBSEC.LOCAL` | `admin123` |
| `testuser@TEST.KERBSEC.LOCAL` | `user123` / `/keytabs/testuser.keytab` |
| `alice@TEST.KERBSEC.LOCAL` | `user123` |
| `bob@TEST.KERBSEC.LOCAL` | `user123` |

### Service Principals (in `/keytabs/service.keytab`)

- `HOST/service.test.kerbsec.local`
- `HOST/localhost`
- `HTTP/service.test.kerbsec.local`
- `HTTP/localhost`
- `cifs/service.test.kerbsec.local`
- `ldap/service.test.kerbsec.local`
- `MSSQLSvc/service.test.kerbsec.local`
- `MSSQLSvc/service.test.kerbsec.local:1433`
- `WSMAN/service.test.kerbsec.local`
- `testservice/service.test.kerbsec.local`
- `HTTP/delegated.test.kerbsec.local` (delegation enabled)

## Manual Testing

### Start the KDC

```bash
cd testing
docker-compose up -d
docker-compose logs -f kdc
```

### Verify KDC is running

```bash
# List principals
docker-compose exec kdc kadmin.local -q "listprincs"

# Get a ticket
docker-compose exec kdc kinit testuser@TEST.KERBSEC.LOCAL
# Password: user123

# Verify ticket
docker-compose exec kdc klist
```

### Run tests from host

```bash
# Copy krb5.conf and modify for localhost
cp testing/kdc/krb5.conf /tmp/test-krb5.conf
sed -i 's/kdc.test.kerbsec.local:88/127.0.0.1:8888/g' /tmp/test-krb5.conf

# Set environment
export KRB5_CONFIG=/tmp/test-krb5.conf
export KERBSEC_TEST_REALM=TEST.KERBSEC.LOCAL
export KERBSEC_TEST_USER=testuser
export KERBSEC_TEST_PASSWORD=user123
export KERBSEC_TEST_SERVICE_HOST=service.test.kerbsec.local

# Run tests
cargo test --features integration-tests
```

### Cleanup

```bash
docker-compose down -v
```

## Debugging

### Enable Kerberos tracing

```bash
export KRB5_TRACE=/dev/stderr
cargo test --features integration-tests
```

### View KDC logs

```bash
docker-compose logs kdc
```

### Interactive shell in KDC

```bash
docker-compose exec kdc bash
kadmin.local
```

## Security Warning

**This test infrastructure uses known, weak passwords and is intentionally insecure.**

- DO NOT use in production
- DO NOT expose to untrusted networks
- Use only for local development and CI testing

## CI Integration

The test script is designed for CI use:

```yaml
# GitHub Actions example
jobs:
  integration-tests:
    runs-on: ubuntu-latest
    services:
      kdc:
        image: ghcr.io/your-org/kerbsec-test-kdc:latest
        ports:
          - 8888:88
          - 8749:749
    steps:
      - uses: actions/checkout@v4
      - name: Run integration tests
        run: ./testing/scripts/run-integration-tests.sh --quick
```
