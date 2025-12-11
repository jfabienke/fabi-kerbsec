#!/bin/bash
# Run kerbsec integration tests against a containerized KDC
#
# Usage:
#   ./testing/scripts/run-integration-tests.sh [--keep-running] [--verbose]
#
# Options:
#   --keep-running  Don't stop containers after tests (for debugging)
#   --verbose       Enable verbose output and KRB5 tracing
#   --build         Force rebuild of Docker images
#   --quick         Skip container health wait, assume running

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTING_DIR="$PROJECT_DIR/testing"
COMPOSE_FILE="$TESTING_DIR/docker-compose.yml"

# Parse arguments
KEEP_RUNNING=false
VERBOSE=false
FORCE_BUILD=false
QUICK=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-running) KEEP_RUNNING=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        --build) FORCE_BUILD=true; shift ;;
        --quick) QUICK=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    if [ "$KEEP_RUNNING" = false ]; then
        log_info "Stopping test containers..."
        docker-compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    else
        log_info "Keeping containers running (--keep-running specified)"
        log_info "To stop: docker-compose -f $COMPOSE_FILE down -v"
    fi
}

# Set up cleanup trap
trap cleanup EXIT

log_info "=== Kerbsec Integration Test Runner ==="
log_info "Project: $PROJECT_DIR"
log_info "Compose: $COMPOSE_FILE"

# Build images if needed
if [ "$FORCE_BUILD" = true ]; then
    log_info "Building Docker images..."
    docker-compose -f "$COMPOSE_FILE" build
fi

# Start containers
log_info "Starting KDC containers..."
docker-compose -f "$COMPOSE_FILE" up -d

if [ "$QUICK" = false ]; then
    # Wait for KDC to be healthy
    log_info "Waiting for KDC to be ready..."
    RETRIES=30
    while [ $RETRIES -gt 0 ]; do
        if docker-compose -f "$COMPOSE_FILE" exec -T kdc kadmin.local -q "listprincs" >/dev/null 2>&1; then
            break
        fi
        RETRIES=$((RETRIES - 1))
        if [ $RETRIES -eq 0 ]; then
            log_error "KDC failed to start!"
            docker-compose -f "$COMPOSE_FILE" logs kdc
            exit 1
        fi
        sleep 1
    done
    log_info "KDC is ready!"
fi

# Copy keytab and krb5.conf for tests
log_info "Setting up test environment..."

# Create temporary directory for test artifacts
TEST_ARTIFACTS="$PROJECT_DIR/target/test-artifacts"
mkdir -p "$TEST_ARTIFACTS"

# Copy keytab from container
docker cp kerbsec-test-kdc:/keytabs/testuser.keytab "$TEST_ARTIFACTS/testuser.keytab" 2>/dev/null || \
    log_warn "Could not copy testuser.keytab (may not exist yet)"
docker cp kerbsec-test-kdc:/keytabs/service.keytab "$TEST_ARTIFACTS/service.keytab" 2>/dev/null || \
    log_warn "Could not copy service.keytab (may not exist yet)"

# Copy krb5.conf
cp "$TESTING_DIR/kdc/krb5.conf" "$TEST_ARTIFACTS/krb5.conf"

# Modify krb5.conf to use localhost ports
sed -i 's/kdc.test.kerbsec.local:88/127.0.0.1:8888/g' "$TEST_ARTIFACTS/krb5.conf"
sed -i 's/kdc.test.kerbsec.local:749/127.0.0.1:8749/g' "$TEST_ARTIFACTS/krb5.conf"

# Set environment for tests
export KRB5_CONFIG="$TEST_ARTIFACTS/krb5.conf"
export KRB5_CLIENT_KTNAME="$TEST_ARTIFACTS/testuser.keytab"
export KRB5_KTNAME="$TEST_ARTIFACTS/service.keytab"
export KERBSEC_TEST_REALM="TEST.KERBSEC.LOCAL"
export KERBSEC_TEST_USER="testuser"
export KERBSEC_TEST_PASSWORD="user123"
export KERBSEC_TEST_SERVICE_HOST="service.test.kerbsec.local"

if [ "$VERBOSE" = true ]; then
    export KRB5_TRACE=/dev/stderr
    export RUST_LOG=kerbsec=debug
fi

log_info "Test environment:"
log_info "  KRB5_CONFIG=$KRB5_CONFIG"
log_info "  KRB5_CLIENT_KTNAME=$KRB5_CLIENT_KTNAME"
log_info "  KERBSEC_TEST_REALM=$KERBSEC_TEST_REALM"

# Verify we can get a ticket
log_info "Verifying Kerberos connectivity..."
if command -v kinit >/dev/null 2>&1; then
    echo "$KERBSEC_TEST_PASSWORD" | kinit -kt "$TEST_ARTIFACTS/testuser.keytab" testuser@TEST.KERBSEC.LOCAL 2>/dev/null && \
        log_info "Successfully obtained TGT!" || \
        log_warn "Could not obtain TGT (kinit failed - this may be expected on some systems)"
fi

# Run integration tests
log_info "Running integration tests..."
cd "$PROJECT_DIR"

# Run tests with the integration-tests feature
if cargo test --features "integration-tests,dns,runtime,iov,trace" -- --test-threads=1 $@; then
    log_info "All integration tests passed!"
    EXIT_CODE=0
else
    log_error "Some integration tests failed!"
    EXIT_CODE=1
fi

# Show container logs on failure
if [ $EXIT_CODE -ne 0 ] && [ "$VERBOSE" = true ]; then
    log_info "KDC logs:"
    docker-compose -f "$COMPOSE_FILE" logs kdc
fi

exit $EXIT_CODE
