#!/bin/bash
# Initialize MIT Kerberos KDC for testing
#
# This script:
# 1. Creates the Kerberos database
# 2. Creates test principals (users and services)
# 3. Generates keytabs for service authentication
# 4. Starts the KDC and kadmin services
#
# WARNING: Uses weak/known passwords - FOR TESTING ONLY

set -e

REALM="${KRB5_REALM:-TEST.KERBSEC.LOCAL}"
KDC_HOST="${KRB5_KDC:-kdc.test.kerbsec.local}"
MASTER_PASSWORD="kerbsec-test-master-key"

# Test user/service passwords (INSECURE - testing only!)
ADMIN_PASSWORD="admin123"
USER_PASSWORD="user123"
SERVICE_PASSWORD="service123"

echo "=== Kerbsec Test KDC Initialization ==="
echo "Realm: $REALM"
echo "KDC Host: $KDC_HOST"

# Check if database already exists
if [ -f "/var/lib/krb5kdc/principal" ]; then
    echo "KDC database already exists, starting services..."
else
    echo "Creating new KDC database..."

    # Create the Kerberos database
    kdb5_util create -s -r "$REALM" -P "$MASTER_PASSWORD"

    echo "Creating principals..."

    # Create admin principal
    kadmin.local -q "addprinc -pw $ADMIN_PASSWORD admin/admin@$REALM"

    # Create test user principals
    kadmin.local -q "addprinc -pw $USER_PASSWORD testuser@$REALM"
    kadmin.local -q "addprinc -pw $USER_PASSWORD alice@$REALM"
    kadmin.local -q "addprinc -pw $USER_PASSWORD bob@$REALM"

    # Create service principals for testing
    # HOST service (used by default SPN)
    kadmin.local -q "addprinc -randkey HOST/service.test.kerbsec.local@$REALM"
    kadmin.local -q "addprinc -randkey HOST/localhost@$REALM"

    # HTTP service (for web services)
    kadmin.local -q "addprinc -randkey HTTP/service.test.kerbsec.local@$REALM"
    kadmin.local -q "addprinc -randkey HTTP/localhost@$REALM"

    # CIFS/SMB service
    kadmin.local -q "addprinc -randkey cifs/service.test.kerbsec.local@$REALM"

    # LDAP service
    kadmin.local -q "addprinc -randkey ldap/service.test.kerbsec.local@$REALM"

    # MSSQLSvc (SQL Server style)
    kadmin.local -q "addprinc -randkey MSSQLSvc/service.test.kerbsec.local@$REALM"
    kadmin.local -q "addprinc -randkey MSSQLSvc/service.test.kerbsec.local:1433@$REALM"

    # WSMAN (WinRM/PowerShell remoting)
    kadmin.local -q "addprinc -randkey WSMAN/service.test.kerbsec.local@$REALM"
    kadmin.local -q "addprinc -randkey wsman/service.test.kerbsec.local@$REALM"

    # Generic test service
    kadmin.local -q "addprinc -randkey testservice/service.test.kerbsec.local@$REALM"

    # Create a principal with delegation enabled (for constrained delegation tests)
    kadmin.local -q "addprinc -randkey +ok_to_delegate HTTP/delegated.test.kerbsec.local@$REALM"

    echo "Generating keytabs..."

    # Service keytab (all service principals)
    kadmin.local -q "ktadd -k /keytabs/service.keytab \
        HOST/service.test.kerbsec.local@$REALM \
        HOST/localhost@$REALM \
        HTTP/service.test.kerbsec.local@$REALM \
        HTTP/localhost@$REALM \
        cifs/service.test.kerbsec.local@$REALM \
        ldap/service.test.kerbsec.local@$REALM \
        MSSQLSvc/service.test.kerbsec.local@$REALM \
        MSSQLSvc/service.test.kerbsec.local:1433@$REALM \
        WSMAN/service.test.kerbsec.local@$REALM \
        wsman/service.test.kerbsec.local@$REALM \
        testservice/service.test.kerbsec.local@$REALM \
        HTTP/delegated.test.kerbsec.local@$REALM"

    # User keytab for automated testing
    kadmin.local -q "ktadd -k /keytabs/testuser.keytab testuser@$REALM"

    # Set permissions
    chmod 644 /keytabs/*.keytab

    echo "KDC initialization complete!"
    echo ""
    echo "Test Principals Created:"
    kadmin.local -q "listprincs" | grep -v "^Authenticating"
    echo ""
    echo "Keytabs generated in /keytabs/"
    ls -la /keytabs/
fi

# Create ACL file for kadmin
cat > /etc/krb5kdc/kadm5.acl << EOF
*/admin@$REALM    *
EOF

echo ""
echo "Starting KDC services..."

# Start kadmind in background
krb5kdc
kadmind

echo "KDC is running!"
echo ""
echo "=== Test Credentials ==="
echo "Admin: admin/admin@$REALM (password: $ADMIN_PASSWORD)"
echo "User:  testuser@$REALM (password: $USER_PASSWORD)"
echo "Keytabs: /keytabs/service.keytab, /keytabs/testuser.keytab"
echo ""

# Keep container running and show logs
tail -f /var/log/krb5kdc.log 2>/dev/null || sleep infinity
