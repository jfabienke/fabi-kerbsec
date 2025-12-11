# MIT Kerberos KDC for integration testing
#
# This container provides a fully functional KDC for testing kerbsec.
# WARNING: This is for testing only - uses weak passwords and insecure settings.

FROM debian:bookworm-slim

# Install MIT Kerberos
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        krb5-kdc \
        krb5-admin-server \
        krb5-user \
        libkrb5-dev \
        dnsutils \
        netcat-openbsd \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Environment
ENV KRB5_REALM=TEST.KERBSEC.LOCAL
ENV KRB5_KDC=kdc.test.kerbsec.local
ENV KRB5_ADMIN_SERVER=kdc.test.kerbsec.local

# Create directories
RUN mkdir -p /var/lib/krb5kdc /var/log/krb5 /keytabs /run/krb5kdc

# Copy initialization script
COPY init-kdc.sh /usr/local/bin/init-kdc.sh
RUN chmod +x /usr/local/bin/init-kdc.sh

# Expose Kerberos ports
EXPOSE 88/tcp 88/udp 749/tcp 749/udp

# Health check
HEALTHCHECK --interval=5s --timeout=5s --retries=10 --start-period=10s \
    CMD kadmin.local -q "listprincs" > /dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/init-kdc.sh"]
