# SoftHSM v2 — PKCS#11 software HSM for development/prototype
#
# Provides a Docker container with SoftHSM2, pkcs11-tool (opensc),
# and pre-initialized tokens with the Nowina DSS test certificates.
#
# Usage:
#   docker build -t softhsm-signing -f docker/softhsm/Dockerfile .
#   docker run -d --name softhsm softhsm-signing
#
# The PKCS#11 library is at: /usr/lib/softhsm/libsofthsm2.so
# Token label: "signing", PIN: "1234", SO-PIN: "5678"

FROM alpine:3.19

RUN apk add --no-cache \
    softhsm \
    opensc \
    openssl \
    bash

# Create token directory
RUN mkdir -p /var/lib/softhsm/tokens

# Copy Nowina test certificates for HSM initialization
COPY certs/nowina/user-cert.pem /opt/certs/user-cert.pem
COPY certs/nowina/user-key.pem  /opt/certs/user-key.pem
COPY certs/nowina/ca-chain.pem  /opt/certs/ca-chain.pem

# Copy initialization script (runs at startup, not build time)
COPY docker/softhsm/init-hsm.sh /opt/init-hsm.sh
RUN chmod +x /opt/init-hsm.sh

VOLUME ["/var/lib/softhsm/tokens"]

# Default: init token then keep running
CMD ["/bin/bash", "-c", "/opt/init-hsm.sh && tail -f /dev/null"]
