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

# Copy and run initialization script
COPY docker/softhsm/init-hsm.sh /opt/init-hsm.sh
RUN chmod +x /opt/init-hsm.sh && /opt/init-hsm.sh

# Expose the token directory as a volume so the Rust server can mount it
VOLUME ["/var/lib/softhsm/tokens"]

# Keep container running (the token store is accessed via file mount)
CMD ["tail", "-f", "/dev/null"]

