# Build stage for the Rust signing server
# NOTE: Must use glibc (not musl/alpine) because cryptoki uses dlopen for PKCS#11
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the path dependency first
COPY rust_pdf_signing /build/rust_pdf_signing

# Copy the main project
COPY remote-signature-pdf /build/remote-signature-pdf

WORKDIR /build/remote-signature-pdf

# Build release binary
RUN cargo build --release --features hsm

# Runtime stage — Debian slim with SoftHSM
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# SoftHSM config pointing to shared token volume
RUN mkdir -p /var/lib/softhsm/tokens
COPY remote-signature-pdf/docker/softhsm/softhsm2.conf /etc/softhsm2.conf

# Copy the binary
COPY --from=builder /build/remote-signature-pdf/target/release/remote-signature-pdf /app/remote-signature-pdf

EXPOSE 8080

ENV RUST_LOG=info
ENV SOFTHSM2_CONF=/etc/softhsm2.conf

CMD ["/app/remote-signature-pdf", "server", "--port", "8080", "--host", "0.0.0.0"]
