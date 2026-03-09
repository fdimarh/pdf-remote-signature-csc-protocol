# Build stage for the Rust signing server
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

WORKDIR /build
COPY . .

# Build release binary
RUN cargo build --release --features hsm

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache \
    softhsm \
    openssl \
    ca-certificates

# SoftHSM config pointing to shared token volume
RUN mkdir -p /var/lib/softhsm/tokens
COPY docker/softhsm/softhsm2.conf /etc/softhsm2.conf

# Copy the binary
COPY --from=builder /build/target/release/remote-signature-pdf /app/remote-signature-pdf

EXPOSE 8080

ENV RUST_LOG=info
ENV SOFTHSM2_CONF=/etc/softhsm2.conf

CMD ["/app/remote-signature-pdf", "server", "--port", "8080", "--host", "0.0.0.0"]

