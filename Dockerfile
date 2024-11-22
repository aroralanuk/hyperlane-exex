FROM rust:latest AS builder

# Install necessary dependencies
RUN apt update && apt install -y cmake clang openssl

# Set the working directory
WORKDIR /usr/src/hyperlane-reth

# Copy the source code into the builder
COPY . .

# Build and install the hyperlane-reth binary
RUN make build-exex && make install-exex

FROM debian:buster-slim

RUN apt update && apt install -y openssl && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/cargo/bin:${PATH}"

# Copy the hyperlane-reth binary from the builder
COPY --from=builder /root/.cargo/bin/hyperlane-reth /usr/local/bin/hyperlane-reth

# Verify that the binary is present
RUN chmod +x /usr/local/bin/hyperlane-reth && \
    hyperlane-reth --version

# Set the entrypoint (can also be defined in docker-compose.yml)
ENTRYPOINT ["hyperlane-reth"]
