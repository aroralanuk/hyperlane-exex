FROM rust:latest AS builder
ENV CARGO_HOME=/usr/local/cargo

# Install necessary dependencies
RUN apt update && \
    apt install -y cmake clang openssl make && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="$CARGO_HOME/bin:${PATH}"

# Set the working directory
WORKDIR /usr/src/hyperlane-reth

# Copy the source code into the builder
COPY . .

# Build and install the hyperlane-reth binary
RUN make build-exex && make install-exex

FROM ubuntu:22.04

RUN apt update && apt install -y openssl && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/cargo/bin:${PATH}"

# Copy the hyperlane-reth binary from the builder
COPY --from=builder /usr/local/cargo/bin/hyperlane-reth /usr/local/bin/hyperlane-reth

# Verify that the binary is present
RUN chmod +x /usr/local/bin/hyperlane-reth && \
    hyperlane-reth --version


ENTRYPOINT ["hyperlane-reth"]
