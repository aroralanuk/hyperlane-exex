# ======= Builder Stage =======
FROM rust:1.82.0-bullseye AS builder

# Install necessary dependencies, including libclang
RUN apt-get update && \
    apt-get install -y \
        git \
        libclang-dev \
        clang \
        build-essential \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/hyperlane-exex

RUN git clone https://github.com/aroralanuk/hyperlane-exex.git . && \
    git checkout master


RUN cargo build --release

# ======= Runtime Stage =======

# Use a minimal base image for the runtime
FROM ubuntu:20.04

# Install necessary runtime dependencies
RUN apt-get update && \
    apt-get install -y \
        libssl1.1 \
        libclang1-10 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/src/hyperlane-exex/target/release/hyperlane-exex /usr/local/bin/hyperlane-exex

RUN useradd -m exex
USER exex

ENTRYPOINT ["hyperlane-exex"]

# Define the default command with arguments
CMD ["--chain", "base", "--datadir", "/data"]