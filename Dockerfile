FROM rust:latest AS builder

# Install necessary dependencies
RUN apt update && apt install -y cmake clang openssl


RUN make build-op && make install-op

FROM debian:buster-slim

RUN apt update && apt install -y openssl && rm -rf /var/lib/apt/lists/*

