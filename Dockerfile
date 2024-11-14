FROM lukemathwalker/cargo-chef:latest-rust-1.82 AS chef
WORKDIR /app

# Install bpf-linker early on
RUN cargo install bpf-linker

# Add nightly toolchain for eBPF
RUN rustup toolchain install nightly --component rust-src

FROM chef AS planner
# Copy cargo files first to cache dependencies
COPY Cargo.toml .
COPY Cargo.lock .

# Copy every workspace member's Cargo.toml as well
COPY kite/Cargo.toml kite/Cargo.toml
COPY kite-ebpf/Cargo.toml kite-ebpf/Cargo.toml
COPY kite-ebpf-common/Cargo.toml kite-ebpf-common/Cargo.toml
COPY kite-admit/Cargo.toml kite-admit/Cargo.toml

COPY kite-ebpf/.cargo/config.toml kite-ebpf/.cargo/config.toml
COPY kite-ebpf/rust-toolchain.toml kite-ebpf/rust-toolchain.toml

RUN find . && cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /app

COPY --from=planner /app/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

# Copy the source code into the container
COPY kite/ ./kite/
COPY kite-ebpf/ ./kite-ebpf/
COPY kite-ebpf-common ./kite-ebpf-common/
COPY kite-admit/ ./kite-admit/

# Build the project for release
RUN cargo build --workspace --release

# Stage 2: Create a minimal image with the compiled binary
FROM debian:bookworm-slim

# Install only necessary dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/kite /usr/local/bin/kite
COPY --from=builder /app/target/release/kite-admit /usr/local/bin/kite-admit
COPY --from=builder /app/target/release/kite-init-container /usr/local/bin/kite-init-container
COPY --from=builder /app/target/release/kite-loader /usr/local/bin/kite-loader


# Expose the port the admission controller listens on
EXPOSE 3030

# Set the binary as the entrypoint
CMD ["/usr/local/bin/kite"]
