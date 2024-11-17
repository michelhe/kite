FROM rust:1.82-bookworm AS chef-base

# Install musl-dev on Alpine to avoid error "ld: cannot find crti.o: No such file or directory"
RUN ((cat /etc/os-release | grep ID | grep alpine) && apk add --no-cache musl-dev || true) \
    && cargo install cargo-chef --locked --version 0.1.68 \
    && rm -rf $CARGO_HOME/registry/

# Add nightly toolchain for eBPF
RUN rustup toolchain install nightly --component rust-src

FROM chef-base AS chef-amd64
WORKDIR /app

# Install bpf-linker early on
RUN cargo install bpf-linker

FROM chef-base AS chef-arm64
WORKDIR /app

# In Arm, an external LLVM (version 19) is requried to build bpf-linker
# Note that the package we add is for bookworm, so need the chef-base stage to be consistent with that.
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    printf "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-19 main\ndeb-src http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-19 main\n" >>/etc/apt/sources.list && \
    apt update && \
    apt install -y libzstd-dev llvm-19-dev libclang-19-dev libpolly-19-dev

# Install bpf-linker with external LLVM
RUN cargo install bpf-linker --no-default-features

FROM chef-${TARGETARCH} as chef

FROM chef AS planner
# Copy cargo files first to cache dependencies
COPY Cargo.toml .
COPY Cargo.lock .

# Copy every workspace member's Cargo.toml as well
COPY kite/Cargo.toml kite/Cargo.toml
COPY kite-ebpf/Cargo.toml kite-ebpf/Cargo.toml
COPY kite-ebpf-common/Cargo.toml kite-ebpf-common/Cargo.toml
COPY kite-k8s-admit/Cargo.toml kite-k8s-admit/Cargo.toml

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
COPY kite-k8s-admit/ ./kite-k8s-admit/

# Build the project for release
RUN cargo build --release

# Stage 2: Create a minimal image with the compiled binary
FROM debian:bookworm-slim

# Install only necessary dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/kite /usr/local/bin/kite
COPY --from=builder /app/target/release/kite-k8s-admit /usr/local/bin/kite-k8s-admit
COPY --from=builder /app/target/release/kite-init-container /usr/local/bin/kite-init-container
COPY --from=builder /app/target/release/kite-loader /usr/local/bin/kite-loader

# Expose the port the admission controller listens on
EXPOSE 3030

# Set the binary as the entrypoint
CMD ["/usr/local/bin/kite"]
