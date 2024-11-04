# Stage 1: Build the Rust application
FROM rust:1.82 AS builder

# Create a new empty shell project
RUN USER=root cargo new --bin app
WORKDIR /app

# Copy the source code into the container
COPY Cargo.toml Cargo.lock ./
RUN cargo fetch  # Pre-fetch dependencies for caching
COPY src ./src

# Build the project for release
RUN cargo build --release

RUN cp /app/target/release/kite /kite
RUN cp /app/target/release/kite-admission-webhook /kite-admission-webhook
RUN cp /app/target/release/kite-init-container /kite-init-container

# Stage 2: Create a minimal image with the compiled binary
FROM debian:bookworm-slim

# Install only necessary dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /kite /usr/local/bin/kite
COPY --from=builder /kite-admission-webhook /usr/local/bin/kite-admission-webhook
COPY --from=builder /kite-init-container /usr/local/bin/kite-init-container

# Expose the port the admission controller listens on
EXPOSE 3030

# Set the binary as the entrypoint
CMD ["/usr/local/bin/kite"]
