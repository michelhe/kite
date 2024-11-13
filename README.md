# Kite

Kite is an observability tool designed to monitor application networking within a cluster. It leverages eBPF to collect metrics from processes and (will) support Prometheus scraping.

> **Note:** This project is a work in progress (WIP) and may not function as intended. Everything here is experimental.

## Architecture

Kite consists of three main components:

1. **Kite Daemon**: The core application responsible for monitoring applications and loading them with the (yet-to-be-written) eBPF program.
2. **Init Container**: A container that runs before the main application container to set up the environment for eBPF monitoring.
3. **Admission Webhook**: A Kubernetes admission controller that injects the init container into pods requiring monitoring.

## Getting Started

### Prerequisites

> **Disclaimer:** Kite only works on machines with cgroup2, as it utilizes new eBPF cgroup programs available only in v2.

### Development Environment Setup

1. Install stable Rust toolchains: `rustup toolchain install stable`
2. Install nightly Rust toolchains: `rustup toolchain install nightly --component rust-src`
3. (If cross-compiling) Add Rust target: `rustup target add ${ARCH}-unknown-linux-musl`
4. (If cross-compiling) Install LLVM: e.g., `brew install llvm` (on macOS)
5. (If cross-compiling) Install C toolchain: e.g., [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
6. Install bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

Ensure you have [pre-commit](https://pre-commit.com/) installed.

## Example: kite-loader

`kite-loader` is a small application to test Kite without setting up a full Kubernetes cluster.

### Building kite-loader

```bash
cargo build --bin kite-loader
```

### Running a Simple Web Server

In another shell, start a simple web server:

```bash
python3 -m http.server 8080
```

### Bombarding the Web Server with Requests

In another shell, run:

```bash
while true; do curl -s localhost:8080; done
```

### Running kite-loader

Now, you can start `kite-loader`:

```bash
sudo -E target/debug/kite-loader -s 3 TEST

# You will see output similar to this:
[INFO] [kite_loader] [TEST] 127.0.0.1:8080 - RPS: 102, Latency (p50/p90/p99): 1/1/1 ms
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License.