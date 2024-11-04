# Kite

Kite is an observability tool to monitor application networking in a cluster.
It utilizes eBPF to collect metrics from processes and supports prometheus scraping.

> The project is WIP and does not work yet. I am concentrating on getting a full working demo for kubernetes workload.

## Architecture

Currently we have 3 components:

1. The kite daemon - the core application. Its job is to watch for applications to monitor, and load them with the (yet-to-be-written) eBPF program.
2. The init container - a container that runs before the main application container to set up the environment for eBPF monitoring.
3. The admission webhook - a Kubernetes admission controller that injects the init container into pods that need monitoring.

## Getting Started

TODO

## Configuration

TODO

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License.