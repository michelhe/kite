#!/bin/bash

set -eo pipefail

curdir=$(dirname "$0")

# Create a Kind cluster
kind create cluster --config ${curdir}/kind.yaml

# Load the Docker image into Kind
kind load docker-image kite:dev

# Install metrics-server
curl -sSL https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml | sed '/--kubelet-use-node-status-port/ a\        - --kubelet-insecure-tls' | kubectl apply -f -

# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.3/cert-manager.yaml