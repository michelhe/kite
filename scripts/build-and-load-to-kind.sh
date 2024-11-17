#!/bin/bash

set -eo pipefail

# This script builds the Docker image and uploads it to a local Kind cluster

# Build the Docker image
docker buildx build -t kite:dev -f Dockerfile .

# Cluster name can be defined by the KIND_CLUSTER_NAME environment variable or defaults to "kind"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"

# Load the Docker image into Kind
kind load docker-image kite:dev