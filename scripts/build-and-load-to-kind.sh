#!/bin/bash

set -eo pipefail

# This script builds the Docker image and uploads it to a local Kind cluster

# Build the Docker image
docker build -t kite:dev -f Dockerfile .

# Load the Docker image into Kind
kind load docker-image kite:dev