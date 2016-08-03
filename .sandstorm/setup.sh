#!/bin/bash

# When you change this file, you must take manual action. Read this doc:
# - https://docs.sandstorm.io/en/latest/vagrant-spk/customizing/#setupsh

set -euo pipefail
GOVERSION='go1.6.3'
if ! [[ -f /usr/local/go/VERSION && "$(cat /usr/local/go/VERSION)" == "$GOVERSION" ]]; then
  echo "Downloading $GOVERSION"
  rm -rf /usr/local/go
  curl -sSL "https://storage.googleapis.com/golang/${GOVERSION}.linux-amd64.tar.gz" | \
    tar -C /usr/local -xzf -
fi
