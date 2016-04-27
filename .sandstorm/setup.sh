#!/bin/bash

# When you change this file, you must take manual action. Read this doc:
# - https://docs.sandstorm.io/en/latest/vagrant-spk/customizing/#setupsh

set -euo pipefail
curl -sSL https://storage.googleapis.com/golang/go1.6.2.linux-amd64.tar.gz | \
  tar -C /usr/local -xzf -
