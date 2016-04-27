#!/bin/bash
set -euo pipefail
# This script is run every time an instance of our app - aka grain - starts up.
# This is the entry point for your application both when a grain is first launched
# and when a grain resumes after being previously shut down.

cd /opt/app
./sandpass \
  -db=/var/keepass.kdb \
  -listen='[::]:8000' \
  -static_dir=/opt/app \
  -templates_dir=/opt/app/templates
