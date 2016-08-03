#!/bin/bash
set -euo pipefail
# This script is run in the VM each time you run `vagrant-spk dev`.  This is
# the ideal place to invoke anything which is normally part of your app's build
# process - transforming the code in your repository into the collection of files
# which can actually run the service in production
cd /opt/app
export GOPATH=/gopath
if [[ ! -h "$GOPATH/src/zombiezen.com/go/sandpass" ]]; then
  mkdir -p "$GOPATH/src/zombiezen.com/go/"
  ln -s /opt/app "$GOPATH/src/zombiezen.com/go/sandpass"
fi
/usr/local/go/bin/go install zombiezen.com/go/sandpass
cp --archive "$GOPATH/bin/sandpass" sandpass
exit 0
