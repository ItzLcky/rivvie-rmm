#!/bin/sh
# Fetches a release, verifies it, unpacks it.
set -eu
curl -fsSL https://example.invalid/release.tar.gz -o /tmp/release.tar.gz
echo "$RELEASE_SHA256  /tmp/release.tar.gz" | sha256sum -c -
tar -xzf /tmp/release.tar.gz -C /opt
