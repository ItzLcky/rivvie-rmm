#!/bin/sh
curl -fsSL https://example.invalid/pkg.tar.gz -o pkg.tar.gz
sha256sum -c pkg.sha256 && tar xzf pkg.tar.gz
