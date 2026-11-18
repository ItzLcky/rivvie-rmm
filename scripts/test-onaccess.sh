#!/bin/sh
# On-access protection tests (crates/rmm-agent/tests/onaccess.rs) as root, in a privileged
# Docker container, so no sudo is needed. The source is mounted read-only; builds and the
# crate cache live in Docker volumes. Extra arguments go to the test binary.
#
#   scripts/test-onaccess.sh                  # debug build, the tests
#   scripts/test-onaccess.sh --release        # against a release agent (the shipped profile)
#   scripts/test-onaccess.sh --bench          # release, plus exec latency and an apt-get
#                                             # install with real-time protection off and block
#
# RMM_ONACCESS_LOG sets the sensor's RUST_LOG (e.g. rmm_agent::sensor::onaccess=debug).
set -eu
cd "$(dirname "$0")/.."
# The public half of the test's signing key (tests/onaccess.rs checks it matches).
TEST_KEY=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
mode=debug
case "${1:-}" in
    --release) mode=release; shift ;;
    --bench) mode=bench; shift ;;
esac
run='cargo test -p rmm-agent --test onaccess -- --ignored --test-threads=1 --nocapture "$@"'
case $mode in
    release|bench)
        run="RMM_UPDATE_PUBKEY=$TEST_KEY CARGO_TARGET_DIR=/target/release-key cargo build --release -p rmm-agent \
             && RMM_ONACCESS_BIN=/target/release-key/release/rmm-agent $run" ;;
esac

exec docker run --rm --privileged \
    -v "$PWD":/src:ro -w /src \
    -v rmm-onaccess-target:/target -e CARGO_TARGET_DIR=/target \
    -v rmm-onaccess-cargo:/usr/local/cargo/registry \
    -e RMM_ONACCESS_BENCH="$([ $mode = bench ] && echo 1)" -e RMM_ONACCESS_LOG \
    rust:1 sh -c "$run" sh "$@"
