#!/usr/bin/env bash
# Runs the S3 storage test (rmm-server's `s3_against_minio`) against a throwaway MinIO in Docker:
# multipart uploads around the part boundaries, ranged reads, aborted uploads, deletes.
# CI runs the same test in the `s3` job.
#
#   scripts/minio-test.sh
#
# MINIO_IMAGE overrides the image, MINIO_PORT the host port (default 59000).
set -euo pipefail
cd "$(dirname "$0")/.."
image=${MINIO_IMAGE:-ghcr.io/coollabsio/minio:RELEASE.2025-10-15T17-29-55Z}
port=${MINIO_PORT:-59000}
name=rmm-minio-test-$$
docker run -d --rm --name "$name" -p "$port:9000" -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin "$image" server /data >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 60); do
  curl -fs "http://127.0.0.1:$port/minio/health/ready" >/dev/null && break
  sleep 1
done
curl -fs "http://127.0.0.1:$port/minio/health/ready" >/dev/null || { docker logs "$name" >&2; echo "MinIO didn't start" >&2; exit 1; }
RMM_TEST_S3_ENDPOINT="http://127.0.0.1:$port" cargo test -p rmm-server s3_against_minio -- --ignored --nocapture
