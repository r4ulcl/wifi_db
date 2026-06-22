#!/usr/bin/env bash
#
# Run the wifi_db test suite against an already-built Docker image.
#
# The production image is intentionally test-free and does not contain the
# test fixtures (see .dockerignore). This script mounts test_data into the
# built image and runs pytest with the image's own Python, tshark and hcxtools.
# That way the exact artifact that would be released is what gets tested.
#
# Usage:
#   ./test_docker.sh [IMAGE]
#
# IMAGE defaults to "wifi_db:test". Exits non-zero if any test fails, so it can
# gate a release (in CI) or a local build.

set -euo pipefail

IMAGE="${1:-wifi_db:test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "${SCRIPT_DIR}/test_data" ]; then
    echo "ERROR: ${SCRIPT_DIR}/test_data not found; cannot run tests." >&2
    exit 1
fi

echo ">> Testing image: ${IMAGE}"

# Override the entrypoint to run pytest instead of wifi_db.py. test_data is
# mounted read-only at the path the tests expect (./test_data, cwd is /app).
docker run --rm \
    --entrypoint python3 \
    -v "${SCRIPT_DIR}/test_data:/app/test_data:ro" \
    -w /app \
    "${IMAGE}" -m pytest

echo ">> Tests passed for ${IMAGE}"
