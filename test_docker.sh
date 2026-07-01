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
#
# pytest generates a Cobertura coverage.xml (see pytest.ini / .coveragerc). The
# repo root is mounted at /host_out so that report survives the --rm container
# and lands at ./coverage.xml on the host, ready to upload to Codacy:
#     export CODACY_PROJECT_TOKEN=<repository coverage token>
#     bash <(curl -Ls https://coverage.codacy.com/get.sh) report -r coverage.xml
# (run from the repo root of the checked-out branch; see
#  https://docs.codacy.com/coverage-reporter/).
docker run --rm \
    --entrypoint python3 \
    -v "${SCRIPT_DIR}/test_data:/app/test_data:ro" \
    -v "${SCRIPT_DIR}:/host_out" \
    -w /app \
    "${IMAGE}" -m pytest --cov-report=xml:/host_out/coverage.xml

echo ">> Tests passed for ${IMAGE}; coverage written to ${SCRIPT_DIR}/coverage.xml"
