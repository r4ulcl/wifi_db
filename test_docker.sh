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
# pytest generates a Cobertura coverage.xml (see pytest.ini / .coveragerc). A
# world-writable scratch directory is mounted at /host_out so that report
# survives the --rm container; it is then moved to ./coverage.xml, ready to
# upload to Codacy:
#     export CODACY_PROJECT_TOKEN=<repository coverage token>
#     bash <(curl -Ls https://coverage.codacy.com/get.sh) report -r coverage.xml
# (run from the repo root of the checked-out branch; see
#  https://docs.codacy.com/coverage-reporter/).
#
# The scratch dir (rather than mounting the repo root itself) is needed because
# the image runs as the non-root "wifidb" user, whose UID does not match the
# owner of the checkout on the host (e.g. the GitHub Actions "runner" user),
# so writing the report into a mounted repo root is denied. It lives under the
# repo root, not /tmp, because the checkout is already known to be visible to
# the Docker daemon (the test_data mount above relies on that), whereas /tmp
# is not shared with the daemon in every setup.
OUT_DIR="$(mktemp -d "${SCRIPT_DIR}/.coverage_out.XXXXXX")"
chmod 0777 "${OUT_DIR}"
trap 'rm -rf "${OUT_DIR}"' EXIT

docker run --rm \
    --entrypoint python3 \
    -v "${SCRIPT_DIR}/test_data:/app/test_data:ro" \
    -v "${OUT_DIR}:/host_out" \
    -w /app \
    "${IMAGE}" -m pytest --cov-report=xml:/host_out/coverage.xml

mv "${OUT_DIR}/coverage.xml" "${SCRIPT_DIR}/coverage.xml"

echo ">> Tests passed for ${IMAGE}; coverage written to ${SCRIPT_DIR}/coverage.xml"
