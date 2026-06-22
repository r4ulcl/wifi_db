# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: compile hcxtools
# Built on the same base as the final stage so the resulting binaries link
# against the exact libcurl/libssl/zlib versions present at runtime.
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS hcxtools-builder

# A single retrying apt-get layer. Retries make the layer resilient to the
# transient failures seen when this stage is built for linux/arm64 under QEMU
# emulation (apt/dpkg child processes occasionally crash, giving exit 100).
RUN apt-get update -o Acquire::Retries=5 \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git make gcc pkg-config \
        zlib1g-dev libcurl4-openssl-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 -b 6.3.1 https://github.com/ZerBea/hcxtools.git /tmp/hcxtools \
    && make -C /tmp/hcxtools \
    && make -C /tmp/hcxtools install \
    && rm -rf /tmp/hcxtools

# ---------------------------------------------------------------------------
# Stage 2: final runtime image
#
# This image is intentionally test-free: the suite is NOT run during the build
# and the test fixtures are not copied in (see .dockerignore). Tests run against
# the built image afterwards by the release pipeline / test_docker.sh, so a
# failing test blocks the release instead of every developer build.
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Runtime dependencies only: tshark for pyshark, and the shared libraries the
# hcxtools binaries link against (the -dev packages and their headers stay in
# the builder stage). ca-certificates is needed for the update HTTPS check.
RUN apt-get update -o Acquire::Retries=5 \
    && apt-get install -y --no-install-recommends \
        ca-certificates tshark libcurl4 libssl3 zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled hcxtools binaries from the builder stage.
COPY --from=hcxtools-builder /usr/bin/hcx* /usr/bin/

# Install Python dependencies first so the layer is cached across code changes.
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Application code. The .dockerignore keeps the test fixtures, .git, the local
# virtualenv and docs out of this layer.
COPY . .

# Create a captures directory and a non-root user to run the app.
# /app holds the default database (db.SQLITE) so SQLite can also create its
# journal/WAL files there; both /app and /captures are owned by the user.
RUN mkdir -p /captures/ \
    && useradd --create-home --shell /usr/sbin/nologin wifidb \
    && chown -R wifidb:wifidb /app /captures

USER wifidb

# Set the entry point
ENTRYPOINT ["python3", "/app/wifi_db.py", "/captures/", "-d", "/app/db.SQLITE"]
