# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: compile hcxtools
#
# Built on the same Alpine base as the final stage so the resulting binary
# links against the exact musl / libcurl / libssl / zlib present at runtime.
# All build tooling and -dev headers stay in this stage and never reach the
# final image.
#
# wifi_db only ever calls hcxpcapngtool, so only that target is built and only
# that one binary is shipped. hcxtools 6.3.1 calls basename() without including
# <libgen.h>; that compiles under glibc but not under musl, so the header is
# injected before building.
# ---------------------------------------------------------------------------
FROM python:3.12-alpine AS hcxtools-builder

RUN apk add --no-cache \
        build-base git pkgconf \
        curl-dev openssl-dev zlib-dev linux-headers

RUN git clone --depth 1 -b 6.3.1 https://github.com/ZerBea/hcxtools.git /tmp/hcxtools \
    && sed -i '1i #include <libgen.h>' /tmp/hcxtools/hcxpcapngtool.c \
    && make -C /tmp/hcxtools hcxpcapngtool \
    && install -m 0755 /tmp/hcxtools/hcxpcapngtool /usr/bin/hcxpcapngtool \
    && strip /usr/bin/hcxpcapngtool \
    && rm -rf /tmp/hcxtools

# ---------------------------------------------------------------------------
# Stage 2: final runtime image
#
# Alpine + musl keeps the image small (~230 MB, vs ~360 MB on Debian slim).
# This image is intentionally test-free: the suite is NOT run during the build
# and the test fixtures are not copied in (see .dockerignore). Tests run against
# the built image afterwards by the release pipeline / test_docker.sh, so a
# failing test blocks the release instead of every developer build.
# ---------------------------------------------------------------------------
FROM python:3.12-alpine

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Runtime dependencies only: tshark for pyshark, and the shared libraries the
# hcxpcapngtool binary links against (the -dev packages and their headers stay
# in the builder stage). ca-certificates is needed for the update HTTPS check.
# --no-cache leaves no apk index behind.
RUN apk add --no-cache \
        ca-certificates tshark libcurl libcrypto3 libssl3 zlib

# Copy only the single hcxtools binary wifi_db uses, from the builder stage.
COPY --from=hcxtools-builder /usr/bin/hcxpcapngtool /usr/bin/hcxpcapngtool

# Install Python dependencies first so the layer is cached across code changes.
# --no-compile keeps .pyc bytecode out of the image; PYTHONDONTWRITEBYTECODE
# stops it being written at runtime too, so imports recompile on first use.
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --no-compile -r requirements.txt

# Application code. The .dockerignore keeps the test fixtures, .git, the local
# virtualenv and docs out of this layer.
COPY . .

# Create a captures directory and a non-root user to run the app.
# /app holds the default database (db.SQLITE) so SQLite can also create its
# journal/WAL files there; both /app and /captures are owned by the user.
RUN mkdir -p /captures/ \
    && adduser -D -s /sbin/nologin wifidb \
    && chown -R wifidb:wifidb /app /captures

USER wifidb

# Set the entry point
ENTRYPOINT ["python3", "/app/wifi_db.py", "/captures/", "-d", "/app/db.SQLITE"]
