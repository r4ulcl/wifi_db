# Compile hcxtools
FROM ubuntu:22.04 as hcxtools-builder

WORKDIR /app

# A single retrying apt-get layer. Retries make the layer resilient to the
# transient failures seen when this stage is built for linux/arm64 under QEMU
# emulation (apt/dpkg child processes occasionally crash, giving exit 100).
# ca-certificates is required for the https git clone below.
RUN apt-get update -o Acquire::Retries=5 \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git make gcc pkg-config python3-pip \
        zlib1g-dev libcurl4-openssl-dev libssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Clone hcxtools and install
RUN git clone -b 6.3.1 https://github.com/ZerBea/hcxtools.git /app/hcxtools

WORKDIR /app/hcxtools
RUN make \
    && make install

WORKDIR /app
RUN rm -rf /app/hcxtools

FROM ubuntu:22.04

WORKDIR /app

# Install dependencies
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -o Acquire::Retries=5 \
    && DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y --no-install-recommends \
        ca-certificates python3-pip tshark git libcurl4-openssl-dev libssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
 
# Copy hcxtools binaries
COPY --from=hcxtools-builder /usr/bin/hcx* /usr/bin/


# Copy and install Python dependencies

RUN python3 -m pip install --no-cache-dir --upgrade pip==24.0
    
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy your application code
COPY . .

# Run tests and remove test data
RUN python3 -m pytest \
    && rm -rf test_data

# Create a captures directory and a non-root user to run the app.
# /app holds the default database (db.SQLITE) so SQLite can also create its
# journal/WAL files there; both /app and /captures are owned by the user.
RUN mkdir -p /captures/ \
    && useradd --create-home --shell /usr/sbin/nologin wifidb \
    && chown -R wifidb:wifidb /app /captures

USER wifidb

# Set the entry point
ENTRYPOINT ["python3", "/app/wifi_db.py", "/captures/", "-d", "/app/db.SQLITE"]

