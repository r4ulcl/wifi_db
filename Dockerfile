# Compile hcxtools
FROM ubuntu:22.04 as hcxtools-builder

WORKDIR /app

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install python3-pip make git -y \
    && apt-get install pkg-config -y \
    && apt-get install libcurl4-openssl-dev libssl-dev pkg-config -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Clone hcxtools and install
RUN git clone https://github.com/ZerBea/hcxtools.git /app/hcxtools \
    && cd /app/hcxtools \
    && make \
    && make install \
    && cd /app \
    && rm -rf /app/hcxtools

FROM python:3.9-slim-buster

WORKDIR /app

# Install dependencies
ENV DEBIAN_FRONTEND noninteractive
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get update && apt-get install -y --no-install-recommends tshark -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/* 
 
# Copy hcxtools binaries
COPY --from=hcxtools-builder /usr/bin/hcx* /usr/bin/


# Copy and install Python dependencies
RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir pytest
    
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy your application code
COPY . .

# Run tests and remove test data
RUN python -m pytest \
    && rm -rf test_data

# Create a captures directory
RUN mkdir /captures/

# Set the entry point
ENTRYPOINT ["python3", "/app/wifi_db.py", "/captures/", "-d", "/db.SQLITE"]

