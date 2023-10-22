# Compile hcxtools
FROM ubuntu:22.04 as hcxtools-builder

WORKDIR /app

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install python3-pip make git zlib1g-dev  -y \
    && apt-get install pkg-config libcurl4-openssl-dev libssl-dev zlib1g-dev make gcc -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Clone hcxtools and install
RUN git clone -b 6.3.1 https://github.com/ZerBea/hcxtools.git /app/hcxtools \
    && cd /app/hcxtools \
    && make \
    && make install \
    && cd /app \
    && rm -rf /app/hcxtools

FROM ubuntu:22.04

WORKDIR /app

# Install dependencies
ENV DEBIAN_FRONTEND noninteractive
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get update && apt-get install -y --no-install-recommends python3-pip tshark git libcurl4-openssl-dev libssl-dev -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/* 
 
# Copy hcxtools binaries
COPY --from=hcxtools-builder /usr/bin/hcx* /usr/bin/


# Copy and install Python dependencies
RUN python3 -m pip install --no-cache-dir -U pip \
    && python3 -m pip install --no-cache-dir pytest
    
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy your application code
COPY . .

# Run tests and remove test data
RUN python3 -m pytest \
    && rm -rf test_data

# Create a captures directory
RUN mkdir /captures/

# Set the entry point
ENTRYPOINT ["python3", "/app/wifi_db.py", "/captures/", "-d", "/db.SQLITE"]

