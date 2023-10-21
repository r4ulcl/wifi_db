FROM ubuntu:22.04                                                                                                                                     
#FROM wireshark/wireshark-ubuntu-dev
#:3.8-slim-buster

WORKDIR /app

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install tshark -y --allow-change-held-packages \
    && apt-get install python3 python3-pip make git -y \
    && apt-get install pkg-config -y \
    && apt-get install libcurl4-openssl-dev libssl-dev pkg-config -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

# Checek the code
RUN python3 -m pip install pytest ; python3 -m pytest

RUN rm -r test_data

# Install hcxtools
RUN git clone https://github.com/ZerBea/hcxtools.git ; cd hcxtools ; make ; make install

RUN mkdir /captures/

ENTRYPOINT ["python3", "/app/wifi_db.py", "/captures/", "-d", "/db.SQLITE"]
