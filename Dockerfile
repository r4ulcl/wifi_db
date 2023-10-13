FROM ubuntu:23.10
#FROM wireshark/wireshark-ubuntu-dev
#:3.8-slim-buster

WORKDIR /app

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install tshark -y --allow-change-held-packages \ 
python3 python3-pip make git pkg-config libcurl4-openssl-dev libssl-dev pkg-config && apt-get clean \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY . .

# Install hcxtools
RUN git clone https://github.com/ZerBea/hcxtools.git ; cd hcxtools ; make ; make install

RUN mkdir /captures/

#CMD ["/app/wifi_db.py"]
ENTRYPOINT ["python3", "/app/wifi_db.py", "/captures/", "-d", "/db.SQLITE"]
                                                                             