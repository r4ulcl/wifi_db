FROM ubuntu
#FROM wireshark/wireshark-ubuntu-dev
#:3.8-slim-buster

WORKDIR /app

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install tshark -y --allow-change-held-packages
RUN apt-get install python3 python3-pip make git -y
RUN apt-get install pkg-config -y
RUN apt-get install libcurl4-openssl-dev libssl-dev pkg-config -y #Dependencies
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

# Install hcxtools
RUN git clone https://github.com/ZerBea/hcxtools.git ; cd hcxtools ; make ; make install

RUN mkdir /captures/

#CMD ["/app/wifi_db.py"]
ENTRYPOINT ["python3", "/app/wifi_db.py", "/captures/", "-d", "/db.SQLITE", "-H"]
                                                                             