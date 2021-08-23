FROM python
#:3.8-slim-buster

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

RUN mkdir /captures/

#CMD ["/app/wifi_db.py"]
ENTRYPOINT ["python", "/app/wifi_db.py", "/captures/", "-d", "/db.SQLITE"]
