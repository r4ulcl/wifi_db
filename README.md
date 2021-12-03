<<<<<<< Updated upstream
# wifi_db
Script to parse Aircrack-ng captures into a SQLite database.

## Install

### Build Docker

``` bash
git clone https://github.com/RaulCalvoLaorden/wifi_db

docker build -t wifi_db .
```

## Manual installation

``` bash

sudo apt install python3-pip

git clone https://github.com/RaulCalvoLaorden/wifi_db

cd wifi_db

pip3 install -r requirements.txt 

```

## Usage

### Scan with airodump-ng

Run airodump-ng saving the output with -w:

``` bash
sudo airodump-ng wlan0mon -w scan
```

``` bash
sudo airodump-ng wlan0mon -w scan --manufacturer --wps --gpsd
```

### Create the SQLite database using Docker

``` bash
CAPTURESFOLDER=/home/user/wifi #Folder with captures
touch db.SQLITE
docker run -v $PWD/db.SQLITE:/db.SQLITE -v $CAPTURESFOLDER:/captures/ wifi_db
```

- '-v $PWD/db.SQLITE:/db.SQLITE': To save de output in current folder db.SQLITE file
- '-v $CAPTURESFOLDER:/captures/': To share the folder with the captures with the docker

### Create the SQLite database using manual installation

Once the capture is created, we can create the database by importing the capture. To do this, put the name of the capture without format.

``` bash
python3 wifi_db.py scan-01
```

In the event that we have multiple captures we can load the folder in which they are directly. And with -d we can rename the output database.

``` bash
python3 wifi_db.py -d database.sqlite scan-folder
```

To open the database we can use sqlitebrowser:

``` bash
sqlitebrowser database.sqlite
```

### Optional arguments

``` bash
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  --debug               increase output verbosity to debug
  -t LAT, --lat LAT     insert a fake lat into the entire database
  -n LON, --lon LON     insert a fake lat into the entire database
  --source [{aircrack-ng,kismet,wigle}]
                        source from capture data (default: aircrack-ng) 
```

### Open database

The database can be open with:
- [sqlitebrowser](https://sqlitebrowser.org/)
- [wifi_data](https://github.com/RaulCalvoLaorden/wifi_data)

### Kismet

TODO

### Wigle

TODO

## Views

- ProbeClients: Shows the complete information of the users with their probes

- ConnectedAP: It shows the information of the clients connected to the APs. With this view you can easily filter by scope and check connected clients.

- ProbeClientsConnected: Displays the list of poor users connected to WiFi networks. This is useful to check the problems of users connecting to networks in the scope.

## TODO

- [X] Aircrack-ng

- [X] All in 1 file (and separately)

- [ ] Kismet

- [ ] Wigle

- [X] install 

- [X] parse all files in folder -f --folder

- [X] Fix Extended errors, tildes, etc (fixed in aircrack-ng 1.6)

- [ ] Support bash multi files: "capture*-1*"

- [X] Script to delete client or AP from DB (mac). - (Whitelist)

- [X] Whitelist to don't add mac to DB (file whitelist.txt, add macs, create DB)

- [X] Overwrite if there is new info (old ESSID='', New ESSID='WIFI')

---------

This program is a continuation of a part of: https://github.com/T1GR3S/airo-heat

## Author

- Raúl Calvo Laorden (@raulcalvolaorden)

## License

[GNU General Public License v3.0](https://github.com/RaulCalvoLaorden/wifi_db/blob/master/LICENSE)
=======
# wifi_db
Script to parse Aircrack-ng captures into a SQLite database.

## Install

### From [DockerHub](https://hub.docker.com/r/raulcalvolaorden/wifi_db) (RECOMMENDED)

``` bash
docker pull raulcalvolaorden/wifi_db
``` 

### Build Docker

``` bash
git clone https://github.com/RaulCalvoLaorden/wifi_db

docker build -t wifi_db .
```

### Manual installation

Dependencies:

- tshark
- hcxtools

``` bash
sudo apt install tshark

git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools
make 
sudo make install
```

Installation

``` bash

sudo apt install python3-pip

git clone https://github.com/RaulCalvoLaorden/wifi_db

cd wifi_db

pip3 install -r requirements.txt 

```


## Usage

### Scan with airodump-ng

Run airodump-ng saving the output with -w:

``` bash
sudo airodump-ng wlan0mon -w scan --manufacturer --wps --gpsd
```

### Create the SQLite database using Docker

``` bash
#Folder with captures
CAPTURESFOLDER=/home/user/wifi

# Output database
touch db.SQLITE

docker run -v $PWD/db.SQLITE:/db.SQLITE -v $CAPTURESFOLDER:/captures/ wifi_db -H
```

- '-v $PWD/db.SQLITE:/db.SQLITE': To save de output in current folder db.SQLITE file
- '-v $CAPTURESFOLDER:/captures/': To share the folder with the captures with the docker


### Create the SQLite database using manual installation

Once the capture is created, we can create the database by importing the capture. To do this, put the name of the capture without format.

``` bash
python3 wifi_db.py scan-01 -H
```

In the event that we have multiple captures we can load the folder in which they are directly. And with -d we can rename the output database.

``` bash
python3 wifi_db.py -d database.sqlite scan-folder -H
```

### Open database

The database can be open with:
- [sqlitebrowser](https://sqlitebrowser.org/)
- [wifi_data](https://github.com/RaulCalvoLaorden/wifi_data)


### Optional arguments

``` bash
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  --debug               increase output verbosity to debug
  -H, --hcxpcapngtool   Get hashcat hashes using hcxpcapngtool (has to be installed)
  -t LAT, --lat LAT     insert a fake lat into the entire database
  -n LON, --lon LON     insert a fake lat into the entire database
  --source [{aircrack-ng,kismet,wigle}]
                        source from capture data (default: aircrack-ng) 
```

### Kismet

TODO

### Wigle

TODO

## Views

- ProbeClients: It shows the complete information of the users with their probes

- ConnectedAP: It shows the information of the clients connected to the APs. With this view you can easily filter by scope and check connected clients.

- ProbeClientsConnected: Displays the list of poor users connected to WiFi networks. This is useful to check the problems of users connecting to networks in the scope.

- HandshakeAP: Show the APs, client file and hashcat hash for each handshake in the Handshake table

- IdentityAP: Show the APs, client and Identity for each identity its table

## TODO

- [X] Aircrack-ng

- [X] All in 1 file (and separately)

- [ ] Kismet

- [ ] Wigle

- [X] install 

- [X] parse all files in folder -f --folder

- [X] Fix Extended errors, tildes, etc (fixed in aircrack-ng 1.6)

- [ ] Support bash multi files: "capture*-1*"

- [X] Script to delete client or AP from DB (mac). - (Whitelist)

- [X] Whitelist to don't add mac to DB (file whitelist.txt, add macs, create DB)

- [X] Overwrite if there is new info (old ESSID='', New ESSID='WIFI')

- [X] Table Handhsakes and PMKID

- [x] Hashcat hash format 22000

- [ ] Table files, if file exists skip (full path)

---------

This program is a continuation of a part of: https://github.com/T1GR3S/airo-heat

## Author

- Raúl Calvo Laorden (@raulcalvolaorden)

## License

[GNU General Public License v3.0](https://github.com/RaulCalvoLaorden/wifi_db/blob/master/LICENSE)
>>>>>>> Stashed changes
