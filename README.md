# wifi_db
Script to parse Aircrack-ng captures to a SQLite database

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
  -t LAT, --lat LAT     insert a fake lat in all database
  -n LON, --lon LON     insert a fake lat in all database
  --source [{aircrack-ng,kismet,wigle}]
                        source from capture data (default: aircrack-ng) 
```

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

- [ ] Overwrite if there is new info (old ESSID='', New ESSID='WIFI') (Work in progress)

---------

This program is a continuation of a part of: https://github.com/T1GR3S/airo-heat

## Author

- Raúl Calvo Laorden (@raulcalvolaorden)

## License

[GNU General Public License v3.0](https://github.com/RaulCalvoLaorden/wifi_db/blob/master/LICENSE)
