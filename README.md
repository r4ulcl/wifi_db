# wifi_db
Script to parse Aircrack-ng captures to a SQLite database

## Install

``` bash

sudo apt install python3-pip

git clone https://github.com/RaulCalvoLaorden/wifi_db

cd wifi_db

pip3 install -r requirements.txt 

```

## Usage

- --help / -h to help
- --folder / -f to process a folder

### Aircrack-ng

- python3 wifi_db.py database.sqlite capture-01

- python3 wifi_db.py database.sqlite -f capture-folder

### Kismet

TODO

## Views

- 

- 

- 

## TODO

- [X] Aircrack-ng

- [X] All in 1 file (and separately)

- [ ] Kismet

- [ ] Wigle

- [X] install 

- [X] parse all files in folder -f --folder

- [X] Fix Extended errors, tildes, etc (fixed in aircrack-ng 1.6)

- [ ] Support bash multi files: "capture*-1*"

- [ ] Script to delete client or AP from DB (mac). 

- [ ] Whitelist to dont add mac to DB (file whitelist.txt, add macs, create DB)

---------

This program is a continuation of a part of: https://github.com/T1GR3S/airo-heat

## Author

- Raúl Calvo Laorden (@raulcalvolaorden)

## License

[GNU General Public License v3.0](https://github.com/RaulCalvoLaorden/wifi_db/blob/master/LICENSE)
