CREATE TABLE IF NOT EXISTS AP
(
    bssid TEXT NOT NULL,
    ssid TEXT,
    cloaked BOOLEAN,
    manuf TEXT,
    channel int,
    frequency int,
    carrier TEXT,
    encryption TEXT,
    packetsTotal int,
    lat_t REAL,
    lon_t REAL,
    mfpc BOOLEAN,
    mfpr BOOLEAN,
    CONSTRAINT Key1 PRIMARY KEY (bssid)
);

CREATE TABLE IF NOT EXISTS Client
(
    mac TEXT NOT NULL,
    ssid TEXT,
    manuf TEXT,
    type TEXT,
    packetsTotal int,
    device TEXT,
    CONSTRAINT Key1 PRIMARY KEY (mac)
);


CREATE TABLE IF NOT EXISTS SeenClient
(
    mac TEXT NOT NULL,
    time datetime NOT NULL,
    tool TEXT,
    signal_rssi int,
    lat REAL,
    lon REAL,
    alt REAL,
    CONSTRAINT Key3 PRIMARY KEY (time,mac),
    CONSTRAINT SeenClients FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS Connected
(
    bssid TEXT NOT NULL,
    mac TEXT NOT NULL,
    CONSTRAINT Key4 PRIMARY KEY (bssid,mac),
    CONSTRAINT Relationship2 FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT Relationship3 FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS WPS
(
    bssid TEXT NOT NULL,
    wlan_ssid TEXT NOT NULL,
    wps_version TEXT NOT NULL,
    wps_device_name TEXT NOT NULL,
    wps_model_name TEXT NOT NULL,
    wps_model_number TEXT NOT NULL,
    wps_config_methods TEXT NOT NULL,
    wps_config_methods_keypad TEXT NOT NULL,
    CONSTRAINT KeyWPS PRIMARY KEY (bssid),
    CONSTRAINT RelationshipWPS FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS SeenAp
(
    bssid TEXT NOT NULL,
    time datetime NOT NULL,
    tool TEXT,
    signal_rssi int,
    lat REAL,
    lon REAL,
    alt REAL,
    bsstimestamp timestamp,
    CONSTRAINT Key3 PRIMARY KEY (time,bssid),
    CONSTRAINT SeenAp FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS Probe
(
    mac TEXT NOT NULL,
    ssid TEXT NOT NULL,
    time datetime,
    CONSTRAINT Key5 PRIMARY KEY (mac,ssid),
    CONSTRAINT ProbesSent FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS Handshake
(
    bssid TEXT NOT NULL,
    mac TEXT NOT NULL,
    file TEXT NOT NULL,
    hashcat TEXT,
    CONSTRAINT Key6 PRIMARY KEY (bssid,mac,file)
    CONSTRAINT FRelationship4 FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT FRelationship5 FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Identity
(
    bssid TEXT NOT NULL,
    mac TEXT NOT NULL,
    identity TEXT NOT NULL,
    method TEXT NOT NULL,
    CONSTRAINT Key7 PRIMARY KEY (bssid,mac,identity)
    CONSTRAINT FRelationship6 FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT FRelationship7 FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE
);
