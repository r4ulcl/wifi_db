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
    firstTimeSeen timestamp,
    wpa_version TEXT,
    akm_suites TEXT,
    pairwise_ciphers TEXT,
    group_cipher TEXT,
    enterprise BOOLEAN,
    pmf TEXT,
    rsn_capabilities TEXT,
    wlan_ssid TEXT,
    wps_version TEXT,
    wps_device_name TEXT,
    wps_model_name TEXT,
    wps_model_number TEXT,
    wps_config_methods TEXT,
    wps_config_methods_keypad TEXT,
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
    randomized BOOLEAN,
    firstTimeSeen timestamp,
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
    hashSHA TEXT NOT NULL,
    hashcat TEXT,
    CONSTRAINT Key6 PRIMARY KEY (bssid,mac,file)
    CONSTRAINT FRelationship4 FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT FRelationship5 FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT FRelationship8 FOREIGN KEY (file,hashSHA) REFERENCES Files (file,hashSHA) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Identity
(
    bssid TEXT NOT NULL,
    mac TEXT NOT NULL,
    identity TEXT NOT NULL,
    method TEXT NOT NULL,
    realm TEXT,
    CONSTRAINT Key7 PRIMARY KEY (bssid,mac,identity)
    CONSTRAINT FRelationship6 FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT FRelationship7 FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS Files
(
    file TEXT NOT NULL,
    processed BOOLEAN,
    hashSHA TEXT NOT NULL,
    time datetime,
    CONSTRAINT Key8 PRIMARY KEY (file,hashSHA)
);


CREATE TABLE IF NOT EXISTS Certificate
(
    bssid TEXT NOT NULL,
    mac TEXT,
    cert_type TEXT,
    file TEXT,
    cert_index int,
    version TEXT,
    serial_number TEXT,
    signature_algorithm TEXT,
    issuer TEXT,
    subject TEXT,
    not_before timestamp,
    not_after timestamp,
    subject_cn TEXT,
    subject_o TEXT,
    subject_ou TEXT,
    issuer_cn TEXT,
    issuer_o TEXT,
    issuer_ou TEXT,
    public_key_algorithm TEXT,
    public_key_size int,
    public_key_curve TEXT,
    public_key_exponent TEXT,
    subject_alt_names TEXT,
    key_usage TEXT,
    ext_key_usage TEXT,
    is_ca BOOLEAN,
    path_length int,
    self_signed BOOLEAN,
    authority_key_id TEXT,
    subject_key_id TEXT,
    crl_urls TEXT,
    ocsp_urls TEXT,
    validity_days int,
    sha1_fingerprint TEXT,
    sha256_fingerprint TEXT NOT NULL,
    CONSTRAINT KeyCert PRIMARY KEY (bssid,sha256_fingerprint),
    CONSTRAINT RelationshipCert FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS EAPMD5
(
    bssid TEXT NOT NULL,
    mac TEXT NOT NULL,
    identity TEXT,
    eap_id TEXT NOT NULL,
    challenge TEXT,
    response TEXT,
    hashcat TEXT,
    file TEXT,
    CONSTRAINT KeyEAPMD5 PRIMARY KEY (bssid,mac,eap_id),
    CONSTRAINT RelationshipEAPMD5AP FOREIGN KEY (bssid) REFERENCES AP (bssid) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT RelationshipEAPMD5Client FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS ProbeFingerprint
(
    mac TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    ie_order TEXT,
    file TEXT,
    CONSTRAINT KeyProbeFingerprint PRIMARY KEY (mac,fingerprint),
    CONSTRAINT RelationshipProbeFingerprint FOREIGN KEY (mac) REFERENCES Client (mac) ON UPDATE CASCADE ON DELETE CASCADE
);