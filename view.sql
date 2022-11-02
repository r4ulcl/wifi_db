CREATE VIEW IF NOT EXISTS ProbeClients AS
SELECT Probe.mac, Client.manuf, Client.type, Client.packetsTotal, Probe.ssid
from Probe join Client on Probe.mac  = Client.mac
ORDER BY Probe.ssid;

CREATE VIEW IF NOT EXISTS ConnectedAP AS
SELECT Connected.bssid, AP.ssid, Connected.mac, Client.manuf
FROM Connected JOIN AP ON Connected.bssid = AP.bssid  JOIN Client ON Connected.mac = Client.mac
ORDER BY Connected.bssid;


CREATE VIEW IF NOT EXISTS ProbeClientsConnected AS
SELECT ConnectedAP.bssid, ConnectedAP.ssid, Probe.mac, Client.manuf, Client.type, Client.packetsTotal, Probe.ssid as "Probe"
from Probe join Client on Probe.mac  = Client.mac join ConnectedAP on Probe.mac = ConnectedAP.mac
where ConnectedAP.ssid != Probe
ORDER BY Probe.ssid;

CREATE VIEW IF NOT EXISTS HandshakeAP AS
SELECT Handshake.bssid, AP.ssid, Handshake.mac, Client.manuf, Handshake.file, Handshake.hashcat
FROM Handshake JOIN AP ON Handshake.bssid = AP.bssid  JOIN Client ON Handshake.mac = Client.mac
ORDER BY Handshake.bssid;

CREATE VIEW IF NOT EXISTS HandshakeAPUnique AS
SELECT Handshake.bssid, AP.ssid, Handshake.mac, Client.manuf, Handshake.file, Handshake.hashcat
FROM Handshake JOIN AP ON Handshake.bssid = AP.bssid  JOIN Client ON Handshake.mac = Client.mac
WHERE hashcat != '' GROUP BY AP.ssid ORDER BY Handshake.bssid;

CREATE VIEW IF NOT EXISTS IdentityAP AS
SELECT Identity.bssid, AP.ssid, Identity.mac, Client.manuf, Identity.identity
FROM Identity JOIN AP ON Identity.bssid = AP.bssid  JOIN Client ON Identity.mac = Client.mac
ORDER BY Identity.bssid;

CREATE VIEW IF NOT EXISTS SummaryAP AS
SELECT ssid, count(ssid) AS "Count", AP.encryption, AP.manuf, AP,cloaked
FROM AP group by ssid
ORDER BY count(ssid) DESC;
