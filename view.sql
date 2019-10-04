CREATE VIEW IF NOT EXISTS ProbeClients AS
SELECT Probe.mac, Client.manuf, Client.type, Client.packetsTotal, Probe.ssid
from Probe join Client on Probe.mac  = Client.mac
ORDER BY Probe.ssid;

CREATE VIEW IF NOT EXISTS ConnectedAP AS
SELECT Connected.bssid, AP.ssid, Connected.mac, Client.manuf
FROM Connected JOIN AP ON Connected.bssid = AP.bssid  JOIN Client ON Connected.mac = Client.mac
ORDER BY Connected.bssid;

