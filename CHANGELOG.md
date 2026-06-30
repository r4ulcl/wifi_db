# Changelog

## v1.6.0

### Added
- X.509 certificate extraction from enterprise (802.1X) EAP into the new `Certificate` table and `CertificateAP` view.
- RSN/WPA security breakdown per AP (WPA version, AKM suites, pairwise/group ciphers, enterprise flag, PMF) and `SecurityAP` view.
- EAP-MD5 challenge/response capture for offline cracking (`EAPMD5` table, `hashcat -m 4800`).
- Probe-request fingerprinting (`fingerprint`, `ie_order`) and randomized-MAC detection for clients.
- EAP realm extraction and EAP method-type lookup on identities.
- AP management-capability detection from beacons/probe responses: 802.11r/k/v fast roaming, Multiple BSSID and Channel Switch Announcement, plus a `CapabilitiesAP` view.
- Hidden (cloaked) SSID recovery from probe responses and (re)association requests.

### Fixed
- Inflated WPS error count and SSID-dependent WPS 2.0 detection.
- `Identity` parser no longer counts EAP Success/Failure frames as errors.
- MFP/PMF detection now reads the RSN capability bits (capable vs required) instead of matching exact values.
- `cloaked` flag no longer reset to `False` when a later frame enriches an existing AP row.
- asyncio child-watcher crash on Python 3.14 and `firstTimeSeen` merge overwriting `0` placeholders.
- Self-update inside the container (`git` now shipped in the image); bind-mounted `db.SQLITE` writable for non-root/podman.
- Docker build, dependency CVEs, and assorted Codacy/security findings (including a SQL injection).

### Updated
- Merged the 1:1 Security, WPS and probe-fingerprint attributes onto the `AP`/`Probe` rows to simplify the schema.
- Improved the `SummaryAP` view: grouped by SSID **and** encryption, now showing WPA version, PMF state, every manufacturer per group, and client counts.
- Slimmed the Docker image from ~360 MB to ~220 MB (Alpine base, ship only the `hcxpcapngtool` binary, drop bytecode/build caches); amd64 and arm64 builds and the full test suite all verified.
- `Files.time` stored as a formatted string to avoid the Python 3.12 sqlite3 adapter deprecation; pyshark asyncio child-watcher warnings silenced in the test suite (`pytest.ini`).
