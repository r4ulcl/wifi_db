# Changelog

## Unreleased

### Fixed
- Handshake `hashcat` hash is no longer stored empty: `setHashcat` now creates the AP/Client/File rows it references before inserting, so hashes that `hcxpcapngtool --all` extracts for handshakes/PMKIDs the tshark parser skipped no longer fail with a `FOREIGN KEY constraint failed` and get dropped.
- `exec_hcxpcapngtool` now commits its writes, matching every other parser.

## v1.6.0 (2026-06-29)

### Added
- X.509 certificate extraction from enterprise (802.1X) EAP into the new `Certificate` table and `CertificateAP` view.
- RSN/WPA security breakdown per AP (WPA version, AKM suites, pairwise/group ciphers, enterprise flag, PMF) and `SecurityAP` view.
- EAP-MD5 challenge/response capture for offline cracking (`EAPMD5` table, `hashcat -m 4800`).
- Probe-request fingerprinting (`fingerprint`, `ie_order`) and randomized-MAC detection for clients.
- EAP realm extraction and EAP method-type lookup on identities.
- AP management-capability detection from beacons/probe responses: 802.11r/k/v fast roaming, Multiple BSSID and Channel Switch Announcement, plus a `CapabilitiesAP` view.
- Hidden (cloaked) SSID recovery from probe responses and (re)association requests.

### Fixed
- MFP/PMF detection now reads the RSN capability bits (capable vs required) instead of matching exact values.
- asyncio child-watcher crash on Python 3.14 and `firstTimeSeen` merge overwriting `0` placeholders.
- `cloaked` flag no longer reset to `False` when a later frame enriches an existing AP row (it is now sticky once detected).
- Docker build, dependency CVEs, and assorted Codacy/security findings (including a SQL injection).

### Updated
- Merged the 1:1 Security, WPS and probe-fingerprint attributes onto the `AP`/`Probe` rows to simplify the schema.
- Improved the `SummaryAP` view: grouped by SSID **and** encryption, now showing WPA version, PMF state, every manufacturer per group, and client counts.
- Slimmed the Docker image from ~360 MB to ~220 MB (Alpine base, ship only the `hcxpcapngtool` binary, drop bytecode/build caches); amd64 and arm64 builds and the full test suite all verified.
