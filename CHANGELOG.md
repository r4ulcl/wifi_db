# Changelog

## v1.6.1

### Changed
- The self-update check now works inside Docker: it detects the container (via `WIFI_DB_DOCKER`, set in the image, or the `/.dockerenv` marker), compares the running version to the latest GitHub release, and when out of date tells you to `docker pull r4ulcl/wifi_db:latest` instead of the generic "not in a Git folder" message.

### Fixed
- Self-update no longer gets stuck on the bundled OUI database. `utils/mac-vendors-export.csv` is refreshed at runtime, so it is almost always locally modified; the update now discards that throwaway copy and pulls with autostash, instead of aborting with "cannot pull with rebase: You have unstaged changes" (and, once upstream has also refreshed the CSV, the equivalent merge conflict) — the failure that showed up when updating months later.
- Version check no longer misreads the current build as a "future/dev version": `1.6.0` and the `v1.6` release tag now compare equal (trailing `.0` segments are padded) instead of `(1, 6) < (1, 6, 0)` making the code look newer than the release.
- `pip install -r requirements.txt` during self-update now runs from the repo root, so it works regardless of the directory `wifi_db.py` was launched from.

## v1.6.0

### Added
- Per-AP RSN/WPA security breakdown (WPA version, AKM suites, pairwise/group ciphers, enterprise flag, PMF) in a new `SecurityAP` view, with human-readable decodes of the `wps_config_methods` and `rsn_capabilities` bitmasks (e.g. `0x00c0` → `MFPR, MFPC`) stored beside the raw values; existing databases migrate automatically.
- X.509 certificate extraction from enterprise (802.1X) EAP into the new `Certificate` table and `CertificateAP` view (based on the @x4v1l0k idea in PR #57).
- EAP enrichment on identities: realm and method-type lookup, plus EAP-MD5 challenge/response capture for offline cracking (`EAPMD5` table, `hashcat -m 4800`).
- Probe-request fingerprinting (`fingerprint`, `ie_order`) with randomized-MAC detection, and hidden (cloaked) SSID recovery from probe responses and (re)association requests.
- AP management-capability detection from beacons/probe responses (802.11r/k/v fast roaming, Multiple BSSID, Channel Switch Announcement) in a new `CapabilitiesAP` view.

### Fixed
- Parsing/detection corrections: inflated WPS error count and SSID-dependent WPS 2.0 detection; MFP/PMF now read from RSN capability bits (capable vs required); `cloaked` and `firstTimeSeen` no longer clobbered when a later frame enriches an AP; EAP Success/Failure frames no longer counted as `Identity` errors.
- asyncio child-watcher crash on Python 3.14.
- Container fixes: in-container self-update (`git` now shipped) and non-root/podman writes to the bind-mounted `db.SQLITE`; plus Docker build, dependency CVEs and Codacy findings (including a SQL injection).

### Updated
- Merged the 1:1 Security, WPS and probe-fingerprint attributes onto the `AP`/`Probe` rows, and improved the `SummaryAP` view (grouped by SSID **and** encryption, showing WPA version, PMF, every manufacturer and client counts).
- Slimmed the Docker image ~360 MB → ~220 MB (Alpine base, ship only `hcxpcapngtool`, drop build caches); amd64/arm64 builds, the full test suite and the built image now verified in CI.
- Refactored internals with no behaviour change: split the oversized `utils/wifi_db_aircrack.py` into modules behind a re-export facade and cut parser/DB cyclomatic complexity below the Codacy limit (shared `safe_insert`/`cap_runner`, lookup tables); public `parse_*` API and callers unchanged.
- Refreshed the bundled IEEE OUI / mac-vendors database (~16k new vendor prefixes).
