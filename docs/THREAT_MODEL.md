# Threat model

## Assumed adversary

An attacker who has already loaded a kernel driver via BYOVD, vulnerable vendor driver, or stolen cert. The tool sees the driver **post-load**; it cannot prevent the load. The attacker may have modified the on-disk file after signing, manual-mapped a synthetic PE, or dropped a driver to `Temp`/`AppData` and loaded it.

## Attacker capabilities

- Modify on-disk PE (patch `SizeOfImage`, strip timestamp, corrupt checksum, add sections) — detected by C1–C7 on-disk analysis.
- Patch kernel-reported `ImageSize` to hide manual mapping — tolerated within ±0x1000 rounding; larger divergence or truncation still flagged.
- Hide from `EnumDeviceDrivers`/`NtQuerySystemInformation` via DKOM or hooks — invisible to user-mode scan (out of scope; documented).
- Serve poisoned blocklist via MITM on update — mitigated by release-coupled `data/blocklist.sha256` pin (see `docs/UPDATE.md`); until pin ships, TLS only.
- Override or replace `data/blocklist.json` on disk between install and scan — not prevented; sign/protect deployment artifact out-of-band.

## Out of scope

- Pre-load prevention (WDAC, HVCI) — complementary.
- Live kernel memory inspection (requires driver).
- Behavioral/EDR detection of driver-exploited payloads.
- Cleanup or remediation — triage only.

## Trust boundaries

- Enumeration path, on-disk file, and in-memory image are distinct; signature over on-disk file does not prove in-memory identity.
- `IsMicrosoftSigned()` validates chain thumbprint against pinned `data/microsoft_roots.json`, not subject substring; stale pin → mis-classification (staleness test guards rotation).
- `Provenance` cites `source` per-entry (`loldrivers.io`, `microsoft:DriverSiPolicy`); `is_sample` indicates sample coverage.
