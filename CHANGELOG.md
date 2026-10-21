# Changelog

## 1.1.2 — 2026-10-20

**Breaking:** Exit codes now `0` clean, `1` warn, `2` suspicious, `3` scan failed. `--strict` promotes `Warn→2`. `--legacy-exit-codes` restores `1` warn / `2` suspicious for one release (v1.1.1 CI compat). Previously every code path with Warn returned `1`; now scan-failed is `3` and `--strict` changes Warn mapping.

- Blocklist bumped to `2026.10.20`, `schema_version:0.2.0`, `is_sample:true`; README warns to run `--update-blocklist`.
- Microsoft `RecommendedDriverBlockRules` imported as `microsoft:DriverSiPolicy` source; provenance cites source per-entry.
- `ImageSize` tolerance `±0x1000` rounding vs truncation; C5 restored to `Suspicious/Medium` on signed mismatch; C6 signer-aware high-bit; `has_driver_entry` via import/export tables; Program Files signed → Clean.
- `IsMicrosoftSigned()` via `data/microsoft_roots.json` thumbprint pin (not subject string); refresh tool + staleness test.
- `/W4 /WX` in Release, `install()` targets, `DRVSCAN_VERSION 0.2.0`.
- Table hides `Clean` by default (`--verbose`), dedupes `next_step`; `--redact-paths`; JSON `fields` + `tool_version`/`blocklist_schema_version` + `is_sample`.
- Update verified against `data/blocklist.sha256` pin (release-coupled); docs for rotation.

## 0.3.0 — 2026-10-21

- Four verified FIXes (v0.2.0): timestamp plausible-window `[2000-01-01, now+30d]` (no high-bit), section characteristics `RWX`/`.text`/`RWX`/`empty`/`non-printable` (not name allowlist), PE parse cap 4 GB (fixes nvlddmkm.sys 114 MB), EP=0 skip on DLL `IMAGE_FILE_DLL`.
- `--pid <name|pid>` per-process device-handle audit: `handles.h/.cpp` `NtQuerySystemInformation(64)` + `NtQueryObject` 500ms thread timeout + `HarddiskVolume*` collapse + `NamedPipe` skip + `SeDebugPrivilege` best-effort; `devmap.h/.cpp` resolves `\Device\`→driver via `data/device_map.json` (26 exact + 4 wildcards, WinObj sources). Table Device column + multi-PID aggregate + JSON `devices[]`/`processes[]` + `--pid-exact` + Levenshtein suggestion + path-not-supported + `handles ≠ intent` disclaimer. Default mode unchanged (81 cases / 177 pass, clean build, 151 clean exit 0).
- `data/device_map.json` v1.0, docs `--pid` (README, LIMITATIONS v0.4).
