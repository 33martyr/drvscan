# drvscan — kernel driver triage in 5 seconds

One executable. One objective: **tell me whether any loaded kernel driver on this Windows machine is suspicious, and why.**

## Quick start

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
.\build\Release\drvscan.exe          # table (hides Clean evidence by default; use --verbose)
.\build\Release\drvscan.exe --json   # JSON to stdout
echo $LASTEXITCODE  # 0 clean, 1 warn, 2 suspicious, 3 scan failed
```

> **Bundled blocklist is a SAMPLE — run `drvscan --update-blocklist` before relying on detection. Without it, `clean` may be a false negative (see `is_sample` in JSON).**

Copy `data/blocklist.json` + `data/microsoft_roots.json` next to the exe (post-build step does this).

## What it does

Enumerates loaded drivers via **documented `EnumDeviceDrivers` (primary) + `NtQuerySystemInformation(SystemModuleInformation)` supplement** for `ImageSize` and full NT path. For each driver it runs evidence-backed checks:

1. **Authenticode** (`WinVerifyTrust`) — taxonomy `Valid/Unsigned/Modified/Revoked/Expired/UntrustedRoot/Unverifiable` via pure `MapVerifyHr()` (tested, see `test_verify.cpp`).
2. **SHA-256 vs bundled blocklist** — `bcrypt` hash vs `data/blocklist.json` (versioned `schema_version:0.2.0`, snapshot `2026.10.20`, sources `loldrivers.io` + `microsoft:DriverSiPolicy`). Detects BYOVD. Every hit cites `source` in `provenance`.
3. **Cert thumbprint reputation** — SHA-1 thumbprints vs known-bad list (CrossCert 2021 etc.) — **signal, not proof**. Pinned Microsoft roots in `data/microsoft_roots.json` classify `IsMicrosoftSigned()` via thumbprint chain, not subject string.
4. **Path regularity** — System32/drivers = regular; signed Program Files = regular (not Warn — see Runbook); AppData/Temp/Downloads/UNC/Device = suspicious (contextual).
5. **Image size** — on-disk `SizeOfImage` vs kernel `ImageSize` with `±0x1000` page tolerance; truncation (`kernel < on-disk`) is `Suspicious/High`, rounding is `Warn/Low`.
6. **PE structural (C1–C7)** — section overlap, escape, entry point (import/export-aware `has_driver_entry`), alignment, checksum (signer-aware), timestamp (signer-aware high-bit), section names. Pure functions on on-disk PE; every finding says *“consistent with”*, never *“is”*.

Each `Evidence` carries `check` (stable ID), `verdict`, `confidence`, `detail` (prose), `provenance`, `recommendation`, and structured `fields` (`observed/expected/kernel/on_disk`). Risk engine is weighted-free for now (any `Suspicious → Suspicious`); see `docs/EVALUATION.md`.

## Output

- **Table (default):** hides `Clean` evidence; `--verbose` shows all. One `next_step` per driver (deduped, highest-severity).
- **JSON (`--json`):** `tool_version`, `blocklist_schema_version`, `blocklist_is_sample`, per-driver `checks[]` with `fields`. `--redact-paths` replaces `C:\Users\<name>\` → `C:\Users\<user>\`.
- **Exit codes:** `0` clean, `1` warn, `2` suspicious, `3` scan failed. `--strict` promotes `Warn→2`; `--legacy-exit-codes` restores v1.1.1 mapping for one release (see `CHANGELOG.md` Breaking:). CI: `drvscan || [[ $? -eq 1 ]]` if you intentionally allow warns.

## CLI

```
drvscan [--json] [--verbose] [--redact-paths] [--blocklist <path>] [--update-blocklist] [--strict] [--legacy-exit-codes] [--help] [--version]
drvscan --pid <name-or-pid> [--pid-exact] [--json] [--verbose] [--redact-paths] [--strict]
```

Per-process mode: `--pid 1234` or `--pid chrome.exe` / `--pid chrome` (extension optional; no full paths — use name from Task Manager, not `C:\...`). Multiple matches aggregate (`chrome.exe × 15`); `--pid-exact` errors if >1. Exit 3 for no match (with Levenshtein suggestion) or inaccessible process (hint: run as Administrator for anti-cheat/system processes); exit 4 for no device handles. `handles do not prove intent — a handle proves open device, not malice.` Table adds Device column per-PID; JSON adds `devices[]` per driver + `processes[]` wrapper. Default mode unchanged (151 clean / 0 warn / 0 suspicious on stock Win10).

`--update-blocklist` fetches via WinHTTP, validates shape, verifies against pinned `data/blocklist.sha256` (release-coupled; rotate by committing new hash with new blocklist — see `docs/UPDATE.md` and chicken-and-egg note), then atomic `MoveFileExW`. TLS only until pin is configured; doc warns accordingly. Failure modes: exit 0 updated, exit 1 network/shape/pin mismatch (old kept).

## Sample JSON

<!-- sample JSON produced after #14 lands -->
<!-- TODO: replace with real `drvscan --json` snippet from a Capcom.sys scan (3 evidence entries) after blocklist refresh. Owner will fill in. -->

## Limitations & docs

See `LIMITATIONS.md`, `docs/THREAT_MODEL.md`, `docs/EVALUATION.md`, `docs/RUNBOOK.md`, `docs/UPDATE.md`.

## Tests & CI

```powershell
cmake --build build --config Release  # /W4 /WX enforced in Release
.\build\Release\drvscan_tests.exe     # 51 cases, 130 assertions
ctest --test-dir build -C Release --output-on-failure
cmake --install build --prefix dist   # install()
```

Coverage: SHA-256 vectors, PE C1–C7 synthetic PEs, `/W4 /WX` clean, `MapVerifyHr` taxonomy, `IsMicrosoftSigned` thumbprint (not subject), revoked-thumbprint dual coverage, staleness fixture, `±0x1000` tolerance.
