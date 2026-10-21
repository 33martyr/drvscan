# Runbook — what to do when drvscan flags something

## One-driver Suspicious (e.g. Capcom.sys hash hit)

1. Verify `provenance` source + `blocklist_version`; run `drvscan --update-blocklist` if `is_sample`.
2. Re-run with `--json --redact-paths` and capture `fields` (`observed`/`expected`).
3. Check `authenticode` vs `cert_blocklist`: `Valid` + `hash_blocklist:Suspicious` is BYOVD — valid signature does not imply safe.
4. Action: unload/remove driver, update vendor, block hash via WDAC.

## Checksum mismatch

- `Suspicious/Medium` on signed driver → tamper indicator. Remove or reinstall from vendor; do not run.
- `Warn/Medium` on unsigned → less conclusive; verify file integrity.

## Timestamp high-bit

- Microsoft-signed + high-bit → reproducible-build hash (expected, informational).
- Third-party + high-bit future → may hide future date; verify with PE tool.

## Path

- `Program Files` + signed → Clean (vendor location) — no action.
- `Temp`/`AppData`/`Downloads`/UNC → investigate dropping process and creation time.

## Size mismatch

- Within `±0x1000` → page rounding, `Warn/Low`, no action.
- Truncation (`kernel < on-disk`) → `Suspicious/High`, check file replacement.

## Multiple Suspicious

Preserve JSON with `--redact-paths` if sharing, isolate host, collect `drvscan --json --verbose` + `Get-WindowsDriver` + event logs for IR.

## Updating

See `docs/UPDATE.md`. Until `data/blocklist.sha256` is real, do not run update on untrusted network.
