# Evaluation

## What was tested vs what wasn't

### Tested (51 cases, 130 assertions, /W4 /WX in Release)

- SHA-256 known vectors + file round-trip.
- PE `SizeOfImage` x86/x64 + malformed headers.
- C1 section overlap (virtual + raw), C2 escape, C3 entry point (import/export-aware `has_driver_entry`), C4 alignment, C5 checksum (signed vs unsigned mismatch), C6 timestamp (Microsoft high-bit vs third-party), C7 section names (GFIDS/.gfids allowlist, suffixes).
- `MapVerifyHr` taxonomy: `Valid/Unsigned/Modified/Revoked/Expired/UntrustedRoot/Unverifiable` table-driven.
- `IsMicrosoftSigned()` via thumbprint pin, not subject string; staleness fixture; revoked-thumbprint dual coverage (`WinVerifyTrust` Valid but blocklist Suspicious).
- Path policy matrix including `ProgramFilesSignedClean` (`CheckDriverPathWithSig`).
- Blocklist versioned load (`schema_version:0.2.0`, `is_sample:true`, snapshot `2026.10.20`), `sources`.
- JSON round-trip (structured `fields`, `tool_version`/`blocklist_schema_version`, redact).
- Risk engine: `Valid+hash→Suspicious`, `cert-only→Medium`, `path-only→Low`.
- `±0x1000` size tolerance + truncation (`Suspicious/High`).

### Not tested

- Real driver binaries (fixtures are byte arrays only).
- Network `--update-blocklist` live fetch (validated via `VerifyBlocklistPin` unit, not integration).
- `NtQuerySystemInformation` hiding / DKOM — requires kernel harness.
- Performance at 500+ drivers.

## Current live distribution (stock Win10 box, 153 drivers)

Post-fixes (#5/#12/C5/C6): clean≈82, warn≈71 with verbose off? Actually with `--verbose` off, Clean evidence hidden by default; Warn count is structural info. After #12, `Program Files` signed drivers are Clean, so warn pool shrinks vs 71→~40. Suspicious 0 on clean box is expected; `exit 0` (or `1` without `--strict` if warns remain). Use `--strict` for CI that wants `Warn→2`.

## Weighted structural scoring

Spec item #6 (weighted count: critical=3, suspicious=2, warn=1, threshold 5/3) is not shipped — risk engine remains `any Suspicious→Suspicious`. Documented here for future `extra A` (P1). Current structural checks each emit independent `Evidence`; the evaluator correlates them rather than counting.
