# Retrospective — what v1.1.1 got wrong, what 1.1.2 fixes

## The pattern: display fixes that weakened classification

v1.1.0 → v1.1.1 showed 71 warns on a clean Win10 box. The response was to downgrade severity — C5 `Suspicious/Medium` → `Warn/Low`, C6 future/pre-1990 → `Warn/Low` with high-bit suppression for all signers — so the summary line looked better. The underlying classifications became wrong: a checksum mismatch on a validated signed driver **is** a tamper indicator, and a high-bit future on an unsigned third-party driver **is** anomalous.

## What was actually noisy

Not C5/C6/C7 per se, but: (a) `Program Files` → `Warn` unconditionally (every gaming PC hit), (b) no `±0x1000` tolerance on `ImageSize`, (c) signer-blind timestamp, (d) table that showed every `Clean` evidence.

## What 1.1.2 restores and what it keeps

- **Reverted**: C5 signer-aware `Suspicious/Medium` (mismatch + `Valid`/`IsMicrosoftSigned`), C6 future `Suspicious/Medium` non-hash case, per-check downgrades removed. Tests assert the higher severity.
- **Kept**: `header_checksum==0` → `Clean` (many legit drivers omit checksum) and GFIDS allowlist are correct.
- **Fixed correctly**: `Program Files` + signed → `Clean`; `±0x1000` rounding vs truncation; signer-aware C6 high-bit; import/export `has_driver_entry`; thumbprint-pin `IsMicrosoftSigned`.
- **Flood fixed by display, not by weakening**: `--verbose` hides `Clean` evidence; table dedupes `next_step`; `--strict`/`--legacy-exit-codes` handle CI.

## Confidence now

Evidence-based, not marketing: each `Evidence` has `verdict` + `confidence` (High/Medium/Low) + `provenance` + structured `fields`. `Suspicious` requires corroboration per `risk::Assess`; `Warn` and `Info` tiers are separate. `blocklist_is_sample:true` means `clean` is not proven clean until `drvscan --update-blocklist`.
