# LIMITATIONS — read before trusting the verdict

**Suspicious is not malicious.** Every flag is an evidence-backed signal with confidence and alternative explanations. Do not treat a single flag as proof of compromise.

1. **User-mode only.** `drvscan` enumerates via `EnumDeviceDrivers` (documented) + `NtQuerySystemInformation(SystemModuleInformation)` (supplement). Kernel tampering (DKOM, hooks) can hide or falsify these results. A rootkit that unlinks its `LDR_DATA_TABLE_ENTRY` or hooks the enumeration will be invisible. This is inherent to user-mode scanning without a driver — which is an intentional non-goal.

2. **Blocklist is a SAMPLE and a snapshot.** Bundled `data/blocklist.json` is `is_sample:true` (`schema_version:0.2.0`, snapshot `2026.10.20`). **Run `drvscan --update-blocklist` before relying on detection** — without it, `clean` may be a false negative. Until updated, the hash set is 12+ placeholder/dummy entries plus Microsoft sample imports. The blocklist carries `version`, `snapshot_date`, `schema_version`, `is_sample`, and `sources`; JSON output echoes `blocklist_is_sample`.

3. **Update is TLS-only until the pin is configured.** `data/blocklist.sha256` is placeholder until the first real snapshot ships. Until a 64-hex pin is committed alongside a real `blocklist.json`, `--update-blocklist` trusts the source over TLS. Do not run `--update-blocklist` on a network you do not trust. See `docs/UPDATE.md` for pin rotation.

4. **Valid signature does not imply safe.** BYOVD drivers are legitimately signed yet vulnerable and abused. The risk engine explicitly does not downgrade a hash blocklist hit because the signature is valid. Likewise, a cert thumbprint match is a **signal, not proof of compromise**.

5. **Signing-root classification may go stale.** `IsMicrosoftSigned()` checks the cert chain against `data/microsoft_roots.json` (pinned SHA-1s). If the list is stale (>6 months), a newly rotated Microsoft cert will be mis-classified as third-party. The staleness test in `test_verify.cpp` fails when the fixture cert no longer matches the pin. Refresh via `tools/refresh-ms-roots.py`.

6. **Path flag is contextual risk only.** `Program Files` signed drivers are `Clean` (vendor location) — unsigned `Program Files` is `Warn`. `Temp`/`AppData`/`Downloads`/UNC is flagged `suspicious` with **low confidence** precisely because it is contextual. `--verbose` hides `Clean` evidence by default to avoid flood.

7. **Image size tolerance.** `ImageSize` mismatch within `±0x1000` (one page) is `Warn/Low` (rounding); truncation (`kernel < on-disk`) is `Suspicious/High`; larger divergence is `Suspicious/Medium`.

8. **PE structural checks are on-disk only.** Section overlap/escape, entry point, alignment, checksum, timestamp, section names all run on the on-disk file — never on the in-memory image. Wording is *“consistent with” / “indicator of”*, never *“is”*. Many inbox drivers have hash-like timestamps (`0xB3E...`) from reproducible builds; the tool handles these via signer-aware C6.

9. **Returned path / on-disk file / loaded memory image are not interchangeable.** Enumeration gives image base + size; the reported path may not resolve; the on-disk file may differ from what is executing. Signature verification is over the on-disk file and does not prove the in-memory image is identical. C3 `has_driver_entry` uses import/export tables, not byte scan, but still heuristic.

10. **Provenance is PII-adjacent.** JSON emits `kernelPath`/`normalizedPath` verbatim. If a driver is in `C:\Users\<name>\AppData\...`, the username leaks. Use `--redact-paths` when sharing reports publicly.

11. **Table dedupes recommendations.** Per-evidence `recommendation` is in JSON (machine); the table shows one deduped `next_step` from the highest-severity evidence.

12. **Exit codes changed in 1.1.2.** Default `0` clean, `1` warn, `2` suspicious, `3` scan failed. `--strict` promotes `Warn→2`. `--legacy-exit-codes` restores v1.1.1 `Warn→1` for one release. See `CHANGELOG.md` Breaking:.

13. **Stock-box warn rate is low post-fix.** Post-#12, a clean Win10 shows mostly `clean` with only genuine anomalies as `warn` (previously 46% warn from over-tuned path/checksum/timestamp — fixed by signer-aware C5/C6 and signed Program Files). See `docs/EVALUATION.md` for current distribution.

14. **No cleaning, no monitoring.** One-shot scan, exit. Triage only — output is the starting point for IR, not a verdict of compromise.

15. **Triage, not detection guarantee.** Does not replace EDR, AV, or memory forensics. Use as the first 5-second question: "where do I look next?"

16. **Per-process device coverage is ~30 entries.** `data/device_map.json` v1.0 maps ~30 WinObj-confirmed `\Device\` names (60% of typical handle count). Unmapped devices report as `<unknown>` / `<unmapped>` (visible, not dropped). `handles ≠ intent` — opening `\Device\Capcom` proves handle, not malice. `NtQueryObject` can hang on named pipes with no reader; v0.3 skips `\Device\NamedPipe\*` and uses a 500ms thread timeout (detached thread leak documented in code; `SeDebugPrivilege` is best-effort).

17. **--pid full paths not supported; window-title not supported; --include-named-pipes is v0.4.** `--pid "C:\...\chrome.exe"` is rejected. No behavioral or timing analysis.

18. **\Driver\ enumeration requires Administrator.** `NtOpenDirectoryObject(\Driver\)` needs `DIRECTORY_QUERY`; without elevation, Section 3 shows `Driver dir: 0xC0000022 (run as Administrator)` and orphaned candidates are not computed. `\Device\` still enumerates; install via `cmake --install` and run elevated for full coverage.

19. **v0.4 surfaces S2–S9 are staged — pending surfaces report as `(pending)` in Section 3.** Global handles, Code Integrity, Amcache, prefetch, ETW, Sysmon, boot log, Defender are honest stubs until wired to `correlate` confidence.

20. **Section 4 (what wasn't covered) is required.** Every run prints Section 4 — pure-payload kernel patches without objects/Amcache/prefetch/CI are not detectable from user mode. HVCI:ON blocks unsigned code; HVCI:OFF the gap is real. `No candidates found = no visible candidates, not proof nothing happened.`
