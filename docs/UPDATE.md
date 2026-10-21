# Update pin — release-coupled hash pin

`drvscan --update-blocklist` fetches `https://www.loldrivers.io/api/drivers.json` (fallback: GitHub raw), validates that the body contains `sha256`, then verifies the body against the pinned hash in `data/blocklist.sha256` before atomically installing it.

## Mechanism: release-coupled hash pin

- `data/blocklist.sha256` contains a single 64-hex SHA-256 (lowercase) of the **full** `data/blocklist.json` that shipped with **this binary's release**. It is updated in the same commit as `data/blocklist.json`.
- On update, the tool computes `SHA-256(downloaded_body)` and compares to the pin that shipped **with this binary** (exe-relative `data/blocklist.sha256`). If mismatch → refuse to install, keep old blocklist, exit 1, explain to re-pin.
- If the pin file is missing or contains placeholder/empty, the tool warns and proceeds without verification (sample/dev mode) — TLS still validates the source, but no downgrade attack is prevented.

## Rotation (also fixes the chicken-and-egg)

Chicken-and-egg: the download is verified against a pin committed **before** the next snapshot exists. Rotation is therefore commit-coupled:

1. Obtain new snapshot (manual or via `tools/import-ms-blocklist.py`).
2. Compute its SHA-256: `python -c "import hashlib; print(hashlib.sha256(open('data/blocklist.json','rb').read()).hexdigest())"`.
3. Write that hex to `data/blocklist.sha256` (same commit).
4. Bump `version`/`snapshot_date` in `data/blocklist.json` and commit.
5. CI's `test_update_pin` verifies pin == hash-of-file; if you forget rotation, CI fails.

Day-2 hit: if you run `--update-blocklist` on a stale binary whose pin is older than the live snapshot, verification will fail until you update the binary — this is intentional (prevents rollback/downgrade).

## Failure modes

- Network down → exit 1, old kept, message `No network — existing blocklist not modified`.
- Shape check fail (no `sha256`) → exit 1, old kept.
- Pin mismatch → exit 1, old kept, message points here.
- File I/O fail → exit 1, old kept.
- Success → exit 0, atomic `MoveFileExW`.

## Until the first real snapshot ships

`data/blocklist.sha256` is placeholder and `data/blocklist.json` is `is_sample:true`. Update proceeds without pin verification (with warning) and README says so.
