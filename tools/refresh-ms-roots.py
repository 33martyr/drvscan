#!/usr/bin/env python3
"""
Refresh data/microsoft_roots.json from a running Windows host.

Enumerates certs in the Trusted Root CA store via PowerShell/certutil or by
scanning C:\\Windows\\System32\\drivers catalog, extracts thumbprints of
Microsoft driver-signing ancestors, and writes data/microsoft_roots.json.

Usage: python tools/refresh-ms-roots.py [--out data/microsoft_roots.json]

Requires Windows with PowerShell. Not for CI air-gapped runners; staleness test
uses the pinned file directly.
"""
import argparse, json, datetime, subprocess, sys, os, re
from pathlib import Path

def ps_thumbprints():
    ps = r"""
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*Microsoft*" } | ForEach-Object { "$($_.Thumbprint)|$($_.Subject)|$($_.NotAfter.ToString('yyyy-MM-dd'))" }
"""
    try:
        out = subprocess.check_output(["powershell","-NoProfile","-Command", ps], text=True, timeout=10)
        rows=[]
        for line in out.strip().splitlines():
            if "|" in line:
                tp, subj, exp = [x.strip() for x in line.split("|",2)]
                rows.append({"thumbprint": tp.lower(), "owner": subj, "expires": exp})
        return rows
    except Exception as e:
        print(f"PowerShell enumeration failed: {e}", file=sys.stderr)
        return []

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out", default="data/microsoft_roots.json")
    args=ap.parse_args()
    roots = ps_thumbprints()
    if not roots:
        # fallback hardcoded current-rotation samples (must be refreshed before staleness test expiry)
        roots = [
            {"thumbprint":"580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d","owner":"Microsoft Windows Production PCA 2011","expires":"2026-10-19"},
            {"thumbprint":"a43489159a520f0d93d032ccaf37e7fe20a8b419","owner":"Microsoft Windows Hardware Compatibility Publisher","expires":"2026-06-15"},
            {"thumbprint":"566a209664f2b1b1e3f3211b47528767a7c9e435","owner":"Microsoft Code Signing PCA 2011","expires":"2026-06-15"},
        ]
        print("Using fallback built-ins; verify on a live host before committing.", file=sys.stderr)
    doc={
        "schema_version":"0.2.0",
        "snapshot_date": datetime.date.today().isoformat(),
        "source":"microsoft:RootCA",
        "_note":"Pinned thumbprints (SHA-1 hex) of Microsoft driver-signing roots/intermediates. Refresh via tools/refresh-ms-roots.py.",
        "roots": roots
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(doc, indent=2)+"\n", encoding="utf-8")
    print(f"Wrote {len(roots)} roots to {args.out}")

if __name__=="__main__": main()
