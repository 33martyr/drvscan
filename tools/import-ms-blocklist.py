#!/usr/bin/env python3
"""Import Microsoft RecommendedDriverBlockRules into data/blocklist.json.
Usage: python tools/import-ms-blocklist.py --xml path/to/RecommendedDriverBlockRules.xml --out data/blocklist.json
Requires the XML from https://aka.ms/drvblock (public). Preserves lolDrivers entries.
"""
import argparse, json, hashlib, re
from pathlib import Path
import xml.etree.ElementTree as ET

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xml", required=True)
    ap.add_argument("--out", default="data/blocklist.json")
    args = ap.parse_args()
    tree = ET.parse(args.xml)
    # Microsoft XML uses <FileRules><Allow|Deny><File ...> with hash — adapt to schema; we store SHA-256 if present
    hashes=[]
    for el in tree.iter():
        # look for SHA256 or Hash attribute
        for attr in ("Sha256Hash","Hash","SHa256","sha256"):
            v=el.attrib.get(attr)
            if v and re.match(r"^[0-9a-fA-F]{64}$", v):
                hashes.append({"sha256":v.lower(),"filename":el.attrib.get("FileName","unknown"),"category":"vulnerable","source":"microsoft:DriverSiPolicy"})
    print(f"Found {len(hashes)} hashes from XML")
    outp=Path(args.out)
    data=json.loads(outp.read_text(encoding="utf-8"))
    existing={e["sha256"] for e in data.get("drivers",[])}
    added=0
    for h in hashes:
        if h["sha256"] not in existing:
            data["drivers"].append(h); added+=1
    if "microsoft:DriverSiPolicy" not in data.get("sources",[]):
        data["sources"].append("microsoft:DriverSiPolicy")
    outp.write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")
    print(f"Added {added} new entries to {args.out}")

if __name__=="__main__": main()
