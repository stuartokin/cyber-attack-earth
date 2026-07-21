#!/usr/bin/env python3
"""
build_cyber_data.py — data pack builder for Cyber Attack Earth.

Fetches the research datasets that browsers cannot fetch directly (Zenodo sends no
CORS headers; jsdelivr rejects oversized GitHub files; api.ransomware.live is not
reliably CORS-enabled) and writes slimmed, same-origin JSON files that the app
loads instantly with no cross-origin issues.

Usage:
    python3 build_cyber_data.py [output_dir]     # default: ./cyber_data

Outputs (place the cyber_data/ folder next to the HTML file):
    cyber_data/eurepoc.min.json   — slimmed EuRepoC Global Dataset rows
    cyber_data/vcdb.min.json      — slimmed VCDB rows
    cyber_data/rwlive.min.json    — {"YYYY-MM": [victim, ...]} leak-site claims, 2020→now
    cyber_data/meta.json          — generation timestamp and counts

Only the standard library + 'requests' are needed (pip install requests).
Re-run whenever you want fresh data, or use the provided GitHub Action to
refresh nightly. Respect each source's licence: EuRepoC (see Zenodo record),
VCDB (repository terms), Ransomware.live (free API — review T&C for
organisational use; keep the pacing delays below).
"""
import csv, io, json, re, sys, time, zipfile
from datetime import date
from pathlib import Path

import requests

EUREPOC_URLS = [
    "https://zenodo.org/records/14965395/files/eurepoc_dyadic_dataset_0_1.csv?download=1",
    "https://zenodo.org/records/14965395/files/eurepoc_global_dataset_1_3.csv?download=1",
]
VCDB_URLS = [
    "https://raw.githubusercontent.com/vz-risk/VCDB/master/data/csv/vcdb.csv.zip",
    "https://cdn.jsdelivr.net/gh/vz-risk/VCDB@master/data/csv/vcdb.csv.zip",
]
RWLIVE_API = "https://api.ransomware.live/v2"
RWLIVE_START = (2020, 1)
UA = {"User-Agent": "cyber-attack-earth-datapack/1.0 (personal research dashboard)"}

# Column families mirrored from the app's parsers — keep any column matching these.
EUREPOC_KEEP = [
    r"^start.*date", r"incident.*start", r"date.*start", r"^date$", r"year",
    r"receiver.*country", r"victim.*country", r"target.*country", r"destination.*country",
    r"initiator.*country", r"actor.*country", r"origin.*country", r"source.*country",
    r"initiator.*name", r"actor.*name", r"threat.*actor", r"attributed.*actor",
    r"incident.*name", r"operation.*name", r"event.*name", r"title",
    r"description", r"summary", r"comment", r"notes",
    r"receiver.*category", r"victim.*sector", r"sector", r"industry", r"target.*category",
    r"type.*incident", r"incident.*type", r"operation.*type", r"cyber.*means", r"technique",
    r"^incident.*id", r"^id$",
]
VCDB_KEEP_EXACT = [
    "timeline.incident.year", "timeline.incident.month",
    "victim.country", "actor.external.country",
    "summary", "reference", "victim.victim_id", "incident_id", "victim.industry",
] + [f"action.{a}.variety" for a in
     ("hacking", "malware", "social", "misuse", "physical", "error", "environmental")]

LONG_TEXT = re.compile(r"description|summary|comment|notes", re.I)


def fetch_first(urls, desc):
    for url in urls:
        try:
            print(f"[fetch] {desc}: {url}")
            r = requests.get(url, headers=UA, timeout=300)
            r.raise_for_status()
            return r
        except Exception as exc:  # noqa: BLE001 - report and try next mirror
            print(f"[warn] {desc} source failed ({exc}); trying next…")
    raise RuntimeError(f"All sources failed for {desc}")


def build_eurepoc():
    r = fetch_first(EUREPOC_URLS, "EuRepoC")
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8", "replace"))))
    if not rows:
        raise RuntimeError("EuRepoC CSV parsed to zero rows")
    pats = [re.compile(p, re.I) for p in EUREPOC_KEEP]
    keep_cols = [c for c in rows[0] if c and any(p.search(c) for p in pats)]
    print(f"[eurepoc] {len(rows)} rows; keeping {len(keep_cols)}/{len(rows[0])} columns")
    slim = []
    for row in rows:
        s = {}
        for c in keep_cols:
            v = (row.get(c) or "").strip()
            if not v:
                continue
            s[c] = v[:700] if LONG_TEXT.search(c) else v[:300]
        if s:
            slim.append(s)
    return slim


def build_vcdb():
    r = fetch_first(VCDB_URLS, "VCDB zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        csv_name = next(n for n in z.namelist() if n.lower().endswith(".csv"))
        text = z.read(csv_name).decode("utf-8", "replace")
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise RuntimeError("VCDB CSV parsed to zero rows")
    header = list(rows[0])
    # VCDB flattens multi-value fields into e.g. "victim.country.US" boolean columns in
    # some exports; keep exact names plus any column starting with a kept prefix.
    keep_cols = [c for c in header
                 if c in VCDB_KEEP_EXACT or any(c.startswith(k + ".") for k in VCDB_KEEP_EXACT)]
    print(f"[vcdb] {len(rows)} rows; keeping {len(keep_cols)}/{len(header)} columns")
    slim = []
    for row in rows:
        s = {}
        for c in keep_cols:
            v = (row.get(c) or "").strip()
            if not v or v == "0":
                continue
            s[c] = v[:700] if LONG_TEXT.search(c) else v[:300]
        if s.get("timeline.incident.year"):
            slim.append(s)
    return slim


def build_rwlive():
    months = {}
    y, m = date.today().year, date.today().month
    # last complete month backwards to RWLIVE_START
    m -= 1
    if m == 0:
        y, m = y - 1, 12
    total = 0
    while (y, m) >= RWLIVE_START:
        key = f"{y}-{m:02d}"
        url = f"{RWLIVE_API}/victims/{y}/{m:02d}"
        try:
            r = requests.get(url, headers=UA, timeout=120)
            if r.status_code == 429:
                print("[rwlive] rate limited; sleeping 30s")
                time.sleep(30)
                continue
            r.raise_for_status()
            slim = []
            for v in r.json() or []:
                cc = (v.get("country") or "").strip().upper()
                if not cc:
                    continue
                slim.append({
                    "victim": (v.get("victim") or v.get("post_title") or "")[:140],
                    "group": (v.get("group") or "")[:60],
                    "attackdate": (v.get("attackdate") or v.get("discovered") or "")[:10],
                    "country": cc,
                    "activity": (v.get("activity") or v.get("sector") or "")[:60],
                    "press": len(v.get("press") or []),
                })
            months[key] = slim
            total += len(slim)
            print(f"[rwlive] {key}: {len(slim)} claims (total {total})")
            time.sleep(1.0)  # polite pacing — keep this
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] rwlive {key} failed ({exc}); continuing")
            time.sleep(3)
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    if not months:
        raise RuntimeError("No Ransomware.live months retrieved")
    return months, total


def main():
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "cyber_data")
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"generated": date.today().isoformat(), "counts": {}}

    for name, builder in (("eurepoc", build_eurepoc), ("vcdb", build_vcdb)):
        try:
            data = builder()
            (out_dir / f"{name}.min.json").write_text(
                json.dumps(data, separators=(",", ":")), encoding="utf-8")
            meta["counts"][name] = len(data)
        except Exception as exc:  # noqa: BLE001
            print(f"[error] {name} build failed: {exc} — existing file (if any) left in place")

    try:
        months, total = build_rwlive()
        (out_dir / "rwlive.min.json").write_text(
            json.dumps(months, separators=(",", ":")), encoding="utf-8")
        meta["counts"]["rwlive_claims"] = total
        meta["rwlive_last"] = max(months)
    except Exception as exc:  # noqa: BLE001
        print(f"[error] rwlive build failed: {exc} — existing file (if any) left in place")

    (out_dir / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(f"[done] pack written to {out_dir}/ — sizes:")
    for f in sorted(out_dir.glob("*.json")):
        print(f"  {f.name}: {f.stat().st_size/1e6:.1f} MB")


if __name__ == "__main__":
    main()
