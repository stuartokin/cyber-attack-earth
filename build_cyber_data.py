#!/usr/bin/env python3
"""
build_cyber_data.py (v2) — data pack builder for Cyber Attack Earth.

v2: VCDB's CSV one-hot-encodes enumerations (victim.country.US=1 etc.), which made
v1's output 253 MB. This version consolidates one-hot groups back into compact
"US; GB" values, keeping outputs a few MB. Also adds hard size guards so an
oversized file can never reach the repo again.

Usage: python3 build_cyber_data.py [output_dir]   # default ./cyber_data
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
UA = {"User-Agent": "cyber-attack-earth-datapack/2.0 (personal research dashboard)"}
MAX_MB = 80  # refuse to write anything bigger

csv.field_size_limit(10_000_000)

EUREPOC_KEEP = [
    r"^start.*date", r"incident.*start", r"date.*start", r"^date$",
    r"receiver.*country", r"victim.*country",
    r"initiator.*country", r"initiator.*name", r"attributed.*actor",
    r"incident.*name", r"^name$", r"title",
    r"description", r"^summary",
    r"receiver.*category", r"incident.*type", r"cyber.*means",
    r"^incident.*id", r"^id$",
]
LONG_TEXT = re.compile(r"description|summary", re.I)

VCDB_PLAIN = ["timeline.incident.year", "timeline.incident.month", "summary",
              "reference", "victim.victim_id", "incident_id", "victim.industry"]
VCDB_ONEHOT = ["victim.country", "actor.external.country"] + [
    f"action.{a}.variety" for a in
    ("hacking", "malware", "social", "misuse", "physical", "error", "environmental")]
TRUTHY = {"1", "true", "TRUE", "True", "yes", "Y"}


def fetch_first(urls, desc):
    for url in urls:
        try:
            print(f"[fetch] {desc}: {url}")
            r = requests.get(url, headers=UA, timeout=300)
            r.raise_for_status()
            return r
        except Exception as exc:
            print(f"[warn] {desc} source failed ({exc}); trying next…")
    raise RuntimeError(f"All sources failed for {desc}")


def write_guarded(path: Path, obj) -> int:
    blob = json.dumps(obj, separators=(",", ":"))
    mb = len(blob.encode()) / 1e6
    if mb > MAX_MB:
        raise RuntimeError(f"{path.name} would be {mb:.0f} MB (> {MAX_MB} MB guard) — not written")
    path.write_text(blob, encoding="utf-8")
    print(f"[write] {path.name}: {mb:.1f} MB")
    return len(obj) if isinstance(obj, list) else len(blob)


def build_eurepoc():
    r = fetch_first(EUREPOC_URLS, "EuRepoC")
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8", "replace"))))
    if not rows:
        raise RuntimeError("EuRepoC CSV parsed to zero rows")
    pats = [re.compile(p, re.I) for p in EUREPOC_KEEP]
    keep = [c for c in rows[0] if c and any(p.search(c) for p in pats)]
    print(f"[eurepoc] {len(rows)} rows; keeping {len(keep)}/{len(rows[0])} columns: {keep}")
    slim = []
    for row in rows:
        s = {}
        for c in keep:
            v = (row.get(c) or "").strip()
            if v:
                s[c] = v[:600] if LONG_TEXT.search(c) else v[:200]
        if s:
            slim.append(s)
    return slim


def build_vcdb():
    r = fetch_first(VCDB_URLS, "VCDB zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = next(n for n in z.namelist() if n.lower().endswith(".csv"))
        text = z.read(name).decode("utf-8", "replace")
    reader = csv.DictReader(io.StringIO(text))
    header = reader.fieldnames or []
    # Map each one-hot group prefix -> its columns and value suffixes
    groups = {}
    for prefix in VCDB_ONEHOT:
        cols = [c for c in header if c.startswith(prefix + ".")]
        if cols:
            groups[prefix] = [(c, c[len(prefix) + 1:]) for c in cols]
    print(f"[vcdb] one-hot groups: " +
          ", ".join(f"{k}({len(v)})" for k, v in groups.items()))
    slim = []
    n = 0
    for row in reader:
        n += 1
        year = (row.get("timeline.incident.year") or "").strip()
        if not year.isdigit() or not (2000 <= int(year) <= 2026):
            continue
        s = {}
        for c in VCDB_PLAIN:
            v = (row.get(c) or "").strip()
            if v:
                s[c] = v[:600] if c in ("summary", "reference") else v[:120]
        for prefix, cols in groups.items():
            plain = (row.get(prefix) or "").strip()  # some exports carry both
            if plain:
                s[prefix] = plain[:120]
                continue
            vals = [suffix for col, suffix in cols
                    if (row.get(col) or "").strip() in TRUTHY
                    and suffix.lower() not in ("unknown", "other")]
            if vals:
                s[prefix] = "; ".join(vals[:6])
        if s.get("victim.country"):
            slim.append(s)
    print(f"[vcdb] {n} rows scanned; {len(slim)} usable incidents")
    if not slim:
        raise RuntimeError("VCDB consolidation produced zero usable rows")
    return slim


def build_rwlive():
    months, total = {}, 0
    y, m = date.today().year, date.today().month
    m -= 1
    if m == 0:
        y, m = y - 1, 12
    while (y, m) >= RWLIVE_START:
        key = f"{y}-{m:02d}"
        try:
            r = requests.get(f"{RWLIVE_API}/victims/{y}/{m:02d}", headers=UA, timeout=120)
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
            time.sleep(1.0)
        except Exception as exc:
            print(f"[warn] rwlive {key} failed ({exc}); continuing")
            time.sleep(3)
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    if not months:
        raise RuntimeError("No Ransomware.live months retrieved")
    return months, total


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "cyber_data")
    out.mkdir(parents=True, exist_ok=True)
    meta = {"generated": date.today().isoformat(), "builder": "v2", "counts": {}}

    for name, builder in (("eurepoc", build_eurepoc), ("vcdb", build_vcdb)):
        try:
            data = builder()
            meta["counts"][name] = write_guarded(out / f"{name}.min.json", data)
        except Exception as exc:
            print(f"[error] {name} build failed: {exc}")

    try:
        months, total = build_rwlive()
        write_guarded(out / "rwlive.min.json", months)
        meta["counts"]["rwlive_claims"] = total
        meta["rwlive_last"] = max(months)
    except Exception as exc:
        print(f"[error] rwlive build failed: {exc}")

    (out / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print("[done]")


if __name__ == "__main__":
    main()    "https://cdn.jsdelivr.net/gh/vz-risk/VCDB@master/data/csv/vcdb.csv.zip",
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
