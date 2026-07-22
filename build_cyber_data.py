#!/usr/bin/env python3
"""
build_cyber_data.py (v3) — data-lake builder for Cyber Attack Earth.

WHAT THIS IS
------------
Browsers cannot fetch most of these sources directly (Zenodo sends no CORS
headers; jsdelivr rejects oversized GitHub files; several APIs need keys that
must never appear in client-side code). So this script runs OUTSIDE the browser
— locally or in GitHub Actions — and writes a small, typed, same-origin data
lake that the app loads instantly.

TABLES (different grain — deliberately NOT merged into one)
-----------------------------------------------------------
  incidents/*.json      one victim-event per row      -> plotted as missiles
  vulns/kev.json        one KEV catalogue entry       -> charts + enrichment
  vulns/epss.json       CVE -> exploit probability    -> enrichment only
  advisories/ics.json   one CISA ICS advisory         -> charts
  techniques/attack.json ATT&CK techniques + groups   -> reference
  reports/vendor.json   curated citations (manual)    -> provenance
  manifest.json         catalogue of all of the above

ADDING A SOURCE
---------------
Write a function, decorate it, done:

    @source(id="mysrc", table="advisories", title="My Source",
            licence="CC-BY 4.0", homepage="https://example.org")
    def build_mysrc():
        rows = get_json("https://example.org/data.json")
        return [{"id": r["id"], "date": r["date"]} for r in rows]

The runner handles fetch errors, size guards, the manifest entry, and leaves
previous output in place if a source fails.

USAGE
-----
    pip install requests
    python3 build_cyber_data.py [output_dir]      # default ./cyber_data
    ONLY_SOURCES=kev,epss python3 build_cyber_data.py   # build a subset

Keyed sources are OFF by default in this phase. Never put keys in the HTML —
they would be public. Use GitHub Actions secrets and this script only.

LICENCES - read before redistributing (you are republishing derived data):
    EuRepoC ............ see Zenodo record terms
    VCDB ............... repository terms
    Ransomware.live .... free community API, fair use; commercial may need paid
    CISA KEV ........... US Government work, public domain
    EPSS (FIRST) ....... free, attribution expected
    MITRE ATT&CK ....... MITRE terms of use, attribution required
    ICS Advisory Proj .. Open Database Licence (ODbL) v1.0 - ATTRIBUTION AND
                         SHARE-ALIKE REQUIRED for derived databases
"""

import csv
import gzip
import io
import json
import os
import re
import sys
import time
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import requests

SCHEMA_VERSION = 3
UA = {"User-Agent": "cyber-attack-earth-datalake/3.0 (personal research dashboard)"}
MAX_MB = 80                      # per-file guard; GitHub hard-fails at 100 MB
START_YEAR = 2000
csv.field_size_limit(10_000_000)


# ---------------------------------------------------------------------------
# Connector registry
# ---------------------------------------------------------------------------
@dataclass
class Source:
    id: str
    table: str
    title: str
    licence: str
    homepage: str
    cadence: str = "daily"
    needs_key: Optional[str] = None
    fn: Callable = None


REGISTRY = []


def source(**kw):
    def deco(fn):
        REGISTRY.append(Source(fn=fn, **kw))
        return fn
    return deco


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------
def get(url, timeout=300, **kw):
    r = requests.get(url, headers=UA, timeout=timeout, **kw)
    r.raise_for_status()
    return r


def get_json(url, **kw):
    return get(url, **kw).json()


def get_first(urls, desc):
    last = None
    for u in urls:
        try:
            print("  [fetch] %s: %s" % (desc, u))
            return get(u)
        except Exception as exc:                      # noqa: BLE001
            print("  [warn]  failed (%s); trying next mirror..." % exc)
            last = exc
    raise RuntimeError("all mirrors failed for %s: %s" % (desc, last))


def write_json(path, obj):
    blob = json.dumps(obj, separators=(",", ":"))
    mb = len(blob.encode()) / 1e6
    if mb > MAX_MB:
        raise RuntimeError("%s would be %.0f MB (>%d MB guard)" % (path.name, mb, MAX_MB))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(blob, encoding="utf-8")
    print("  [write] %s  %.2f MB" % (path.name, mb))


# ===========================================================================
# LAYER 1 - verified incidents
# ===========================================================================
EUREPOC_URLS = [
    "https://zenodo.org/records/14965395/files/eurepoc_dyadic_dataset_0_1.csv?download=1",
    "https://zenodo.org/records/14965395/files/eurepoc_global_dataset_1_3.csv?download=1",
]
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


@source(id="eurepoc", table="incidents", title="EuRepoC Global Dataset",
        licence="See Zenodo record terms", cadence="on release",
        homepage="https://eurepoc.eu/")
def build_eurepoc():
    r = get_first(EUREPOC_URLS, "EuRepoC")
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8", "replace"))))
    if not rows:
        raise RuntimeError("parsed zero rows")
    pats = [re.compile(p, re.I) for p in EUREPOC_KEEP]
    keep = [c for c in rows[0] if c and any(p.search(c) for p in pats)]
    print("  [eurepoc] %d rows; keeping %d columns" % (len(rows), len(keep)))
    out = []
    for row in rows:
        s = {}
        for c in keep:
            v = (row.get(c) or "").strip()
            if v:
                s[c] = v[:600] if LONG_TEXT.search(c) else v[:200]
        if s:
            out.append(s)
    return out


VCDB_URLS = [
    "https://raw.githubusercontent.com/vz-risk/VCDB/master/data/csv/vcdb.csv.zip",
    "https://cdn.jsdelivr.net/gh/vz-risk/VCDB@master/data/csv/vcdb.csv.zip",
]
VCDB_PLAIN = ["timeline.incident.year", "timeline.incident.month", "summary",
              "reference", "victim.victim_id", "incident_id", "victim.industry"]
VCDB_ONEHOT = ["victim.country", "actor.external.country"] + [
    "action.%s.variety" % a for a in
    ("hacking", "malware", "social", "misuse", "physical", "error", "environmental")]
TRUTHY = set(["1", "true", "TRUE", "True", "yes", "Y"])


@source(id="vcdb", table="incidents", title="VERIS Community Database",
        licence="Repository terms", cadence="weekly",
        homepage="https://verisframework.org/vcdb.html")
def build_vcdb():
    r = get_first(VCDB_URLS, "VCDB zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = next(n for n in z.namelist() if n.lower().endswith(".csv"))
        text = z.read(name).decode("utf-8", "replace")
    reader = csv.DictReader(io.StringIO(text))
    header = reader.fieldnames or []
    # VCDB one-hot-encodes enumerations (victim.country.US=1). Consolidate back
    # to "US; GB" so output is a few MB rather than a few hundred.
    groups = {}
    for prefix in VCDB_ONEHOT:
        cols = [(c, c[len(prefix) + 1:]) for c in header if c.startswith(prefix + ".")]
        if cols:
            groups[prefix] = cols
    out, scanned = [], 0
    this_year = date.today().year
    for row in reader:
        scanned += 1
        year = (row.get("timeline.incident.year") or "").strip()
        if not year.isdigit() or not (START_YEAR <= int(year) <= this_year):
            continue
        s = {}
        for c in VCDB_PLAIN:
            v = (row.get(c) or "").strip()
            if v:
                s[c] = v[:600] if c in ("summary", "reference") else v[:120]
        for prefix, cols in groups.items():
            plain = (row.get(prefix) or "").strip()
            if plain:
                s[prefix] = plain[:120]
                continue
            vals = [suf for col, suf in cols
                    if (row.get(col) or "").strip() in TRUTHY
                    and suf.lower() not in ("unknown", "other")]
            if vals:
                s[prefix] = "; ".join(vals[:6])
        if s.get("victim.country"):
            out.append(s)
    print("  [vcdb] %d scanned -> %d usable" % (scanned, len(out)))
    if not out:
        raise RuntimeError("consolidation produced zero rows")
    return out


RWLIVE_API = "https://api.ransomware.live/v2"
RWLIVE_START = (2020, 1)


@source(id="rwlive", table="incidents", title="Ransomware.live leak-site claims",
        licence="Free community API - fair use; review T&C for organisational use",
        cadence="daily", homepage="https://www.ransomware.live/about")
def build_rwlive():
    months, total = {}, 0
    y, m = date.today().year, date.today().month
    m -= 1
    if m == 0:
        y, m = y - 1, 12
    while (y, m) >= RWLIVE_START:
        key = "%d-%02d" % (y, m)
        try:
            r = requests.get("%s/victims/%d/%02d" % (RWLIVE_API, y, m),
                             headers=UA, timeout=120)
            if r.status_code == 429:
                print("  [rwlive] rate limited; sleeping 30s")
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
            print("  [rwlive] %s: %d claims (total %d)" % (key, len(slim), total))
            time.sleep(1.0)                       # polite pacing - keep this
        except Exception as exc:                  # noqa: BLE001
            print("  [warn] rwlive %s failed (%s); continuing" % (key, exc))
            time.sleep(3)
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    if not months:
        raise RuntimeError("no months retrieved")
    return months


# ===========================================================================
# LAYER 2 - enrichment (vulnerabilities and techniques). NOT incidents.
# ===========================================================================
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]


@source(id="kev", table="vulns", title="CISA Known Exploited Vulnerabilities",
        licence="US Government work - public domain", cadence="daily",
        homepage="https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
def build_kev():
    data = get_first(KEV_URLS, "CISA KEV").json()
    out = []
    for v in data.get("vulnerabilities", []):
        out.append({
            "cve": v.get("cveID", ""),
            "vendor": (v.get("vendorProject") or "")[:60],
            "product": (v.get("product") or "")[:80],
            "name": (v.get("vulnerabilityName") or "")[:160],
            "added": (v.get("dateAdded") or "")[:10],
            "ransomware": (v.get("knownRansomwareCampaignUse") or "Unknown")[:10],
        })
    print("  [kev] %d catalogue entries" % len(out))
    if not out:
        raise RuntimeError("zero KEV entries")
    return out


EPSS_URLS = [
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",     # legacy, redirects
]
EPSS_MIN = 0.10        # keep the file small: everything at/above 10% probability


@source(id="epss", table="vulns", title="EPSS exploit-prediction scores (FIRST)",
        licence="Free to use; attribution to FIRST expected", cadence="daily",
        homepage="https://www.first.org/epss/")
def build_epss():
    r = get_first(EPSS_URLS, "EPSS")
    text = gzip.decompress(r.content).decode("utf-8", "replace")
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    rdr = csv.DictReader(io.StringIO("\n".join(lines)))
    rows, kept = 0, []
    for row in rdr:
        rows += 1
        try:
            sc = float(row.get("epss") or 0)
        except ValueError:
            continue
        if sc >= EPSS_MIN:
            try:
                pct = float(row.get("percentile") or 0)
            except ValueError:
                pct = 0.0
            kept.append([row.get("cve", ""), round(sc, 4), round(pct, 4)])
    print("  [epss] %d scored CVEs -> %d at/above %.2f" % (rows, len(kept), EPSS_MIN))
    if not kept:
        raise RuntimeError("zero EPSS rows kept")
    return {"cols": ["cve", "epss", "percentile"], "rows": kept, "min_score": EPSS_MIN}


ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")


@source(id="attack", table="techniques", title="MITRE ATT&CK Enterprise",
        licence="MITRE terms of use - attribution required", cadence="on release",
        homepage="https://attack.mitre.org/")
def build_attack():
    bundle = get_json(ATTACK_URL, timeout=300)
    techniques, groups = [], []
    for o in bundle.get("objects", []):
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = None
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                ref = r
                break
        if not ref:
            continue
        if o.get("type") == "attack-pattern":
            techniques.append({
                "id": ref.get("external_id", ""),
                "name": (o.get("name") or "")[:120],
                "tactics": [p.get("phase_name") for p in o.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"],
                "url": ref.get("url", ""),
            })
        elif o.get("type") == "intrusion-set":
            desc = re.sub(r"\[|\]|\(https?:[^)]*\)", "",
                          str(o.get("description") or "").split(". ")[0])
            groups.append({
                "id": ref.get("external_id", ""),
                "name": (o.get("name") or "")[:80],
                "aliases": (o.get("aliases") or [])[:8],
                "desc": desc[:220],
                "url": ref.get("url", ""),
            })
    print("  [attack] %d techniques, %d groups" % (len(techniques), len(groups)))
    if not techniques:
        raise RuntimeError("zero techniques parsed")
    return {"techniques": techniques, "groups": groups}


# ===========================================================================
# LAYER 3 - operational technology advisories
# ===========================================================================
ICSAP_REPO = "icsadvprj/ICS-Advisory-Project"
ICSAP_DIR = "ICS-CERT_ADV"


@source(id="icsadv", table="advisories",
        title="CISA ICS advisories (via ICS Advisory Project)",
        licence="Open Database Licence (ODbL) v1.0 - attribution + share-alike",
        cadence="weekly", homepage="https://www.icsadvisoryproject.com/")
def build_icsadv():
    # The consolidated CSV filename is versioned, so enumerate and take the newest.
    listing = get_json("https://api.github.com/repos/%s/contents/%s"
                       % (ICSAP_REPO, ICSAP_DIR), timeout=60)
    csvs = sorted([f for f in listing if f["name"].lower().endswith(".csv")],
                  key=lambda f: f["name"])
    if not csvs:
        raise RuntimeError("no CSV found in ICS Advisory Project repo")
    newest = csvs[-1]
    print("  [icsadv] using %s" % newest["name"])
    text = get(newest["download_url"], timeout=180).content.decode("utf-8", "replace")
    rdr = csv.DictReader(io.StringIO(text))

    def pick(row, *names):
        for n in names:
            for k in row:
                if k and k.strip().lower() == n:
                    v = (row.get(k) or "").strip()
                    if v:
                        return v
        return ""

    out = []
    for row in rdr:
        adv = pick(row, "ics-cert number", "ics_cert_number", "advisory id", "id")
        rel = pick(row, "original release date", "release date", "date")
        if not adv:
            continue
        ym = re.search(r"(20\d{2})", rel or adv)
        out.append({
            "id": adv[:24],
            "title": pick(row, "product", "title", "advisory title")[:120],
            "vendor": pick(row, "vendor")[:60],
            "date": rel[:10],
            "year": int(ym.group(1)) if ym else None,
            "sectors": pick(row, "critical infrastructure sectors",
                            "critical infrastructure sector", "sector")[:160],
            "cves": pick(row, "cve", "cves")[:120],
            "cvss": pick(row, "cvss v3", "cvss", "cvss v4")[:8],
        })
    seen, dedup = set(), []
    for a in out:
        if a["id"] in seen:
            continue
        seen.add(a["id"])
        dedup.append(a)
    print("  [icsadv] %d product rows -> %d distinct advisories" % (len(out), len(dedup)))
    if not dedup:
        raise RuntimeError("zero advisories parsed")
    return dedup


# ===========================================================================
# LAYER 5 - vendor threat reports: CURATED CITATIONS ONLY.
# These are copyrighted PDFs with no APIs. We record where to read them and what
# they are - we do not scrape or reproduce their content. Edit this list by hand.
# ===========================================================================
VENDOR_REPORTS = [
    {"org": "Microsoft", "title": "Microsoft Digital Defense Report", "cadence": "annual",
     "url": "https://www.microsoft.com/en-us/security/security-insider/microsoft-digital-defense-report"},
    {"org": "Google / Mandiant", "title": "M-Trends", "cadence": "annual",
     "url": "https://www.mandiant.com/m-trends"},
    {"org": "CrowdStrike", "title": "Global Threat Report", "cadence": "annual",
     "url": "https://www.crowdstrike.com/en-us/global-threat-report/"},
    {"org": "IBM", "title": "X-Force Threat Intelligence Index", "cadence": "annual",
     "url": "https://www.ibm.com/reports/threat-intelligence"},
    {"org": "Palo Alto Networks", "title": "Unit 42 research", "cadence": "continuous",
     "url": "https://unit42.paloaltonetworks.com/"},
    {"org": "Recorded Future", "title": "Insikt Group research", "cadence": "continuous",
     "url": "https://www.recordedfuture.com/research"},
    {"org": "ENISA", "title": "ENISA Threat Landscape", "cadence": "annual",
     "url": "https://www.enisa.europa.eu/publications"},
    {"org": "NCSC (UK)", "title": "Annual Review", "cadence": "annual",
     "url": "https://www.ncsc.gov.uk/"},
    {"org": "Dragos", "title": "OT/ICS Cybersecurity Year in Review", "cadence": "annual",
     "url": "https://www.dragos.com/ot-cybersecurity-year-in-review/"},
]


@source(id="reports", table="reports", title="Vendor & agency threat reports (curated)",
        licence="Links only - reports are copyright of their publishers",
        cadence="manual", homepage="")
def build_reports():
    return VENDOR_REPORTS


# ===========================================================================
# Runner
# ===========================================================================
def count_rows(data):
    if isinstance(data, dict):
        if "rows" in data and isinstance(data["rows"], list):
            return len(data["rows"])
        if data and all(isinstance(v, list) for v in data.values()):
            return sum(len(v) for v in data.values())
        return len(data)
    return len(data)


def main():
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "cyber_data")
    out_dir.mkdir(parents=True, exist_ok=True)
    only = set(x for x in os.environ.get("ONLY_SOURCES", "").split(",") if x)

    results, entries = {}, []
    for src in REGISTRY:
        if only and src.id not in only:
            continue
        if src.needs_key and not os.environ.get(src.needs_key):
            print("[skip] %s: %s not set" % (src.id, src.needs_key))
            entries.append({"id": src.id, "title": src.title, "table": src.table,
                            "licence": src.licence, "homepage": src.homepage,
                            "status": "skipped (no key)", "rows": 0})
            continue
        print("[build] %s -> %s" % (src.id, src.table))
        t0 = time.time()
        try:
            data = src.fn()
            results[src.id] = data
            entries.append({"id": src.id, "title": src.title, "table": src.table,
                            "licence": src.licence, "homepage": src.homepage,
                            "cadence": src.cadence, "status": "ok",
                            "rows": count_rows(data),
                            "seconds": round(time.time() - t0, 1)})
        except Exception as exc:                       # noqa: BLE001
            print("[error] %s failed: %s - previous output left in place" % (src.id, exc))
            entries.append({"id": src.id, "title": src.title, "table": src.table,
                            "licence": src.licence, "homepage": src.homepage,
                            "status": "failed: %s" % str(exc)[:120], "rows": 0})

    tables = {}

    # ---- incidents (partitioned) ----
    inc_files, inc_counts = {}, {}
    if "eurepoc" in results:
        write_json(out_dir / "incidents" / "eurepoc.json", results["eurepoc"])
        inc_files["eurepoc"] = "incidents/eurepoc.json"
        inc_counts["eurepoc"] = len(results["eurepoc"])
    if "vcdb" in results:
        by_year = {}
        for row in results["vcdb"]:
            y = (row.get("timeline.incident.year") or "").strip()
            by_year.setdefault(y, []).append(row)
        parts = {}
        for y in sorted(by_year):
            p = "incidents/vcdb-%s.json" % y
            write_json(out_dir / p, by_year[y])
            parts[y] = {"file": p, "rows": len(by_year[y])}
        inc_files["vcdb_partitions"] = parts
        inc_counts["vcdb"] = len(results["vcdb"])
    if "rwlive" in results:
        write_json(out_dir / "incidents" / "rwlive.json", results["rwlive"])
        inc_files["rwlive"] = "incidents/rwlive.json"
        inc_counts["rwlive"] = sum(len(v) for v in results["rwlive"].values())
    if inc_files:
        tables["incidents"] = {"files": inc_files, "counts": inc_counts,
                               "total": sum(inc_counts.values())}

    # ---- vulns ----
    vulns = {}
    if "kev" in results:
        write_json(out_dir / "vulns" / "kev.json", results["kev"])
        vulns["kev"] = {"file": "vulns/kev.json", "rows": len(results["kev"])}
    if "epss" in results:
        write_json(out_dir / "vulns" / "epss.json", results["epss"])
        vulns["epss"] = {"file": "vulns/epss.json",
                         "rows": len(results["epss"]["rows"]), "min_score": EPSS_MIN}
    if vulns:
        tables["vulns"] = {"files": vulns}

    # ---- advisories ----
    if "icsadv" in results:
        write_json(out_dir / "advisories" / "ics.json", results["icsadv"])
        tables["advisories"] = {"files": {"ics": {"file": "advisories/ics.json",
                                                  "rows": len(results["icsadv"])}}}

    # ---- techniques ----
    if "attack" in results:
        a = results["attack"]
        write_json(out_dir / "techniques" / "attack.json", a)
        tables["techniques"] = {"files": {"attack": {
            "file": "techniques/attack.json",
            "techniques": len(a["techniques"]), "groups": len(a["groups"])}}}

    # ---- reports ----
    if "reports" in results:
        write_json(out_dir / "reports" / "vendor.json", results["reports"])
        tables["reports"] = {"files": {"vendor": {"file": "reports/vendor.json",
                                                  "rows": len(results["reports"])}}}

    manifest = {
        "schema": SCHEMA_VERSION,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tables": tables,
        "sources": entries,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")

    print("\n[done] manifest written. Summary:")
    for e in entries:
        print("   %-9s %-30s %8d rows" % (e["id"], e["status"][:30], e["rows"]))
    total_mb = sum(f.stat().st_size for f in out_dir.rglob("*.json")) / 1e6
    print("   total pack size: %.1f MB" % total_mb)


if __name__ == "__main__":
    main()
