#!/usr/bin/env python3
"""
build_cyber_data.py v3.5.0 (2026-07-23) - data-lake builder for Cyber Attack Earth.

VERSION HISTORY (newest first) - check manifest.json "builder" to see what ran
-----------------------------------------------------------------------------
 3.5.0  Version stamped into the run banner and manifest; per-source expected row
        counts; CISSM switched to the Base44 API-key model with a manual-export
        fallback that accepts any .csv/.json in manual_sources/ or the repo root.
 3.4.0  ICS advisories merged across the whole archive rather than one file
        (394 -> ~3,900 rows); attacker-origin column guarded against falling back
        onto the victim country.
 3.3.0  CVE backfill bounded per run with throttle detection and caching.
 3.2.0  CISSM connector added; CVE publication-volume series added.
 3.1.0  ICS Advisory Project column matching normalised.
 3.0.0  Connector registry, typed tables, partitioned incidents, manifest.

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
# Bump this whenever the builder changes. It is printed at the start of every run and
# written into manifest.json, so you can tell at a glance which version produced a
# given data pack - and spot immediately if an old copy is still deployed.
BUILDER_VERSION = "3.5.0"
BUILDER_DATE = "2026-07-23"
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
    expected: int = 0          # roughly what a healthy run should return; the app
                               # compares this against reality so shortfalls are obvious
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
        homepage="https://eurepoc.eu/", expected=4300)
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
        homepage="https://verisframework.org/vcdb.html", expected=10400)
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
        cadence="daily", homepage="https://www.ransomware.live/about", expected=21000)
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
        homepage="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", expected=1650)
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
        homepage="https://www.first.org/epss/", expected=17000)
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
        homepage="https://attack.mitre.org/", expected=870)
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
        cadence="weekly", homepage="https://www.icsadvisoryproject.com/", expected=3800)
def build_icsadv():
    """Pull the full ICS advisory archive.

    The repository publishes several CSVs: usually a consolidated/master file plus
    per-year or per-release files. Taking only the newest filename gave a single
    year (~400 rows) instead of the whole history, so this now prefers a master
    file if one exists and otherwise merges every CSV, de-duplicating by advisory ID.
    """
    listing = get_json("https://api.github.com/repos/%s/contents/%s"
                       % (ICSAP_REPO, ICSAP_DIR), timeout=60)
    csvs = [f for f in listing if f["name"].lower().endswith(".csv")]
    if not csvs:
        raise RuntimeError("no CSV found in ICS Advisory Project repo")
    print("  [icsadv] %d CSV files in %s" % (len(csvs), ICSAP_DIR))

    # A consolidated file, if the project publishes one, is a single cheap fetch.
    master = [f for f in csvs
              if re.search(r"master|consolidat|all[_-]?ics|full|combined", f["name"], re.I)]
    if master:
        chosen = sorted(master, key=lambda f: f["name"])[-1:]
        print("  [icsadv] using consolidated file: %s" % chosen[0]["name"])
    else:
        chosen = sorted(csvs, key=lambda f: f["name"])[:60]
        print("  [icsadv] no consolidated file - merging %d CSVs" % len(chosen))

    def parse_one(text, label):
        rdr = csv.DictReader(io.StringIO(text))
        header = rdr.fieldnames or []
        rows = list(rdr)
        if not rows:
            return []
        find = col_finder(header)
        col_id = find("ics cert number", "ics cert no", "advisory id",
                      "advisory number", "id")
        if not col_id:
            pat = re.compile(r"^ICS(MA)?A?-\d{2}-\d{3}", re.I)
            for h in header:
                hits = sum(1 for r in rows[:60] if pat.match(str(r.get(h) or "").strip()))
                if hits >= 15:
                    col_id = h
                    break
        if not col_id:
            print("  [icsadv] %s: could not find an advisory-ID column; header=%s"
                  % (label, header[:8]))
            return []
        col_date = find("original release date", "release date", "date published", "date")
        col_vendor = find("vendor")
        col_product = find("product")
        col_sector = find("critical infrastructure sectors",
                          "critical infrastructure sector", "ci sector", "sector")
        col_cve = find("cve", "cves")
        col_cvss = find("cvss v4 base", "cvss v3 base", "cvss v4", "cvss v3", "cvss")

        def val(row, col, limit=120):
            return (row.get(col) or "").strip()[:limit] if col else ""

        out = []
        for row in rows:
            adv = val(row, col_id, 24)
            if not adv:
                continue
            rel = val(row, col_date, 24)
            ym = re.search(r"(20\d{2})", rel) or re.search(r"ICS\w*-(\d{2})-", adv)
            year = None
            if ym:
                g = ym.group(1)
                year = int(g) if len(g) == 4 else 2000 + int(g)
            iso = ""
            m1 = re.match(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})", rel)
            m2 = re.match(r"(\d{1,2})[-/](\d{1,2})[-/](20\d{2})", rel)
            if m1:
                iso = "%s-%02d-%02d" % (m1.group(1), int(m1.group(2)), int(m1.group(3)))
            elif m2:
                iso = "%s-%02d-%02d" % (m2.group(3), int(m2.group(1)), int(m2.group(2)))
            out.append({
                "id": adv,
                "title": val(row, col_product) or val(row, col_vendor),
                "vendor": val(row, col_vendor, 60),
                "date": iso or rel[:10],
                "year": year,
                "sectors": val(row, col_sector, 160),
                "cves": val(row, col_cve, 120),
                "cvss": val(row, col_cvss, 8),
            })
        return out

    merged, seen, files_used = [], set(), 0
    for f in chosen:
        try:
            text = get(f["download_url"], timeout=180).content.decode("utf-8", "replace")
        except Exception as exc:                              # noqa: BLE001
            print("  [icsadv] skip %s (%s)" % (f["name"], str(exc)[:60]))
            continue
        rows = parse_one(text, f["name"])
        added = 0
        for a in rows:
            if a["id"] in seen:
                continue
            seen.add(a["id"])
            merged.append(a)
            added += 1
        files_used += 1
        if added:
            print("  [icsadv] %s: %d rows, %d new (running total %d)"
                  % (f["name"], len(rows), added, len(merged)))
    years = sorted({a["year"] for a in merged if a["year"]})
    print("  [icsadv] %d files read -> %d distinct advisories, %s-%s"
          % (files_used, len(merged),
             years[0] if years else "?", years[-1] if years else "?"))
    if not merged:
        raise RuntimeError("zero advisories parsed")
    return merged


# ===========================================================================
# LAYER 1b - CISSM Cyber Events Database (MANUAL DROP)
# CISSM does not publish a public bulk download: detailed records are released
# on request to researchers and public officials (contact Dr Charles Harry,
# charry@umd.edu). We therefore do NOT scrape it and do NOT use third-party
# mirrors. If you obtain your own export, drop the CSV in:
#       manual_sources/cissm.csv
# and this connector will pick it up automatically. Otherwise it skips cleanly.
# Cite: Harry, C., & Gallagher, N. (2018). Classifying Cyber Events.
#       Journal of Information Warfare, 17(3), 17-31.
# ===========================================================================
MANUAL_DIR = Path("manual_sources")


def norm_header(s):
    return re.sub(r"[^a-z0-9]+", " ", str(s or "").lower()).strip()


def col_finder(header):
    """Find a column by normalised name: exact match first, then substring.

    `exclude` prevents a column already claimed by a more specific field from being
    reused - without it, "actor country" falls back to the victim's "country" and
    every attack appears to originate from its own victim.
    """
    normmap = {norm_header(h): h for h in header if h}

    def find(*cands, **kw):
        exclude = set(kw.get("exclude") or ())
        for c in cands:
            if c in normmap and normmap[c] not in exclude:
                return normmap[c]
        for c in cands:
            for nk, orig in normmap.items():
                if orig in exclude:
                    continue
                if c in nk or nk in c:
                    return orig
        return None
    return find


# Automated download from the GoTech Cyber Events Database portal
# (https://cybereventsdatabase.org). Credentials come from environment variables
# only -- NEVER hardcode them, and never commit them: this repository is public.
#
#   Repo -> Settings -> Secrets and variables -> Actions -> New repository secret
#       CISSM_USER   your portal email
#       CISSM_PASS   your portal password
#   then in .github/workflows/update-cyber-data.yml add to the build step:
#       env:
#         CISSM_USER: ${{ secrets.CISSM_USER }}
#         CISSM_PASS: ${{ secrets.CISSM_PASS }}
#
# Portals change their login flow without notice, so if the automated route
# fails the connector falls back to a manual export at manual_sources/cissm.csv
# and tells you exactly what it saw. Optional overrides if the paths move:
#       CISSM_LOGIN_URL, CISSM_DOWNLOAD_URL
# The portal is a Base44 application. Base44 apps authenticate with an API key,
# not a scripted username/password login (sign-in is browser-based), and expose
# their data through an auto-generated REST "entities" endpoint.
#
# HOW TO SET THIS UP
#   1. Sign in at https://cybereventsdatabase.org in a browser
#   2. Open the "Api Management" page and create / copy your API key
#   3. Repo -> Settings -> Secrets and variables -> Actions -> New repository secret
#         CISSM_API_KEY   the key from that page
#   4. Make sure the workflow passes it through:
#         env:
#           CISSM_API_KEY: ${{ secrets.CISSM_API_KEY }}
#
# If the Api Management page shows an exact request URL, put it in CISSM_DOWNLOAD_URL
# and this connector will use it verbatim - that is the most reliable route.
# Optional overrides: CISSM_APP_ID, CISSM_ENTITY, CISSM_DOWNLOAD_URL
CISSM_APP_ID_DEFAULT = "68c3041c75bb09b9728e4b37"      # from the site's own asset URLs
CISSM_API_ROOT = "https://app.base44.com/api/apps"
CISSM_ENTITY_CANDIDATES = ["CyberEvent", "CyberEvents", "Event", "Events",
                           "CyberEventRecord", "Incident", "Incidents"]
CISSM_PAGE_SIZE = 500
CISSM_MAX_PAGES = 200
CISSM_DIAG = ""          # short summary, surfaced in manifest.json so it can be read
                         # without opening the Actions log


def _cissm_rows_from_json(payload):
    if isinstance(payload, dict):
        for k in ("data", "events", "results", "rows", "items", "records"):
            if isinstance(payload.get(k), list):
                return payload[k]
        return []
    return payload if isinstance(payload, list) else []


def _cissm_get(url, key, params=None):
    """Base44 expects the key in an api_key header; send the common variants."""
    headers = dict(UA)
    headers["api_key"] = key
    headers["Authorization"] = "Bearer " + key
    headers["Accept"] = "application/json"
    return requests.get(url, headers=headers, params=params or {}, timeout=120)


def _cissm_pull_entity(url, key):
    """Page through an entities endpoint. Returns [] if the endpoint is not usable."""
    rows, skip = [], 0
    for page in range(CISSM_MAX_PAGES):
        try:
            r = _cissm_get(url, key, {"limit": CISSM_PAGE_SIZE, "skip": skip})
        except Exception as exc:                                  # noqa: BLE001
            print("  [cissm] %s failed: %s" % (url, str(exc)[:90]))
            return rows
        if r.status_code >= 400:
            if page == 0:
                print("  [cissm] %s -> HTTP %d %s"
                      % (url, r.status_code, (r.text or "")[:80].replace("\n", " ")))
            return rows
        try:
            batch = _cissm_rows_from_json(r.json())
        except Exception:                                         # noqa: BLE001
            # not JSON - it may be a direct CSV export
            body = r.content.decode("utf-8", "replace")
            if "," in body.split("\n", 1)[0]:
                return list(csv.DictReader(io.StringIO(body)))
            return rows
        if not batch:
            break
        rows.extend(batch)
        print("  [cissm] page %d: +%d (total %d)" % (page + 1, len(batch), len(rows)))
        if len(batch) < CISSM_PAGE_SIZE:
            break
        skip += len(batch)
        time.sleep(0.4)
    return rows


def _cissm_fetch_remote():
    """Fetch via the Base44 API. Returns list-of-dicts, or None to fall back."""
    global CISSM_DIAG
    key = os.environ.get("CISSM_API_KEY", "").strip()
    if not key:
        legacy = os.environ.get("CISSM_USER", "").strip()
        CISSM_DIAG = ("no CISSM_API_KEY set - looking for a manual export instead. "
                      "The portal is a Base44 app; API keys are only offered to admin "
                      "accounts, so the Download Dataset export is the normal route."
                      + (" CISSM_USER/CISSM_PASS cannot be used and can be deleted."
                         if legacy else ""))
        print("  [cissm] %s" % CISSM_DIAG)
        return None
    print("  [cissm] CISSM_API_KEY seen (%d chars)" % len(key))

    explicit = os.environ.get("CISSM_DOWNLOAD_URL", "").strip()
    if explicit:
        print("  [cissm] using CISSM_DOWNLOAD_URL")
        rows = _cissm_pull_entity(explicit, key)
        if rows:
            CISSM_DIAG = "ok via CISSM_DOWNLOAD_URL"
            return rows
        CISSM_DIAG = "CISSM_DOWNLOAD_URL returned no rows - check the URL and key"
        return None

    app_id = os.environ.get("CISSM_APP_ID", "").strip() or CISSM_APP_ID_DEFAULT
    entities = ([os.environ["CISSM_ENTITY"]] if os.environ.get("CISSM_ENTITY")
                else CISSM_ENTITY_CANDIDATES)
    tried = []
    for ent in entities:
        url = "%s/%s/entities/%s" % (CISSM_API_ROOT, app_id, ent)
        print("  [cissm] trying entity %s" % ent)
        rows = _cissm_pull_entity(url, key)
        tried.append(ent)
        if rows:
            print("  [cissm] entity %s returned %d records" % (ent, len(rows)))
            CISSM_DIAG = "ok via entity %s (%d records)" % (ent, len(rows))
            return rows
    CISSM_DIAG = ("API key accepted but no entity matched (tried: %s). Open the Api "
                  "Management page, copy the exact request URL, and set it as "
                  "CISSM_DOWNLOAD_URL - or set CISSM_ENTITY to the entity name."
                  % ", ".join(tried))
    print("  [cissm] %s" % CISSM_DIAG)
    return None


@source(id="cissm", table="incidents",
        title="CISSM / GoTech Cyber Events Database",
        licence="Access granted by CISSM on request - do not redistribute raw records",
        cadence="manual export", homepage="https://cybereventsdatabase.org", expected=17169)
def _cissm_manual_rows():
    """Read an export the user downloaded from the portal's Analytics dashboard.

    Accepts any .csv or .json dropped in manual_sources/ - the portal names its
    exports with a timestamp, so requiring an exact filename just creates a
    needless step. The newest usable file wins.
    """
    # Look in manual_sources/ first, then the repository root - uploading into a
    # subfolder is awkward from a phone, so either location is accepted. The search
    # is not recursive, so the data lake's own JSON files are never picked up.
    pool = []
    for d in (MANUAL_DIR, Path(".")):
        if d.exists():
            pool += [p for p in d.iterdir()
                     if p.suffix.lower() in (".csv", ".json") and p.is_file()]
    if not pool:
        return None
    cands = sorted(pool,
                   key=lambda p: (p.name.lower().startswith("cissm"), p.stat().st_size),
                   reverse=True)
    for path in cands:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:                                  # noqa: BLE001
            print("  [cissm] cannot read %s (%s)" % (path.name, str(exc)[:60]))
            continue
        rows = []
        if path.suffix.lower() == ".json":
            try:
                rows = _cissm_rows_from_json(json.loads(text))
            except Exception as exc:                              # noqa: BLE001
                print("  [cissm] %s is not valid JSON (%s)" % (path.name, str(exc)[:60]))
                continue
        else:
            rows = list(csv.DictReader(io.StringIO(text)))
        if rows and isinstance(rows[0], dict):
            print("  [cissm] using manual export %s (%d rows, %.1f MB)"
                  % (path.name, len(rows), path.stat().st_size / 1e6))
            return rows
        print("  [cissm] %s contained no usable rows" % path.name)
    return None


def build_cissm():
    rows = _cissm_fetch_remote()
    if rows is None:
        rows = _cissm_manual_rows()
    if rows is None:
        raise RuntimeError(
            "%s | no export found. Sign in at cybereventsdatabase.org, open Analytics, "
            "press Download Dataset, and commit the file to the repository - either in "
            "manual_sources/ or the top level. Any .csv or .json filename works."
            % (CISSM_DIAG or "portal download unavailable"))
    if not rows:
        raise RuntimeError("no rows obtained")
    header = list(rows[0].keys())
    print("  [cissm] fields: %s" % (header,))
    find = col_finder(header)
    c_date = find("event date", "date", "date published", "eventdate", "event_date")
    c_org = find("organization", "target", "victim", "organisation", "entity")
    c_ind = find("industry", "sector", "industry code")
    # Victim country first, so the attacker-origin lookup cannot fall back onto it.
    c_country = find("country", "country of impact", "impacted country", "target country")
    c_actorc = find("actor country", "threat actor country", "country of actor",
                    "attacker country", "origin country", exclude=[c_country])
    # Only trust an origin column that actually names an actor/attacker/origin.
    if c_actorc and not re.search(r"actor|attack|threat|origin|source",
                                  norm_header(c_actorc)):
        print("  [cissm] ignoring %r as attacker origin - not an actor column" % c_actorc)
        c_actorc = None
    c_actor = find("actor", "threat actor", "actor name", "actor type",
                   exclude=[c_org, c_country, c_actorc])
    c_type = find("event type", "type", "event subtype", "attack type")
    c_desc = find("description", "summary", "event description")
    c_url = find("source url", "url", "source", "link")
    print("  [cissm] mapped -> date=%r actor=%r actor_country=%r org=%r industry=%r "
          "country=%r type=%r" % (c_date, c_actor, c_actorc, c_org, c_ind, c_country, c_type))
    if not (c_date and c_country):
        raise RuntimeError("could not identify date and country columns")

    def v(row, col, limit=160):
        return str(row.get(col) or "").strip()[:limit] if col else ""

    out = []
    for row in rows:
        d = v(row, c_date, 24)
        m = (re.search(r"(20\d{2})[-/](\d{1,2})", d)
             or re.search(r"(\d{1,2})[-/](\d{1,2})[-/](20\d{2})", d))
        if not m:
            continue
        if len(m.group(1)) == 4:
            year, month = int(m.group(1)), int(m.group(2))
        else:
            year, month = int(m.group(3)), int(m.group(1))
        if not (START_YEAR <= year <= date.today().year) or not (1 <= month <= 12):
            continue
        out.append({
            "year": year, "month": month,
            "actor": v(row, c_actor, 80),
            "actor_country": v(row, c_actorc, 60),
            "org": v(row, c_org, 120),
            "industry": v(row, c_ind, 60),
            "country": v(row, c_country, 60),
            "type": v(row, c_type, 60),
            "desc": v(row, c_desc, 400),
            "url": v(row, c_url, 200),
        })
    print("  [cissm] %d records -> %d usable events" % (len(rows), len(out)))
    if not out:
        raise RuntimeError("no usable events parsed")
    return out


# ===========================================================================
# LAYER 2b - CVE publication volume (context series, NOT incidents)
# Monthly counts of published CVEs, used as a third overlay alongside incidents
# and KEV additions: attack surface growing vs attacks growing vs
# known-exploited growing. Uses NVD's public endpoint with resultsPerPage=1 and
# reads only totalResults - no records are downloaded or redistributed.
# No API key required; setting NVD_API_KEY simply raises the rate limit.
# Historical months are cached in the output file, so only the trailing window
# is refetched on later runs.
# ===========================================================================
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_REFRESH_MONTHS = 24        # trailing months re-checked every run
CVE_MAX_FETCH_PER_RUN = 40     # bound the work: history fills in over several runs
CVE_MAX_SECONDS = 420          # hard stop, so one slow source cannot stall the build


@source(id="cve", table="vulns", title="CVE publication volume (NVD)",
        licence="NVD data - US Government work, public domain", cadence="daily",
        homepage="https://nvd.nist.gov/", expected=320)
def build_cve(out_dir=None):
    key = os.environ.get("NVD_API_KEY", "").strip()
    headers = dict(UA)
    if key:
        headers["apiKey"] = key
    delay = 0.8 if key else 6.5          # NVD: 50 req/30s with key, 5 req/30s without

    prior = {}
    cache = (out_dir or Path("cyber_data")) / "vulns" / "cve.json"
    if cache.exists():
        try:
            prior = json.loads(cache.read_text(encoding="utf-8")).get("months", {})
        except Exception:                                  # noqa: BLE001
            prior = {}
    today = date.today()
    now_idx = today.year * 12 + today.month
    months = []
    y, m = START_YEAR, 1
    while y * 12 + m <= now_idx:
        months.append((y, m))
        m += 1
        if m == 13:
            y, m = y + 1, 1

    # Newest first: the recent end of the chart is the useful part, and it means a
    # partial history still looks sensible. Older months fill in on later runs.
    months.reverse()
    counts, fetched, reused, t_start = dict(prior), 0, 0, time.time()
    throttled, failures = 0, 0
    for (y, m) in months:
        keyname = "%d-%02d" % (y, m)
        recent = (now_idx - (y * 12 + m)) < CVE_REFRESH_MONTHS
        if keyname in counts and not recent:
            reused += 1
            continue
        if fetched >= CVE_MAX_FETCH_PER_RUN:
            print("  [cve] per-run fetch cap (%d) reached; remaining history will fill "
                  "in on later runs" % CVE_MAX_FETCH_PER_RUN)
            break
        if time.time() - t_start > CVE_MAX_SECONDS:
            print("  [cve] time budget (%ds) reached; stopping this run cleanly"
                  % CVE_MAX_SECONDS)
            break
        last_day = 28
        for d in (31, 30, 29, 28):
            try:
                date(y, m, d); last_day = d; break
            except ValueError:
                continue
        params = {
            "pubStartDate": "%04d-%02d-01T00:00:00.000" % (y, m),
            "pubEndDate": "%04d-%02d-%02dT23:59:59.999" % (y, m, last_day),
            "resultsPerPage": 1,
        }
        try:
            r = requests.get(NVD_API, params=params, headers=headers, timeout=60)
            if r.status_code in (403, 429):
                throttled += 1
                if throttled >= 3:
                    print("  [cve] NVD is throttling this runner repeatedly - stopping "
                          "here and keeping what we have. Add a free NVD_API_KEY secret "
                          "to raise the limit.")
                    break
                print("  [cve] throttled at %s; backing off 20s" % keyname)
                time.sleep(20)
                r = requests.get(NVD_API, params=params, headers=headers, timeout=60)
            r.raise_for_status()
            counts[keyname] = int(r.json().get("totalResults", 0))
            fetched += 1
            if fetched % 10 == 0:
                print("  [cve] %s: %d published (%d fetched, %d cached, %ds elapsed)"
                      % (keyname, counts[keyname], fetched, reused,
                         int(time.time() - t_start)))
            time.sleep(delay)
        except Exception as exc:                            # noqa: BLE001
            print("  [warn] cve %s failed (%s)" % (keyname, exc))
            failures += 1
            if failures >= 8:
                print("  [cve] too many consecutive failures - stopping this run")
                break
            time.sleep(3)
    if not counts:
        raise RuntimeError("no CVE counts retrieved (NVD may be throttling this runner)")
    missing = len(months) - len(counts)
    print("  [cve] %d months total (%d fetched this run, %d cached, %d still to backfill)"
          % (len(counts), fetched, reused, max(0, missing)))
    return {"months": counts, "note": "Monthly count of CVEs published, from NVD. "
                                      "Counts shift slightly over time as records are backdated."}


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
    {"org": "NCSC (UK)", "title": "OT and industrial control system guidance", "cadence": "continuous",
     "url": "https://www.ncsc.gov.uk/collection/operational-technology"},
    {"org": "ENISA", "title": "ENISA Threat Landscape", "cadence": "annual",
     "url": "https://www.enisa.europa.eu/topics/cyber-threats/threats-and-trends"},
    {"org": "CISA", "title": "ICS advisories and OT alerts", "cadence": "continuous",
     "url": "https://www.cisa.gov/news-events/cybersecurity-advisories"},
    {"org": "WEF", "title": "Global Cybersecurity Outlook", "cadence": "annual",
     "url": "https://www.weforum.org/publications/"},
    {"org": "Verizon", "title": "Data Breach Investigations Report (DBIR)", "cadence": "annual",
     "url": "https://www.verizon.com/business/resources/reports/dbir/"},
    {"org": "CISSM (UMD)", "title": "Cyber Events Database", "cadence": "continuous",
     "url": "https://cissm.umd.edu/cyber-events-database"},
]


@source(id="reports", table="reports", title="Vendor & agency threat reports (curated)",
        licence="Links only - reports are copyright of their publishers",
        cadence="manual", homepage="", expected=15)
def build_reports():
    return VENDOR_REPORTS


# ===========================================================================
# Runner
# ===========================================================================
def count_rows(data):
    """Row count for the manifest. Handles the several shapes connectors return."""
    if isinstance(data, dict):
        if "rows" in data and isinstance(data["rows"], list):
            return len(data["rows"])
        if isinstance(data.get("months"), dict):        # CVE volume series
            return len(data["months"])
        if isinstance(data.get("techniques"), list):    # ATT&CK bundle
            return len(data["techniques"]) + len(data.get("groups", []))
        if data and all(isinstance(v, list) for v in data.values()):
            return sum(len(v) for v in data.values())   # month -> list (rwlive)
        return len(data)
    return len(data)


def main():
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "cyber_data")
    out_dir.mkdir(parents=True, exist_ok=True)
    print("=" * 66)
    print("  BUILDER v%s   (%s)   schema v%d" % (BUILDER_VERSION, BUILDER_DATE, SCHEMA_VERSION))
    print("  output: %s" % out_dir.resolve())
    print("  If manifest.json does not show builder %s afterwards, the repository"
          % BUILDER_VERSION)
    print("  is still running an older copy of this script.")
    print("=" * 66)
    only = set(x for x in os.environ.get("ONLY_SOURCES", "").split(",") if x)

    results, entries = {}, []
    for src in REGISTRY:
        if only and src.id not in only:
            continue
        if src.needs_key and not os.environ.get(src.needs_key):
            print("[skip] %s: %s not set" % (src.id, src.needs_key))
            entries.append({"id": src.id, "title": src.title, "table": src.table,
                            "licence": src.licence, "homepage": src.homepage,
                            "expected": src.expected,
                            "status": "skipped (no key)", "rows": 0})
            continue
        print("[build] %s -> %s" % (src.id, src.table))
        t0 = time.time()
        try:
            import inspect
            data = (src.fn(out_dir=out_dir)
                    if "out_dir" in inspect.signature(src.fn).parameters else src.fn())
            results[src.id] = data
            entries.append({"id": src.id, "title": src.title, "table": src.table,
                            "licence": src.licence, "homepage": src.homepage,
                            "cadence": src.cadence, "status": "ok",
                            "expected": src.expected, "rows": count_rows(data),
                            "seconds": round(time.time() - t0, 1)})
        except Exception as exc:                       # noqa: BLE001
            print("[error] %s failed: %s - previous output left in place" % (src.id, exc))
            entries.append({"id": src.id, "title": src.title, "table": src.table,
                            "licence": src.licence, "homepage": src.homepage,
                            "expected": src.expected,
                            "status": "failed: %s" % str(exc)[:300], "rows": 0})

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
    if "cissm" in results:
        write_json(out_dir / "incidents" / "cissm.json", results["cissm"])
        inc_files["cissm"] = "incidents/cissm.json"
        inc_counts["cissm"] = len(results["cissm"])
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
    if "cve" in results:
        write_json(out_dir / "vulns" / "cve.json", results["cve"])
        vulns["cve"] = {"file": "vulns/cve.json",
                        "months": len(results["cve"]["months"])}
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
        "builder": BUILDER_VERSION,
        "builder_date": BUILDER_DATE,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tables": tables,
        "sources": entries,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")

    print("\n[done] manifest written by BUILDER v%s (schema v%d). Summary:"
          % (BUILDER_VERSION, SCHEMA_VERSION))
    for e in entries:
        exp = e.get("expected") or 0
        if not exp:
            health = ""
        elif e["rows"] == 0:
            health = "  <-- MISSING (expected ~%d)" % exp
        elif e["rows"] < exp * 0.9:
            health = "  <-- LOW (%d%% of ~%d expected)" % (round(100 * e["rows"] / exp), exp)
        else:
            health = "  ok vs ~%d expected" % exp
        print("   %-9s %-30s %8d rows%s" % (e["id"], e["status"][:30], e["rows"], health))
    total_mb = sum(f.stat().st_size for f in out_dir.rglob("*.json")) / 1e6
    print("   total pack size: %.1f MB" % total_mb)
    print("\n   Verify in cyber_data/manifest.json:  \"builder\": \"%s\"" % BUILDER_VERSION)


if __name__ == "__main__":
    main()
