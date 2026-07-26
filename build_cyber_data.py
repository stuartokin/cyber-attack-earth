#!/usr/bin/env python3
"""
build_cyber_data.py v3.14.1 (2026-07-26) - data-lake builder for Cyber Attack Earth.

VERSION HISTORY (newest first) - check manifest.json "builder" to see what ran
-----------------------------------------------------------------------------
 3.14.1 Advisory extraction from ATT&CK now works two independent ways: reference
        URLs containing an advisory identifier (whatever the host path), and the
        "(Citation: CISA AA20-239A ...)" markers MITRE writes into its prose, scanned
        across the full description rather than the truncated first sentence. Neither
        depends on the other, because the raw bundle could not be inspected before
        writing this and a single assumption about URL shape was too fragile to rely
        on. Each group also reports how many advisories were found, so a zero is
        visible rather than silent.
 3.14.0 cisa.gov returns HTTP 403 to automated requests for its advisory feeds and
        index pages from a datacentre address; its static files (the KEV catalogue)
        are cached and unaffected. Rather than defeat that control, the advisory list
        is now taken from the CISA advisories MITRE cites in the ATT&CK bundle we
        already download - published for programmatic use, and attributed to each
        group by MITRE rather than by my own text matching, which is better sourced
        than the original design. Advisory page bodies remain unreadable, so CVE
        links are absent and each record records that; identifiers, titles, links and
        group attribution are unaffected. The direct routes are retained in case the
        site becomes reachable.
 3.13.1 The CISA advisory connector returned nothing on its first real run and the
        manifest could not say why, because both failure paths looked identical. It now
        tries three feed paths and then falls back to scraping the advisories index for
        the /advisories/aaNN-NNNx link pattern, which has been stable far longer than
        any feed URL. Every attempt logs its HTTP status, content type, body size and
        how many advisories were recognised, so a failure names its own cause. Dates
        missing from a listing are recovered from the advisory page.
 3.13.0 CISA cybersecurity advisories (AA series) added as an ENRICHMENT source, not
        an incident source: a joint advisory says what a named actor does and which
        flaws they use, never who was attacked, so it adds nothing to the incident
        count and nothing to the review queue. Each advisory carries its identifier,
        date, the CVEs it references, ATT&CK technique identifiers, and any threat
        group whose ATT&CK alias it names. Group matching ignores aliases shorter
        than five characters and requires a word boundary, because attaching an
        advisory to the wrong actor is worse than attaching it to none. Pages are
        read a bounded number per run and cached.
 3.12.0 EuRepoC static release now follows Zenodo's own versioning instead of two
        hard-coded URLs pinned to version 1.3.2. The build resolves the newest release
        in the series, says so in the log when it moves, and records the version and
        DOI in manifest.json so a published chart can cite exactly what it was built
        on. The pinned URLs remain as a fallback. This removes a silent staleness
        failure: the previous code would have served 1.3.2 indefinitely.
 3.11.2 Hardened the NVD record parser against malformed input: a non-string date,
        or a list holding something other than a dictionary, would previously raise
        and stop the whole connector rather than skipping one bad record. Found by
        fuzzing the parser rather than in the wild.
 3.11.1 Cosmetic tidy of the NVD detail: truncated descriptions end with an ellipsis
        rather than stopping mid-word, and records sort by CVE year and number rather
        than as text (so CVE-2025-9242 precedes CVE-2025-10035). No refetch needed;
        existing cached records keep their descriptions until next refreshed.
 3.11.0 NVD per-CVE detail added for the exploited catalogue only: severity and
        CVSS version, weakness identifiers, publication date, reference count and a
        short description, for the ~1,600 flaws CISA records as actually exploited.
        The full NVD corpus (~250,000 records) is deliberately NOT downloaded - it
        would be a multi-hundred-megabyte artefact almost none of which anyone would
        look at. Work is capped per run and cached in vulns/nvd.json, so the first
        few nights fill it in and later runs fetch only newly catalogued flaws.
        Publication dates make the gap between disclosure and observed exploitation
        measurable for the first time.
 3.10.0 KEV entries now carry the catalogue's weakness identifiers (cwes) and the
        remediation due date, so exploited flaws can be grouped by underlying weakness
        and by how urgently CISA required them fixed - the recurring-theme view, rather
        than only a vendor league table.
 3.9.0  Curated impact overlay moved out of the app into two human-maintained CSVs
        (impact_overlay.csv = one row per incident, impact_figures.csv = one row per
        figure with its own source URL and as_of date). The builder validates and
        joins them but never writes to them; a figure with no source URL is rejected
        rather than published, and every validation note is carried into the manifest
        as "warnings". Also stopped an overlay CSV in the repo root being mistaken for
        an unnamed CISSM export.
 3.8.1  Fixed a decorator-placement bug introduced in 3.8.0: the new _eurepoc_impact
        helper had been dropped between the @source("eurepoc") decorator and
        build_eurepoc, so the registry bound the source to the helper and the static
        EuRepoC dataset failed with "missing 1 required positional argument: 'row'"
        and returned zero rows. The helper now sits above the decorator. (Same class
        of bug as the 3.7.3 CISSM fix - a decorator must sit directly on its build_
        function.)
 3.8.0  EuRepoC impact coding captured. The TableView and static releases already
        score each reviewed incident on weighted cyber-intensity, functional
        disruption duration, data-breach severity and economic loss; the builder now
        maps those fields onto a clean `imp` dimension object per incident (a blank
        or "Not available" field stays absent, never a zero) to drive the app's new
        "Impact over time" chart. About 950 of the provisional records carry at least
        intensity; the richer dimensions follow the reviewed subset.
 3.7.3  Fixed the CISSM connector registration: the @source decorator had been left
        attached to a helper (_manual_rows) rather than to build_cissm, so the
        registry called the wrong function. This was the real cause of both the
        "missing argument: kind" and the "NoneType has no len()" failures.
 3.7.2  A connector returning None no longer poisons the run: results are validated
        before being stored, writes refuse null, the partition step checks values
        rather than keys, and any empty table left by an earlier build is removed.
        One failing source can no longer bring down the whole build.
 3.7.1  Removed a dead function left by the manual-export refactor and gave
        _manual_rows a default argument, so a stale or partial copy cannot raise
        "missing 1 required positional argument" in place of the real message.
 3.7.0  Disclosure-lag inputs retained: EuRepoC added_to_DB alongside start_date,
        and Ransomware.live's discovery date alongside the attack date, so the gap
        between an event and its appearance in a dataset can be measured.
 3.6.2  CVE per-run fetch cap lifts automatically when NVD_API_KEY is set, so the
        whole history completes in one run instead of five nights.
 3.6.1  TableView export slimmed to the static release's columns and the EuRepoC
        coding status ("Open" / "Coding finished") carried through to the app.
 3.6.0  EuRepoC TableView manual export supported as a provisional layer covering
        the period after the static release; manual-drop reader generalised so
        several sources can coexist; EuRepoC noted as CC BY-NC 4.0.
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
BUILDER_VERSION = "3.14.1"
BUILDER_DATE = "2026-07-26f"
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
    if obj is None:
        raise RuntimeError("refusing to write %s: nothing to write" % path.name)
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
    r"added.*to.*db", r"^added", r"detection.*disclosure",
]
LONG_TEXT = re.compile(r"description|summary", re.I)


# ── EuRepoC impact extraction ───────────────────────────────────────────────
# EuRepoC already scores each reviewed incident on intensity, functional
# disruption, data impact and economic loss. We map those coded fields onto the
# clean 0..N dimensions the app plots, and attach them as `imp`. Nothing is
# invented: a field that EuRepoC left blank or "Not available" stays absent, so
# the app's composite never counts a gap as a zero.
def _eurepoc_impact(row):
    def val(*names):
        for n in names:
            for k, v in row.items():
                if k and k.strip().lower() == n:
                    s = str(v or "").strip()
                    if s and s.lower() != "not available" and s.lower() != "none":
                        return s
        return None
    imp = {}
    # weighted cyber intensity: an integer 0..8+ (already a score)
    wi = val("weighted_cyber_intensity", "unweighted_cyber_intensity")
    if wi is not None:
        m = re.search(r"-?\d+", wi)
        if m:
            n = int(m.group(0))
            if n > 0:
                imp["intensity"] = min(8, n)
    # functional impact -> operational disruption duration ordinal
    fi = (val("functional_impact") or "").lower()
    if fi:
        if "no system" in fi or "no interference" in fi:
            imp["disruption"] = 0
        elif "month" in fi:
            imp["disruption"] = 4
        elif "week" in fi:
            imp["disruption"] = 3
        elif "day" in fi and "< 24" not in fi and "<24" not in fi:
            imp["disruption"] = 2
        elif "day" in fi or "24h" in fi or "< 24" in fi:
            imp["disruption"] = 1
    # intelligence impact -> data / breach severity ordinal
    ii = (val("intelligence_impact") or "").lower()
    if ii:
        if "major data breach" in ii:
            imp["data"] = 3
        elif "minor data breach" in ii:
            imp["data"] = 1
        elif "no data breach" in ii or "no data corruption" in ii:
            imp["data"] = 0
    # economic impact -> financial loss in USD (euro converted at a fixed, rough rate;
    # this is an order-of-magnitude view, not an audited figure)
    ev = val("economic_impact_exact_value")
    if ev is not None:
        m = re.search(r"-?\d+(?:\.\d+)?", ev.replace(",", ""))
        if m:
            amt = float(m.group(0))
            if amt > 0:
                cur = (val("economic_impact_currency") or "dollar").lower()
                if "eur" in cur:
                    amt *= 1.08          # rough EUR->USD; documented as approximate
                imp["financial"] = round(amt)
    return imp or None

# ── Zenodo: always take the newest EuRepoC release ─────────────────────────
# The static release was previously fetched from two hard-coded Zenodo URLs
# pinned to record 14965395 (version 1.3.2). That works until EuRepoC publishes
# a new version, at which point the app keeps serving the old one indefinitely
# and nothing says so - the worst kind of staleness, because it looks fine.
#
# Zenodo versions records and exposes a "latest" link on every version, so the
# fix is to start from any known record and follow it. The resolved version and
# DOI are recorded in the manifest, which also gives a citable reference for
# whichever release the published map is actually built on.
ZENODO_API = "https://zenodo.org/api"
EUREPOC_ZENODO_SEED = 14965395          # any known version; only used to find the series

# The dyadic file has one row per origin-to-target pair, which is what the map
# draws; several rows can share an incident id, and the app counts distinct
# incidents separately. The global file (one row per incident) is the fallback.
EUREPOC_FILE_PREFER = [r"dyadic", r"global"]
# Never these, whatever else is missing. The attribution file has one row per
# attribution CLAIM and the receiver file one row per affected country: both are
# different units of analysis, and silently loading one in place of the incident
# data would distort every count in the app. If neither preferred file is present,
# the fetcher refuses and the build falls back rather than guessing.
EUREPOC_FILE_NEVER = [r"attribution", r"receiver", r"codebook", r"readme"]

EUREPOC_RELEASE = {}                    # filled in by the fetcher, read by the manifest


def _zenodo_latest_record(seed_id):
    """Resolve the newest version of a Zenodo record series from any known member."""
    r = requests.get("%s/records/%s" % (ZENODO_API, seed_id), headers=UA, timeout=60)
    r.raise_for_status()
    rec = r.json()
    latest = ((rec.get("links") or {}).get("latest") or "")
    if latest:
        tail = str(latest).rstrip("/").split("/")[-1]
        if tail and tail != str(seed_id):
            r2 = requests.get(latest, headers=UA, timeout=60)
            r2.raise_for_status()
            rec = r2.json()
    return rec


def _zenodo_pick_csv(rec, prefer=None):
    """Choose which CSV in the record to use, by preference order of filename."""
    cands = []
    for f in (rec.get("files") or []):
        if not isinstance(f, dict):
            continue
        key = str(f.get("key") or f.get("filename") or "")
        if not key.lower().endswith(".csv"):
            continue
        links = f.get("links") or {}
        url = links.get("self") or links.get("download") or ""
        if url:
            cands.append((key, url, f.get("size") or 0))
    if not cands:
        return None, None, 0
    banned = [re.compile(p, re.I) for p in EUREPOC_FILE_NEVER]
    cands = [c for c in cands if not any(b.search(c[0]) for b in banned)]
    for pat in (prefer or EUREPOC_FILE_PREFER):
        rx = re.compile(pat, re.I)
        for key, url, size in cands:
            if rx.search(key):
                return key, url, size
    # Deliberately no "just take the first one": an unexpected file is more likely
    # to be the wrong unit of analysis than a usable substitute.
    return None, None, 0


def _zenodo_release_meta(rec):
    md = rec.get("metadata") or {}
    return {
        "record": rec.get("id") or rec.get("recid"),
        "concept": rec.get("conceptrecid"),
        "version": md.get("version") or "",
        "doi": rec.get("doi") or md.get("doi") or "",
        "published": (md.get("publication_date") or "")[:10],
        "title": (md.get("title") or "")[:140],
    }


def eurepoc_release_csv():
    """Newest EuRepoC release CSV as text, or None if Zenodo cannot be reached."""
    try:
        rec = _zenodo_latest_record(EUREPOC_ZENODO_SEED)
        meta = _zenodo_release_meta(rec)
        key, url, size = _zenodo_pick_csv(rec)
        if not url:
            print("  [eurepoc] record %s has no recognised incident CSV "
                  "(looked for %s); falling back rather than guessing"
                  % (meta.get("record"), " or ".join(EUREPOC_FILE_PREFER)))
            return None
        meta["file"] = key
        r = requests.get(url, headers=UA, timeout=180)
        r.raise_for_status()
        EUREPOC_RELEASE.clear()
        EUREPOC_RELEASE.update(meta)
        print("  [eurepoc] release %s (record %s, %s) file %s, %.1f MB"
              % (meta.get("version") or "?", meta.get("record"),
                 meta.get("doi") or "no doi", key, len(r.content) / 1e6))
        if str(meta.get("record")) != str(EUREPOC_ZENODO_SEED):
            print("  [eurepoc] NOTE: newer than the pinned seed release - "
                  "the map is now built on %s" % (meta.get("version") or meta.get("record")))
        return r.content.decode("utf-8", "replace")
    except Exception as exc:                              # noqa: BLE001
        print("  [warn] eurepoc: could not resolve the latest Zenodo release (%s)" % exc)
        return None


@source(id="eurepoc", table="incidents", title="EuRepoC Global Dataset",
        licence="See Zenodo record terms", cadence="on release",
        homepage="https://eurepoc.eu/", expected=4300)
def build_eurepoc():
    # Newest release first; the pinned URLs remain as a fallback so a Zenodo
    # outage degrades to the previous behaviour rather than losing the source.
    text = eurepoc_release_csv()
    if text is None:
        print("  [eurepoc] falling back to the pinned release URLs")
        text = get_first(EUREPOC_URLS, "EuRepoC").content.decode("utf-8", "replace")
    rows = list(csv.DictReader(io.StringIO(text)))
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
            imp = _eurepoc_impact(row)   # same coded fields as the TableView export, if present
            if imp:
                s["imp"] = imp
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
                    # kept separately so the gap between the two can be measured
                    "discovered": (v.get("discovered") or "")[:10],
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
            # CISA added weakness identifiers to the catalogue; carrying them lets the
            # app group exploited flaws by the underlying weakness rather than only by
            # vendor, which is where the recurring themes actually show up.
            "cwes": [str(c)[:12] for c in (v.get("cwes") or [])][:4],
            "due": (v.get("dueDate") or "")[:10],
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
            # Government advisories MITRE itself cites for this group. This is a
            # better link than any text matching of my own: the attribution is
            # MITRE's, and it arrives with the bundle we are already downloading -
            # which matters because cisa.gov refuses automated requests to its
            # dynamic pages (HTTP 403 from a datacentre address), while this
            # bundle is published precisely to be consumed programmatically.
            # Two independent routes, because I cannot see the raw bundle from here
            # and should not bet the whole feature on one URL shape:
            #   1. external_references whose URL contains an advisory identifier -
            #      works whatever the host path looks like, including the older
            #      us-cert.cisa.gov/ncas/alerts/ form.
            #   2. the citation markers MITRE writes into its prose, e.g.
            #      "(Citation: CISA AA20-239A BeagleBoyz August 2020)" - which is
            #      visible in the published data and needs no URL at all.
            advs, seen_adv = [], set()

            def _add_adv(aid, url, title):
                aid = (aid or "").lower()
                if not aid or aid in seen_adv:
                    return
                seen_adv.add(aid)
                advs.append({"id": aid,
                             "url": (url or
                                     "https://www.cisa.gov/news-events/"
                                     "cybersecurity-advisories/" + aid)[:300],
                             "title": (title or "").strip()[:220]})

            for r2 in o.get("external_references", []):
                u2 = str(r2.get("url") or "")
                sn = str(r2.get("source_name") or "")
                title = str(r2.get("description") or sn or "")
                m2 = re.search(r"(?<![a-z0-9])(a{1,2}\d{2}-\d{3}[a-z]?)(?![a-z0-9])", u2, re.I)
                if m2 and "cisa" in u2.lower():
                    _add_adv(m2.group(1), u2, title)
                    continue
                # a citation named for an advisory, even if the link has moved
                m3 = re.search(r"CISA\s+(a{1,2}\d{2}-\d{3}[a-z]?)", sn, re.I)
                if m3:
                    _add_adv(m3.group(1), u2 if "cisa" in u2.lower() else "", sn)

            # and the prose, scanned in full rather than the truncated first sentence
            full_desc = str(o.get("description") or "")
            for m4 in re.finditer(r"Citation:\s*CISA\s+(a{1,2}\d{2}-\d{3}[a-z]?)([^)]{0,80})",
                                  full_desc, re.I):
                _add_adv(m4.group(1), "", "CISA " + m4.group(1).upper()
                         + " " + m4.group(2).strip())
            groups.append({
                "id": ref.get("external_id", ""),
                "name": (o.get("name") or "")[:80],
                "aliases": (o.get("aliases") or [])[:8],
                "desc": desc[:220],
                "url": ref.get("url", ""),
                "advisories": advs[:12],
            })
    adv_groups = sum(1 for g in groups if g.get("advisories"))
    adv_total = len({a["id"] for g in groups for a in (g.get("advisories") or [])})
    print("  [attack] %d techniques, %d groups; %d groups cite %d distinct CISA "
          "advisories" % (len(techniques), len(groups), adv_groups, adv_total))
    if not adv_total:
        print("  [attack] NOTE: no CISA advisory citations found. The advisory "
              "enrichment will be empty - paste a group's external_references to fix "
              "the pattern.")
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


def _manual_rows(kind="cissm", allow_any=False):
    """Read an export the user downloaded from a portal and committed to the repo.

    Files are matched by name first (anything containing `kind`), so several manual
    sources can coexist. `allow_any` keeps the older behaviour of accepting an
    unnamed export, used only by CISSM for backwards compatibility.
    """
    pool = []
    for d in (MANUAL_DIR, Path(".")):
        if d.exists():
            pool += [p for p in d.iterdir()
                     if p.suffix.lower() in (".csv", ".json") and p.is_file()]
    named = [p for p in pool if kind in p.name.lower()]
    # never let another source's clearly-named export be claimed by this one
    # "impact" guards the curated overlay files: they live in the repo root as plain
    # .csv, and without this an unnamed-CISSM fallback could swallow them and emit
    # nonsense incidents.
    others = {"cissm", "eurepoc", "impact"} - {kind}
    generic = [p for p in pool
               if not any(o in p.name.lower() for o in others)
               and kind not in p.name.lower()]
    cands = sorted(named, key=lambda p: p.stat().st_size, reverse=True)
    if allow_any:
        cands += sorted(generic, key=lambda p: p.stat().st_size, reverse=True)
    for path in cands:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:                                  # noqa: BLE001
            print("  [%s] cannot read %s (%s)" % (kind, path.name, str(exc)[:60]))
            continue
        rows = []
        if path.suffix.lower() == ".json":
            try:
                rows = _cissm_rows_from_json(json.loads(text))
            except Exception as exc:                              # noqa: BLE001
                print("  [%s] %s is not valid JSON (%s)" % (kind, path.name, str(exc)[:60]))
                continue
        else:
            rows = list(csv.DictReader(io.StringIO(text)))
        if rows and isinstance(rows[0], dict):
            print("  [%s] using manual export %s (%d rows, %.1f MB)"
                  % (kind, path.name, len(rows), path.stat().st_size / 1e6))
            return rows
        print("  [%s] %s contained no usable rows" % (kind, path.name))
    return None


# ===========================================================================
# EuRepoC TableView export (MANUAL, PROVISIONAL)
# ---------------------------------------------------------------------------
# The static Zenodo release is fully expert-reviewed but stops at 31.12.2024.
# EuRepoC's TableView offers the current working data, which they describe as
# NOT fully expert-reviewed. Downloading it is a browser action, so it cannot be
# automated here.
#
#   1. Open https://eurepoc.eu/table-view/ on a desktop browser
#   2. Use the download button to export the table
#   3. Commit the file with "eurepoc" in its name, e.g.
#          manual_sources/eurepoc_tableview_2026-07.csv
#
# Only incidents AFTER the static release's coverage end are kept, so the two
# layers cannot double-count. Everything from here is flagged provisional and is
# labelled as such in the application.
#
# LICENCE: EuRepoC is CC BY-NC 4.0 (non-commercial) as of 2 April 2025. Check
# before redistributing these records.
# ===========================================================================
EUREPOC_STATIC_END = "2024-12-31"


@source(id="eurepoc_live", table="incidents",
        title="EuRepoC TableView export (provisional, not fully expert-reviewed)",
        licence="CC BY-NC 4.0 - non-commercial use only",
        cadence="manual export", expected=0,
        homepage="https://eurepoc.eu/table-view/")

def build_eurepoc_live():
    rows = _manual_rows("eurepoc")
    if rows is None:
        raise RuntimeError(
            "no EuRepoC TableView export found. The static release covers only to "
            "%s; to fill the period since, export from https://eurepoc.eu/table-view/ "
            "and commit the file with 'eurepoc' in its name" % EUREPOC_STATIC_END)
    header = list(rows[0].keys())
    print("  [eurepoc_live] fields: %s" % (header[:12],))
    find = col_finder(header)
    c_date = find("start date", "incident start", "start", "date")
    if not c_date:
        raise RuntimeError("could not identify a start-date column in the export")
    cutoff = EUREPOC_STATIC_END
    out, skipped = [], 0
    for row in rows:
        d = str(row.get(c_date) or "").strip()
        m = (re.search(r"(20\d{2})-(\d{1,2})-(\d{1,2})", d)
             or re.search(r"(\d{1,2})[/.](\d{1,2})[/.](20\d{2})", d))
        if not m:
            continue
        if len(m.group(1)) == 4:
            iso = "%s-%02d-%02d" % (m.group(1), int(m.group(2)), int(m.group(3)))
        else:
            iso = "%s-%02d-%02d" % (m.group(3), int(m.group(2)), int(m.group(1)))
        if iso <= cutoff:
            skipped += 1
            continue                       # the static release already covers this
        # Keep the same columns as the static release rather than all 84, so the
        # published pack stays small and the two EuRepoC layers look alike.
        pats = [re.compile(p, re.I) for p in EUREPOC_KEEP]
        slim = {}
        for k, v in row.items():
            if not k:
                continue
            val = str(v or "").strip()
            if not val:
                continue
            if any(p.search(k) for p in pats):
                slim[k] = val[:600 if LONG_TEXT.search(k) else 200]
        slim[c_date] = iso
        slim["_provisional"] = "1"
        # EuRepoC marks each record "Open" (still being coded) or "Coding finished".
        # That distinction matters: an open record is a working draft.
        st = ""
        for k, v in row.items():
            if k and k.strip().lower() == "status":
                st = str(v or "").strip()
                break
        if st:
            slim["_status"] = st[:40]
        imp = _eurepoc_impact(row)
        if imp:
            slim["imp"] = imp          # EuRepoC-coded impact dimensions for the impact chart
        out.append(slim)
    finished = sum(1 for r in out if str(r.get("_status", "")).lower().startswith("coding finished"))
    print("  [eurepoc_live] %d rows -> %d after %s (%d already in the static release)"
          % (len(rows), len(out), cutoff, skipped))
    print("  [eurepoc_live] coding status: %d finished, %d still open"
          % (finished, len(out) - finished))
    if not out:
        raise RuntimeError(
            "export contained no incidents after %s - it may be an older extract" % cutoff)
    return out


def _cissm_manual_rows():
    """Read an export the user downloaded from the portal's Analytics dashboard.

    Accepts any .csv or .json dropped in manual_sources/ - the portal names its
    exports with a timestamp, so requiring an exact filename just creates a
    needless step. The newest usable file wins.
    """
    return _manual_rows("cissm", allow_any=True)


@source(id="cissm", table="incidents",
        title="CISSM / GoTech Cyber Events Database",
        licence="Access granted by CISSM on request - do not redistribute raw records",
        cadence="manual export", homepage="https://cybereventsdatabase.org", expected=17169)
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
# Without a key NVD allows about 5 requests per 30 seconds, so the backfill has to be
# spread over several nightly runs. A free NVD_API_KEY raises that to roughly 50 per
# 30 seconds, which is fast enough to finish the whole history in one run - so the
# per-run cap lifts automatically when a key is present. Without that, adding the key
# would speed each request up but still stop after 40 months, which defeats the point.
CVE_MAX_FETCH_PER_RUN_NOKEY = 40
CVE_MAX_FETCH_PER_RUN_KEYED = 400
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
    cap = CVE_MAX_FETCH_PER_RUN_KEYED if key else CVE_MAX_FETCH_PER_RUN_NOKEY
    print("  [cve] %s (delay %.1fs, up to %d months this run)"
          % ("API key in use" if key else "no API key - slow mode", delay, cap))

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
        if fetched >= cap:
            print("  [cve] per-run fetch cap (%d) reached; remaining history will fill "
                  "in on later runs%s" % (cap,
                  "" if key else ". Add a free NVD_API_KEY secret to finish in one run"))
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


# ── Curated impact overlay ──────────────────────────────────────────────────
# Two human-maintained CSVs in the repo, normalised so figures can be appended
# without re-editing existing rows:
#   impact_overlay.csv   one row per incident  (identity, description, status)
#   impact_figures.csv   one row per FIGURE    (incident_id, dimension, value,
#                                               unit, source_url, as_of, note)
# The builder never writes to either file - they are the human's record. It only
# validates and joins them. A figure with no source URL is REJECTED rather than
# published, which enforces the "verified primary source" rule mechanically
# instead of relying on memory.
IMPACT_DIM_RANGE = {
    "intensity": (0, 8), "disruption": (0, 4), "data": (0, 3), "novelty": (0, 3),
    "financial": (0, 1e13), "people": (0, 1e10),
}
IMPACT_WARNINGS = []


def _impact_read(namepart):
    """Read one overlay CSV by name fragment from manual_sources/ or the repo root."""
    for d in (MANUAL_DIR, Path(".")):
        if not d.exists():
            continue
        for p in sorted(d.iterdir()):
            if p.is_file() and p.suffix.lower() == ".csv" and namepart in p.name.lower():
                text = p.read_text(encoding="utf-8-sig", errors="replace")  # tolerate a BOM
                rows = list(csv.DictReader(io.StringIO(text)))
                clean = []
                for r in rows:
                    clean.append({(k or "").strip().lower(): (v or "").strip()
                                  for k, v in r.items() if k})
                print("  [impact] %s: %d rows" % (p.name, len(clean)))
                return clean
    return []


@source(id="impact_overlay", table="impact",
        title="Curated impact overlay (human-maintained, per-figure sources)",
        licence="Compiled from cited primary sources; figures are estimates where noted",
        cadence="manual", homepage="", expected=0)
def build_impact_overlay():
    IMPACT_WARNINGS.clear()
    incidents = _impact_read("impact_overlay")
    figures = _impact_read("impact_figures")
    if not incidents:
        IMPACT_WARNINGS.append("no impact_overlay.csv found - the curated layer is empty")
        return []

    out, seen = {}, set()
    for r in incidents:
        iid = r.get("id", "")
        if not iid:
            IMPACT_WARNINGS.append("skipped an incident row with no id")
            continue
        if iid in seen:
            IMPACT_WARNINGS.append("duplicate incident id %r - later row ignored" % iid)
            continue
        seen.add(iid)
        try:
            year, month = int(r.get("year") or 0), int(r.get("month") or 1)
        except ValueError:
            IMPACT_WARNINGS.append("%s: unreadable year/month - skipped" % iid)
            continue
        if not (2000 <= year <= 2100) or not (1 <= month <= 12):
            IMPACT_WARNINGS.append("%s: year/month out of range - skipped" % iid)
            continue
        out[iid] = {
            "id": iid, "name": r.get("name") or iid, "year": year, "month": month,
            "victim_country": r.get("victim_country", ""), "sector": r.get("sector", ""),
            "type": r.get("type", ""), "severity": r.get("severity") or "High",
            "summary": r.get("summary", "")[:900],
            "source_name": r.get("source_name", ""), "source_url": r.get("source_url", ""),
            "notable": (r.get("notable", "").lower() in ("y", "yes", "true", "1")),
            "review_status": (r.get("review_status") or "verified").lower(),
            "last_checked": r.get("last_checked", ""),
            "imp": {}, "figures": {},
        }

    kept = dropped = 0
    for f in figures:
        iid, dim = f.get("incident_id", ""), (f.get("dimension") or "").lower()
        if iid not in out:
            IMPACT_WARNINGS.append("figure for unknown incident %r - ignored" % iid)
            dropped += 1
            continue
        if dim not in IMPACT_DIM_RANGE:
            IMPACT_WARNINGS.append("%s: unknown dimension %r - ignored" % (iid, dim))
            dropped += 1
            continue
        url = f.get("source_url", "")
        if not url.startswith("http"):
            # The rule that matters: no source, no figure.
            IMPACT_WARNINGS.append("%s/%s: no source URL - figure REJECTED" % (iid, dim))
            dropped += 1
            continue
        raw = (f.get("value") or "").replace(",", "").replace("$", "")
        m = re.search(r"-?\d+(?:\.\d+)?", raw)
        if not m:
            IMPACT_WARNINGS.append("%s/%s: unreadable value %r - ignored" % (iid, dim, raw[:20]))
            dropped += 1
            continue
        val = float(m.group(0))
        lo, hi = IMPACT_DIM_RANGE[dim]
        if not (lo <= val <= hi):
            IMPACT_WARNINGS.append("%s/%s: %g outside %g..%g - ignored" % (iid, dim, val, lo, hi))
            dropped += 1
            continue
        out[iid]["imp"][dim] = int(val) if dim not in ("financial", "people") else val
        out[iid]["figures"][dim] = {
            "source_url": url, "as_of": f.get("as_of", ""),
            "confidence": f.get("confidence", ""), "note": f.get("note", "")[:200],
        }
        kept += 1

    rows = list(out.values())
    for r in rows:
        if r["notable"]:
            r["imp"]["notable"] = True
    nofig = [r["id"] for r in rows if not r["figures"]]
    for iid in nofig:
        IMPACT_WARNINGS.append("%s: no valid figures - it will plot only if scored elsewhere" % iid)
    print("  [impact] %d incidents, %d figures kept, %d rejected, %d warnings"
          % (len(rows), kept, dropped, len(IMPACT_WARNINGS)))
    for w in IMPACT_WARNINGS[:12]:
        print("  [impact] WARNING %s" % w)
    return rows


# ── NVD per-CVE detail for the exploited catalogue ──────────────────────────
# The CVE connector above counts how many vulnerabilities were published each
# month. This one fetches the DETAIL - severity, weakness, publication date -
# but only for the flaws that matter most: the ones CISA has recorded as
# actually exploited. That is about 1,600 records rather than a quarter of a
# million, which keeps the pack small enough to load in a browser and the run
# inside a sensible time budget.
#
# Why not the whole corpus: NVD holds ~250,000 CVEs. Even at 2,000 per request
# that is a large multi-hundred-megabyte artefact no browser should download,
# and almost all of it would never be looked at. Enriching the exploited set
# gives the analytical value at a thousandth of the size.
#
# The work is capped per run and cached, so the first few nights fill it in and
# later runs only fetch newly catalogued flaws.
NVD_DETAIL_MAX_PER_RUN_KEYED = 500
NVD_DETAIL_MAX_PER_RUN_NOKEY = 30
NVD_DETAIL_MAX_SECONDS = 900


def _nvd_parse_cve(item):
    """Pull the few fields worth carrying out of one NVD API record."""
    cve = item.get("cve") or {}
    if not isinstance(cve, dict):
        return {"cve": ""}
    out = {"cve": str(cve.get("id") or "")}
    # Coerce before slicing: a non-string here (seen only with malformed input, but
    # cheap to guard) would otherwise take the whole build down.
    pub = str(cve.get("published") or "")[:10]
    if pub:
        out["published"] = pub

    # CVSS: prefer v3.1, then v3.0, then v2 - and record which, because comparing
    # scores across versions is not strictly valid and the reader should know.
    metrics = cve.get("metrics") or {}
    for keyname, label in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                           ("cvssMetricV2", "2.0")):
        arr = metrics.get(keyname) or []
        if not arr:
            continue
        first = arr[0] if isinstance(arr[0], dict) else {}
        data = first.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        out["cvss"] = float(score)
        out["cvssVer"] = label
        sev = data.get("baseSeverity") or first.get("baseSeverity") or ""
        if sev:
            out["sev"] = str(sev).title()
        break

    cwes = []
    for w in (cve.get("weaknesses") or []):
        if not isinstance(w, dict):
            continue
        for d in (w.get("description") or []):
            if not isinstance(d, dict):
                continue
            v = str(d.get("value") or "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    if cwes:
        out["cwes"] = cwes[:4]

    refs = cve.get("references") or []
    if refs:
        out["refs"] = len(refs)
    for d in (cve.get("descriptions") or []):
        if not isinstance(d, dict):
            continue
        if (d.get("lang") or "") == "en":
            txt = " ".join(str(d.get("value") or "").split())
            if txt:
                # mark the cut so a truncated description does not read as a
                # sentence that simply stops mid-word
                out["desc"] = txt if len(txt) <= 320 else txt[:319].rstrip() + "\u2026"
            break
    return out


@source(id="nvdcve", table="vulns",
        title="NVD detail for exploited vulnerabilities",
        licence="NVD data - US Government work, public domain",
        cadence="daily", homepage="https://nvd.nist.gov/", expected=0)
def build_nvd_detail(out_dir=None):
    key = os.environ.get("NVD_API_KEY", "").strip()
    headers = dict(UA)
    if key:
        headers["apiKey"] = key
    delay = 0.8 if key else 6.5
    cap = NVD_DETAIL_MAX_PER_RUN_KEYED if key else NVD_DETAIL_MAX_PER_RUN_NOKEY

    # Which flaws to enrich: whatever is in the exploited catalogue right now.
    try:
        kev_json = get_first(KEV_URLS, "CISA KEV (for NVD enrichment)").json()
        wanted = [v.get("cveID", "") for v in kev_json.get("vulnerabilities", [])]
        wanted = [c for c in wanted if c.startswith("CVE-")]
    except Exception as exc:                                # noqa: BLE001
        print("  [nvd] could not read the exploited catalogue (%s) - skipping" % exc)
        return []
    if not wanted:
        return []

    cached = {}
    cache = (out_dir or Path("cyber_data")) / "vulns" / "nvd.json"
    if cache.exists():
        try:
            for rec in json.loads(cache.read_text(encoding="utf-8")):
                if rec.get("cve"):
                    cached[rec["cve"]] = rec
        except Exception:                                   # noqa: BLE001
            cached = {}

    # Fetch what we do not have, and retry anything that came back without a score
    # (NVD sometimes publishes a record before it has been analysed).
    todo = [c for c in wanted if c not in cached]
    todo += [c for c in wanted if c in cached and "cvss" not in cached[c]]
    print("  [nvd] %s; %d catalogued, %d cached, %d to fetch (cap %d this run)"
          % ("API key in use" if key else "no API key - slow mode",
             len(wanted), len(cached), len(todo), cap))

    fetched, throttled, failures, t0 = 0, 0, 0, time.time()
    for cve_id in todo:
        if fetched >= cap:
            print("  [nvd] per-run cap reached; the rest fills in on later runs")
            break
        if time.time() - t0 > NVD_DETAIL_MAX_SECONDS:
            print("  [nvd] time budget reached; stopping this run cleanly")
            break
        try:
            r = requests.get(NVD_API, params={"cveId": cve_id},
                             headers=headers, timeout=60)
            if r.status_code in (403, 429):
                throttled += 1
                if throttled >= 3:
                    print("  [nvd] repeatedly throttled - keeping what we have")
                    break
                print("  [nvd] throttled at %s; backing off 20s" % cve_id)
                time.sleep(20)
                r = requests.get(NVD_API, params={"cveId": cve_id},
                                 headers=headers, timeout=60)
            r.raise_for_status()
            items = r.json().get("vulnerabilities") or []
            if items:
                rec = _nvd_parse_cve(items[0])
                if rec.get("cve"):
                    cached[rec["cve"]] = rec
            fetched += 1
            if fetched % 50 == 0:
                print("  [nvd] %d fetched, %ds elapsed" % (fetched, int(time.time() - t0)))
            time.sleep(delay)
        except Exception as exc:                            # noqa: BLE001
            failures += 1
            print("  [warn] nvd %s failed (%s)" % (cve_id, exc))
            if failures >= 8:
                print("  [nvd] too many consecutive failures - stopping this run")
                break

    def _cve_key(c):
        # sort by year then number, so CVE-2025-9242 precedes CVE-2025-10035
        parts = c.split("-")
        try:
            return (int(parts[1]), int(parts[2]))
        except (IndexError, ValueError):
            return (0, 0)
    rows = [cached[c] for c in sorted(cached, key=_cve_key)]
    scored = sum(1 for r in rows if "cvss" in r)
    print("  [nvd] %d records held, %d with a CVSS score (%d fetched this run)"
          % (len(rows), scored, fetched))
    return rows


# ── CISA cybersecurity advisories (AA series) ──────────────────────────────
# This is deliberately NOT an incident source. A joint advisory does not tell you
# who was attacked; it tells you what a named actor does, which flaws they use,
# and which techniques to look for. So it enriches two things the app already
# holds - the ATT&CK groups and the exploited-vulnerability catalogue - rather
# than adding rows to the incident count. Nothing here reaches the review queue,
# which is why it was worth building first: it costs no human attention at all.
#
# What we extract per advisory: the AA identifier, title, date, URL, any CVEs
# referenced, any ATT&CK technique identifiers, and any threat-group names that
# match an alias already in the ATT&CK data. Group matching is deliberately
# conservative - see _aa_match_groups.
# Several candidates, because CISA has reorganised these paths before and a feed that
# 404s is indistinguishable from one that returns an empty list unless you look.
AA_FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.cisa.gov/news.xml",
    "https://www.cisa.gov/uscert/ncas/alerts.xml",
]
# Last resort: read the advisories index pages directly. The section URL and the
# /advisories/aaNN-NNNx link pattern have been stable for years, so scraping the
# index is more dependable than any single feed path.
AA_INDEX_PAGES = [
    "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94",
    "https://www.cisa.gov/news-events/cybersecurity-advisories",
]
AA_MAX_PAGES_PER_RUN = 60          # advisory pages fetched per build
AA_MAX_SECONDS = 240
AA_PAGE_DELAY = 0.4

_AA_ID = re.compile(r"\b(a{1,2}\d{2}-\d{3}[a-z]?)\b", re.I)
_AA_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_AA_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _aa_strip_html(html):
    """Crude but sufficient: we only need the text to search for identifiers."""
    txt = re.sub(r"(?is)<(script|style).*?</\1>", " ", html or "")
    txt = re.sub(r"(?s)<[^>]+>", " ", txt)
    txt = txt.replace("&amp;", "&").replace("&nbsp;", " ").replace("&#039;", "'")
    return re.sub(r"\s+", " ", txt)


def _aa_parse_feed(xml_text):
    """Pull items out of the advisory feed without an XML dependency.

    Returns a list of {id, title, url, date}. Only entries that look like an
    advisory identifier are kept, so ordinary news items are ignored.
    """
    out, seen = [], set()
    items = re.findall(r"(?is)<(?:item|entry)\b.*?</(?:item|entry)>", xml_text or "")
    for it in items:
        def tag(name):
            m = re.search(r"(?is)<%s[^>]*>(.*?)</%s>" % (name, name), it)
            if m:
                return m.group(1)
            m = re.search(r'(?is)<%s[^>]*href="([^"]+)"' % name, it)   # atom <link href=…>
            return m.group(1) if m else ""
        title = _aa_strip_html(tag("title")).strip()
        link = _aa_strip_html(tag("link")).strip()
        date = (_aa_strip_html(tag("pubDate")) or _aa_strip_html(tag("updated"))
                or _aa_strip_html(tag("published"))).strip()
        if not link:
            continue
        m = _AA_ID.search(link) or _AA_ID.search(title)
        if not m:
            continue                      # not an advisory
        aid = m.group(1).lower()
        if aid in seen:
            continue
        seen.add(aid)
        out.append({"id": aid, "title": title[:220], "url": link, "date": _aa_date(date)})
    return out


def _aa_date(raw):
    """Normalise whatever the feed gives us to YYYY-MM-DD, or empty."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if m:
        return m.group(0)
    MONTHS = {m: i for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun",
         "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
    m = re.search(r"(\d{1,2})\s+([A-Za-z]{3})[a-z]*\s+(\d{4})", raw)
    if m:
        mon = MONTHS.get(m.group(2).lower())
        if mon:
            return "%s-%02d-%02d" % (m.group(3), mon, int(m.group(1)))
    m = re.search(r"([A-Za-z]{3})[a-z]*\s+(\d{1,2}),\s*(\d{4})", raw)
    if m:
        mon = MONTHS.get(m.group(1).lower())
        if mon:
            return "%s-%02d-%02d" % (m.group(3), mon, int(m.group(2)))
    return ""


def _aa_match_groups(text, group_index):
    """Which known ATT&CK groups does this advisory name?

    Conservative on purpose. Short or generic aliases ("Sandworm" is fine,
    "APT" or "TA" alone is not) produce false positives that would attach an
    advisory to the wrong actor, which is worse than attaching nothing. Only
    aliases of five characters or more are matched, and only on a word boundary.
    """
    hits, low = [], text.lower()
    for alias, gid in group_index.items():
        if len(alias) < 5:
            continue
        if re.search(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])", low):
            if gid not in hits:
                hits.append(gid)
    return hits[:8]


def _aa_group_index(attack):
    """alias (lowercased) -> group id, from the ATT&CK data already fetched."""
    idx = {}
    for g in ((attack or {}).get("groups") or []):
        gid = g.get("id") or ""
        if not gid:
            continue
        for nm in [g.get("name") or ""] + list(g.get("aliases") or []):
            nm = (nm or "").strip().lower()
            if nm:
                idx.setdefault(nm, gid)
    return idx




def _aa_from_index(html, base="https://www.cisa.gov"):
    """Advisory links out of an index page, when no feed is usable.

    Looks only for the /cybersecurity-advisories/aaNN-NNNx URL shape, so ICS and
    medical advisories on the same page are ignored along with ordinary news.
    """
    out, seen = [], set()
    for m in re.finditer(r'href="([^"]*?/(a{1,2}\d{2}-\d{3}[a-z]?))"([^>]*)>(.{0,240}?)</a>',
                         html or "", re.I | re.S):
        href, aid, _attrs, label = m.group(1), m.group(2).lower(), m.group(3), m.group(4)
        if aid in seen:
            continue
        seen.add(aid)
        url = href if href.startswith("http") else base + href
        out.append({"id": aid, "title": _aa_strip_html(label).strip()[:220],
                    "url": url, "date": ""})
    return out


def _aa_listing():
    """Advisory list from whichever source works, with enough logging to tell which."""
    for u in AA_FEEDS:
        try:
            r = requests.get(u, headers=UA, timeout=60)
            ctype = (r.headers.get("content-type") or "").split(";")[0]
            body = r.content.decode("utf-8", "replace")
            items = _aa_parse_feed(body) if r.status_code == 200 else []
            print("  [cisaaa] feed %s -> HTTP %s, %s, %d bytes, %d advisories"
                  % (u, r.status_code, ctype or "no type", len(body), len(items)))
            if items:
                return items, u
            if r.status_code == 200 and len(body) < 400:
                print("  [cisaaa]   body starts: %s" % body[:160].replace("\n", " "))
        except Exception as exc:                          # noqa: BLE001
            print("  [cisaaa] feed %s -> error (%s)" % (u, exc))
    for u in AA_INDEX_PAGES:
        try:
            r = requests.get(u, headers=UA, timeout=60)
            body = r.text if r.status_code == 200 else ""
            items = _aa_from_index(body)
            print("  [cisaaa] index %s -> HTTP %s, %d bytes, %d advisory links"
                  % (u, r.status_code, len(body), len(items)))
            if items:
                return items, u
        except Exception as exc:                          # noqa: BLE001
            print("  [cisaaa] index %s -> error (%s)" % (u, exc))
    return [], None

@source(id="cisaaa", table="advisories",
        title="CISA cybersecurity advisories (AA series)",
        licence="US Government work - public domain",
        cadence="daily", homepage="https://www.cisa.gov/news-events/cybersecurity-advisories",
        expected=0)
def build_cisa_aa(out_dir=None):
    # The feed gives the list; the identifiers we want are in the page bodies, so
    # pages are fetched a bounded number at a time and cached between runs.
    # ── Where the list comes from ──────────────────────────────────────────
    # First choice is the ATT&CK bundle's own citations, because cisa.gov returns
    # 403 to automated requests for its feeds and index pages (its static files,
    # such as the KEV catalogue, are served from cache and do work). MITRE
    # publishes the bundle for programmatic use and attributes each advisory to a
    # group itself, so this is both the reliable route and the better-sourced one.
    listed, via = [], None
    attack_early = None
    apath0 = (out_dir or Path("cyber_data")) / "techniques" / "attack.json"
    if apath0.exists():
        try:
            attack_early = json.loads(apath0.read_text(encoding="utf-8"))
        except Exception:                                 # noqa: BLE001
            attack_early = None
    if attack_early:
        seen, byid = set(), {}
        for g in (attack_early.get("groups") or []):
            for a in (g.get("advisories") or []):
                aid = a.get("id") or ""
                if not aid:
                    continue
                rec = byid.setdefault(aid, {"id": aid, "url": a.get("url") or "",
                                            "title": a.get("title") or "", "date": "",
                                            "groups": [], "cves": [], "techniques": []})
                if g.get("id") and g["id"] not in rec["groups"]:
                    rec["groups"].append(g["id"])
                seen.add(aid)
        listed = list(byid.values())
        if listed:
            via = "MITRE ATT&CK citations (%d advisories, attributed by MITRE)" % len(listed)
            print("  [cisaaa] %s" % via)

    # Only if that produced nothing do we try CISA directly. Kept because the site
    # may become reachable again, and because it is the only route that yields the
    # CVE lists inside advisory bodies.
    if not listed:
        listed, via = _aa_listing()
        if not listed:
            print("  [cisaaa] no advisory list available: ATT&CK carried no CISA "
                  "citations and cisa.gov refused every request (see above)")
            return []
        print("  [cisaaa] using %s" % via)

    cached = {}
    cache = (out_dir or Path("cyber_data")) / "advisories" / "aa.json"
    if cache.exists():
        try:
            for rec in json.loads(cache.read_text(encoding="utf-8")):
                if rec.get("id"):
                    cached[rec["id"]] = rec
        except Exception:                                 # noqa: BLE001
            cached = {}

    # Group aliases come from the ATT&CK file this build has already written (or the
    # previous build left behind). Deliberately NOT by calling build_attack() again:
    # the @source decorator returns the original function, so that would re-download
    # the whole ATT&CK bundle for nothing. If the file is not there yet, group
    # matching simply waits for the next run.
    attack = None
    apath = (out_dir or Path("cyber_data")) / "techniques" / "attack.json"
    if apath.exists():
        try:
            attack = json.loads(apath.read_text(encoding="utf-8"))
        except Exception:                                 # noqa: BLE001
            attack = None
    gidx = _aa_group_index(attack) if attack else {}
    if not gidx:
        print("  [cisaaa] no ATT&CK groups available yet - advisory group matching "
              "will fill in on the next run")

    todo = [a for a in listed if a["id"] not in cached or not cached[a["id"]].get("scanned")]
    print("  [cisaaa] %d advisories listed, %d cached, %d to read (cap %d)"
          % (len(listed), len(cached), len(todo), AA_MAX_PAGES_PER_RUN))

    fetched, blocked, t0 = 0, 0, time.time()
    for a in todo:
        if fetched >= AA_MAX_PAGES_PER_RUN:
            print("  [cisaaa] per-run cap reached; the rest fills in on later runs")
            break
        if time.time() - t0 > AA_MAX_SECONDS:
            print("  [cisaaa] time budget reached; stopping cleanly")
            break
        rec = dict(cached.get(a["id"]) or {})
        rec.update({k: a[k] for k in ("id", "title", "url", "date") if a.get(k)})
        for k in ("groups", "cves", "techniques"):        # keep what the listing gave
            if a.get(k) and not rec.get(k):
                rec[k] = a[k]
        try:
            pr = requests.get(a["url"], headers=UA, timeout=45)
            pr.raise_for_status()
            text = _aa_strip_html(pr.text)
            if not rec.get("date"):
                dm = re.search(r"(?:Release Date|Last Revised)[:\s]*([A-Za-z]+ \d{1,2},\s*\d{4})",
                               text, re.I)
                if dm:
                    rec["date"] = _aa_date(dm.group(1))
            cves = sorted({c.upper() for c in _AA_CVE.findall(text)})
            techs = sorted({t for t in _AA_TECH.findall(text)})
            rec["cves"] = cves[:60]
            rec["techniques"] = techs[:40]
            if gidx:
                rec["groups"] = _aa_match_groups(text, gidx)
            rec["scanned"] = True
            fetched += 1
            time.sleep(AA_PAGE_DELAY)
        except Exception as exc:                          # noqa: BLE001
            # Expected while cisa.gov blocks us. The advisory is still recorded with
            # its identifier, title, link and MITRE attribution; only the CVE list
            # inside the page body is missing, and the record says so.
            if blocked < 3:
                print("  [cisaaa] page not readable for %s (%s) - keeping the "
                      "citation without its CVE list" % (a["id"], str(exc)[:60]))
            blocked += 1
            rec.setdefault("cves", [])
            rec.setdefault("techniques", [])
            rec["body"] = False
        cached[rec["id"]] = rec

    rows = sorted(cached.values(), key=lambda r: (r.get("date") or "", r.get("id") or ""),
                  reverse=True)
    withcve = sum(1 for r in rows if r.get("cves"))
    withgrp = sum(1 for r in rows if r.get("groups"))
    print("  [cisaaa] %d advisories held; %d reference CVEs, %d attributed to a group "
          "(%d pages read, %d unreadable this run)"
          % (len(rows), withcve, withgrp, fetched, blocked))
    if blocked and not withcve:
        print("  [cisaaa] note: advisory bodies are unreachable, so CVE links are "
              "absent. Group attribution and links out are unaffected.")
    return rows


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
    if data is None:
        return 0
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
    try:
        return len(data)
    except TypeError:
        return 0


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
            # A connector must return usable data or raise. Returning None used to be
            # stored anyway, which wrote a null table and then crashed the whole build
            # several steps later - a long way from the actual fault.
            if data is None:
                raise RuntimeError("connector returned no data (None) instead of raising")
            if hasattr(data, "__len__") and len(data) == 0:
                raise RuntimeError("connector returned an empty result")
            results[src.id] = data
            entry = {"id": src.id, "title": src.title, "table": src.table,
                     "licence": src.licence, "homepage": src.homepage,
                     "cadence": src.cadence, "status": "ok",
                     "expected": src.expected, "rows": count_rows(data),
                     "seconds": round(time.time() - t0, 1)}
            # Surface the overlay's validation notes so a bad hand edit is visible in
            # the manifest the next morning, rather than silently plotting a wrong dot.
            if src.id == "impact_overlay" and IMPACT_WARNINGS:
                entry["warnings"] = IMPACT_WARNINGS[:40]
                entry["status"] = "ok with %d warning(s)" % len(IMPACT_WARNINGS)
            entries.append(entry)
        except Exception as exc:                       # noqa: BLE001
            print("[error] %s failed: %s - previous output left in place" % (src.id, exc))
            entries.append({"id": src.id, "title": src.title, "table": src.table,
                            "licence": src.licence, "homepage": src.homepage,
                            "expected": src.expected,
                            "status": "failed: %s" % str(exc)[:300], "rows": 0})

    tables = {}

    # ---- incidents (partitioned) ----
    inc_files, inc_counts = {}, {}
    if results.get("eurepoc"):
        write_json(out_dir / "incidents" / "eurepoc.json", results["eurepoc"])
        inc_files["eurepoc"] = "incidents/eurepoc.json"
        inc_counts["eurepoc"] = len(results["eurepoc"])
    if results.get("vcdb"):
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
    if results.get("rwlive"):
        write_json(out_dir / "incidents" / "rwlive.json", results["rwlive"])
        inc_files["rwlive"] = "incidents/rwlive.json"
        inc_counts["rwlive"] = sum(len(v) for v in results["rwlive"].values())
    if results.get("cissm"):
        write_json(out_dir / "incidents" / "cissm.json", results["cissm"])
        inc_files["cissm"] = "incidents/cissm.json"
        inc_counts["cissm"] = len(results["cissm"])
    if results.get("eurepoc_live"):
        write_json(out_dir / "incidents" / "eurepoc_live.json", results["eurepoc_live"])
        inc_files["eurepoc_live"] = "incidents/eurepoc_live.json"
        inc_counts["eurepoc_live"] = len(results["eurepoc_live"])
    if inc_files:
        tables["incidents"] = {"files": inc_files, "counts": inc_counts,
                               "total": sum(inc_counts.values())}

    # ---- vulns ----
    vulns = {}
    if results.get("kev"):
        write_json(out_dir / "vulns" / "kev.json", results["kev"])
        vulns["kev"] = {"file": "vulns/kev.json", "rows": len(results["kev"])}
    if results.get("epss"):
        write_json(out_dir / "vulns" / "epss.json", results["epss"])
        vulns["epss"] = {"file": "vulns/epss.json",
                         "rows": len(results["epss"]["rows"]), "min_score": EPSS_MIN}
    if results.get("cve"):
        write_json(out_dir / "vulns" / "cve.json", results["cve"])
        vulns["cve"] = {"file": "vulns/cve.json",
                        "months": len(results["cve"]["months"])}
    if vulns:
        tables["vulns"] = {"files": vulns}

    # ---- advisories ----
    if results.get("icsadv"):
        write_json(out_dir / "advisories" / "ics.json", results["icsadv"])
        tables["advisories"] = {"files": {"ics": {"file": "advisories/ics.json",
                                                  "rows": len(results["icsadv"])}}}

    # ---- techniques ----
    if results.get("attack"):
        a = results["attack"]
        write_json(out_dir / "techniques" / "attack.json", a)
        tables["techniques"] = {"files": {"attack": {
            "file": "techniques/attack.json",
            "techniques": len(a["techniques"]), "groups": len(a["groups"])}}}

    # ---- CISA advisories (enrichment, not incidents) ----
    if results.get("cisaaa"):
        aa = results["cisaaa"]
        write_json(out_dir / "advisories" / "aa.json", aa)
        tables.setdefault("advisories", {"files": {}})
        tables["advisories"]["files"]["aa"] = {
            "file": "advisories/aa.json",
            "rows": len(aa),
            "with_cves": sum(1 for r in aa if r.get("cves")),
            "with_groups": sum(1 for r in aa if r.get("groups")),
        }

    # ---- reports ----
    if results.get("reports"):
        write_json(out_dir / "reports" / "vendor.json", results["reports"])
        tables["reports"] = {"files": {"vendor": {"file": "reports/vendor.json",
                                                  "rows": len(results["reports"])}}}
    # ---- NVD detail for exploited flaws ----
    if results.get("nvdcve"):
        write_json(out_dir / "vulns" / "nvd.json", results["nvdcve"])
        scored = sum(1 for r in results["nvdcve"] if "cvss" in r)
        tables.setdefault("vulns", {"files": {}})
        tables["vulns"]["files"]["nvd"] = {"file": "vulns/nvd.json",
                                          "rows": len(results["nvdcve"]),
                                          "scored": scored}

    # ---- curated impact overlay ----
    if results.get("impact_overlay"):
        write_json(out_dir / "impact" / "overlay.json", results["impact_overlay"])
        figs = sum(len(r.get("figures") or {}) for r in results["impact_overlay"])
        tables["impact"] = {"files": {"impact_overlay": {"file": "impact/overlay.json",
                                                        "rows": len(results["impact_overlay"]),
                                                        "figures": figs}}}

    # A previous version could leave a table containing "null" behind. Remove any
    # such file so the app is never asked to parse it.
    for stale in (out_dir / "incidents").glob("*.json") if (out_dir / "incidents").exists() else []:
        try:
            if stale.read_text(encoding="utf-8").strip() in ("null", "", "{}"):
                print("  [tidy] removing empty table %s" % stale.name)
                stale.unlink()
        except Exception:                                  # noqa: BLE001
            pass

    manifest = {
        "schema": SCHEMA_VERSION,
        "builder": BUILDER_VERSION,
        "builder_date": BUILDER_DATE,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tables": tables,
        "sources": entries,
    }
    # Which upstream release this build used, so a published chart can be cited
    # precisely and a stale pin is visible rather than silent.
    if EUREPOC_RELEASE:
        manifest["releases"] = {"eurepoc": dict(EUREPOC_RELEASE)}
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
