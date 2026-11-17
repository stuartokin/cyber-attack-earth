#!/usr/bin/env python3
"""Checks Stuart's hand-curated files before they reach the map.

- impact_overlay.csv: unique ids, valid years/months/severity, a source URL on every row
- impact_figures.csv: every figure points at a real incident, has a source URL, and is
  inside its dimension's range (the same ranges the builder enforces)
- estimates.csv: every row has a URL and a method; review_status is a known value
- manual_sources/sec_review.csv: the columns the builder writes, decisions only y/n/blank
- nothing personal (e-mail addresses) in any curated file - the repo is public

Run from tests/:  python3 test_curated.py
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fails = []


def check(cond, msg):
    if not cond:
        print("  FAIL " + msg)
        fails.append(msg)


def rows(name):
    with open(ROOT / name, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
RANGES = {"intensity": (0, 8), "disruption": (0, 4), "data": (0, 3), "novelty": (0, 3),
          "financial": (0, 1e13), "people": (0, 1e11)}

# ---- impact_overlay.csv ----
ov = rows("impact_overlay.csv")
ids = [r["id"] for r in ov]
check(len(ids) == len(set(ids)), "impact_overlay ids are unique")
for r in ov:
    i = r["id"]
    check(bool(re.fullmatch(r"[a-z0-9-]+", i)), "%s: id is a lowercase slug" % i)
    check(r["year"].isdigit() and 2000 <= int(r["year"]) <= 2100, "%s: year 2000+" % i)
    check(not r["month"] or (r["month"].isdigit() and 1 <= int(r["month"]) <= 12), "%s: month 1-12" % i)
    check(r["severity"] in ("Critical", "High", "Medium", "Low"), "%s: severity known" % i)
    check(r["source_url"].startswith("http"), "%s: has a source URL" % i)
    check(r["review_status"] in ("verified", "provisional", ""), "%s: review_status known" % i)
    check(len(r["summary"]) <= 900, "%s: summary under 900 characters" % i)
    check(r["notable"].lower() in ("y", "n", "yes", "no", ""), "%s: notable is y, n or blank" % i)
labels = sum(1 for r in ov if r["notable"].lower() in ("y", "yes"))
if labels > 7:   # advice, not a rule: MAINTENANCE says about 7 labels fit on the chart
    print("  note: %d incidents are labelled on the chart (about 7 fit comfortably)" % labels)
print("  impact_overlay: %d incidents" % len(ov))

# ---- impact_figures.csv ----
fg = rows("impact_figures.csv")
known = set(ids)
for r in fg:
    tag = "%s/%s" % (r["incident_id"], r["dimension"])
    check(r["incident_id"] in known, "%s: points at a known incident" % tag)
    check(r["dimension"] in RANGES, "%s: dimension known" % tag)
    check(r["source_url"].startswith("http"), "%s: has a source URL" % tag)
    try:
        v = float(str(r["value"]).replace(",", "").replace("$", ""))
        lo, hi = RANGES.get(r["dimension"], (0, 0))
        check(lo <= v <= hi, "%s: value %s inside %s-%s" % (tag, r["value"], lo, hi))
    except ValueError:
        check(False, "%s: value is a number" % tag)
    check(r["confidence"] in ("coded", "reported"), "%s: confidence coded/reported" % tag)
    check(not r["as_of"] or re.fullmatch(r"\d{4}-\d{2}", r["as_of"]), "%s: as_of is YYYY-MM" % tag)
print("  impact_figures: %d figures" % len(fg))

# ---- estimates.csv ----
es = rows("estimates.csv")
eids = [r["id"] for r in es]
check(len(eids) == len(set(eids)), "estimates ids are unique")
for r in es:
    check(r["url"].startswith("http"), "%s: has a URL" % r["id"])
    check(len(r["method"].strip()) > 10, "%s: states a method" % r["id"])
    check(r["review_status"] in ("verified", "provisional"), "%s: review_status known" % r["id"])
    check(bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", r["published"])), "%s: published is a date" % r["id"])
print("  estimates: %d published figures" % len(es))

# ---- SEC review queue ----
sec = ROOT / "manual_sources" / "sec_review.csv"
if sec.exists():
    sr = rows("manual_sources/sec_review.csv")
    with open(sec, encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    check(header == ["cik", "company", "filed", "item", "url", "review_status"],
          "sec_review.csv has the columns the builder writes")
    for r in sr:
        check(r["review_status"].strip().lower() in ("", "y", "n"),
              "sec %s %s: decision is y, n or blank" % (r["cik"], r["filed"]))
    print("  sec_review: %d candidates, %d decided" % (len(sr), sum(1 for r in sr if r["review_status"])))

# ---- nothing personal in curated files (public repo) ----
for name in ("impact_overlay.csv", "impact_figures.csv", "estimates.csv"):
    text = (ROOT / name).read_text(encoding="utf-8")
    check(not EMAIL.search(text), "%s contains no e-mail address" % name)

print("\n%s: %d failure(s)" % ("PASS" if not fails else "FAIL", len(fails)))
sys.exit(1 if fails else 0)
