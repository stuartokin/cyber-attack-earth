#!/usr/bin/env python3
"""Checks the committed data pack: manifest parses, every source reports a status,
every file the manifest lists exists and parses, and the incident total adds up.

Run from tests/:  python3 test_pack.py [path/to/cyber_data]
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACK = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "cyber_data"
fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def files_in(entry):
    if isinstance(entry, dict):
        if "file" in entry:
            yield entry["file"]
        else:
            for v in entry.values():
                yield from files_in(v)


m = json.loads((PACK / "manifest.json").read_text(encoding="utf-8"))
check(m.get("schema") == 3, "manifest schema is 3")
check(bool(m.get("builder")), "manifest names a builder version (%s)" % m.get("builder"))
srcs = m.get("sources") or []
check(len(srcs) >= 15, "manifest lists %d sources" % len(srcs))
for s in srcs:
    check(bool(s.get("status")), "source %s reports a status (%s)" % (s.get("id"), str(s.get("status"))[:40]))

seen = 0
for group, t in (m.get("tables") or {}).items():
    for key, entry in (t.get("files") or {}).items():
        for f in files_in(entry):
            p = (ROOT / f) if f.startswith("manual_sources/") else (PACK / f)
            ok = p.exists()
            if ok and p.suffix == ".json":
                try:
                    json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    ok = False
            check(ok, "%s/%s -> %s exists and parses" % (group, key, f))
            seen += 1
check(seen >= 15, "manifest references %d files" % seen)
inc = (m.get("tables") or {}).get("incidents") or {}
check(inc.get("total") == sum((inc.get("counts") or {}).values()),
      "incident total equals the sum of its counts (%s)" % inc.get("total"))
for sid in ("eurepoc", "vcdb", "rwlive", "cissm"):
    check(sid in (inc.get("counts") or {}), "incident layer %s is listed" % sid)

print("\n%s: %d failure(s)" % ("PASS" if not fails else "FAIL", len(fails)))
sys.exit(1 if fails else 0)
