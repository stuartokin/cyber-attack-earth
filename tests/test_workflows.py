#!/usr/bin/env python3
"""Checks the GitHub workflows keep the rules in CLAUDE.md:

- any workflow that runs on its own (schedule, issues, workflow_run...) starts with the
  kill-switch `switch` job reading this repo's and the master automation.json, and every
  other job waits for it
- every job has a timeout (the default is six hours)
- no secret values written into a workflow; secrets only via ${{ secrets.X }}
- the data workflow checks the pack before it commits
- automation.json exists and says paused true/false

Run from tests/:  python3 test_workflows.py   (needs PyYAML, present on GitHub runners)
"""
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WF = ROOT / ".github" / "workflows"
SELF_STARTING = {"schedule", "issues", "issue_comment", "workflow_run", "pull_request_target",
                 "repository_dispatch", "discussion"}
fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


auto = json.loads((ROOT / "automation.json").read_text(encoding="utf-8"))
check(auto.get("paused") in (True, False), "automation.json says paused true or false")

files = sorted(WF.glob("*.yml")) + sorted(WF.glob("*.yaml"))
check(len(files) >= 2, "workflows found (%d)" % len(files))
for f in files:
    text = f.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    on = doc.get(True) or doc.get("on") or {}          # YAML reads a bare `on:` as True
    triggers = set(on) if isinstance(on, dict) else set(on if isinstance(on, list) else [on])
    jobs = doc.get("jobs") or {}
    name = f.name
    if triggers & SELF_STARTING:
        check("switch" in jobs, "%s: runs on its own, so has a kill-switch job" % name)
        sw = json.dumps(jobs.get("switch", {}))
        check("stuartokin.github.io/main/automation.json" in sw and "automation.json" in sw,
              "%s: switch reads the master and this repo's automation.json" % name)
        for jn, j in jobs.items():
            if jn == "switch":
                continue
            needs = j.get("needs")
            needs = [needs] if isinstance(needs, str) else (needs or [])
            check("switch" in needs and "needs.switch.outputs.go" in str(j.get("if", "")),
                  "%s: job %s waits for the switch" % (name, jn))
    for jn, j in jobs.items():
        check(isinstance(j.get("timeout-minutes"), int), "%s: job %s has a timeout" % (name, jn))
    # nothing that looks like a literal key or token
    check(not re.search(r"(ghp_|github_pat_|sk-[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16})", text),
          "%s: no literal tokens" % name)
    for m in re.finditer(r"(?im)^\s*([A-Z_]*(KEY|TOKEN|SECRET|CONTACT)[A-Z_]*):\s*(.+)$", text):
        val = m.group(3).strip()
        check(val.startswith("${{"), "%s: %s comes from secrets, not a literal" % (name, m.group(1)))

data = (WF / "update-cyber-data.yml").read_text(encoding="utf-8")
check(data.index("tests/test_pack.py") < data.index("git commit"),
      "update-cyber-data.yml checks the pack before committing")
check("concurrency:" in data, "update-cyber-data.yml runs one at a time")

print("\n%s: %d failure(s)" % ("PASS" if not fails else "FAIL", len(fails)))
sys.exit(1 if fails else 0)
