# Lessons

What went wrong or surprised us, so the next session does not repeat it. Newest first.

## 2026-11-17

1. **"Previous output left in place" is not the same as "still shown".** The builder kept
   a failed source's file on disk but rebuilt the manifest from this run's results only.
   The app loads only what the manifest lists, so the layer vanished. Any "keep the last
   good copy" rule must cover the index, not just the file. Now `carry_forward()`.
2. **Green lights can lie by omission.** Every source reported "ok" while two hand
   exports were four months old; the chip only checked failures and the pack's build
   date. Health checks must include the age of the *inputs*, not just the run.
3. **Upstream column names drift between releases.** EuRepoC's dyadic file has no
   `incident_type` (it uses one yes/no column per type), calls intensity
   `weighted_intensity` not `weighted_cyber_intensity`, and writes lists as Python
   text (`"['Health']"`). The app silently fell back to "Not categorised". The builder
   now normalises; `test_builder.py` pins it.
4. **Don't guess units.** EuRepoC 1.3's `economic_impact_value` holds values like 6 and
   20 with no stated unit. Left out rather than shown as dollars.
5. **Prefix matching is a trap.** `"eurepoc".startsWith("eurepoc")` made the
   automatically-fetched Zenodo release show the hand export's "refresh due". Map ids
   exactly.
6. **A "can we reach the internet" probe should test what you actually need.** The page
   checked a CDN file to decide whether to load the same-origin data pack.
7. **Unbounded retries hide in `continue`.** rwlive retried HTTP 429 for ever, and the
   job had no timeout (GitHub default 6 hours). Cap retries and set `timeout-minutes`.
8. **Sort what you commit.** ransomware.live returns rows in no fixed order; 28 of 31
   "changed" months nightly were reorderings. Sorting keeps git history small.
9. **Sandbox network:** this cloud session cannot reach most outside data sites unless
   the environment allows them (an environment called `cyber-attack-earth` now allows
   EuRepoC, Zenodo and CISSM). GitHub Actions runners have open internet, so the real
   refresh happens there. Pushing a git *tag* from the session was refused (403); a
   backup *branch* via the GitHub API worked.
10. **Don't get round access controls.** CISSM's dataset API and EuRepoC's API both need
    keys. Ask the providers; don't scrape their dashboards.
