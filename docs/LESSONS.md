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
11. **Anonymous GitHub API calls from Actions share a 60-an-hour limit.** The ICS listing
    was refused on the first 3.19.0 run (the shrink/carry logic kept its old data, as
    designed). Builder now sends the workflow's `GITHUB_TOKEN` to api.github.com.
12. **Ask the provider for their own sample code.** CISSM's API page documented a
    `getDataset` endpoint that was broken (503); Dr Harry's R example used the Base44
    entities route, which worked. Follow the provider's working example over their docs.
13. **Page through APIs in a fixed order and de-duplicate.** skip/limit paging without a
    sort can repeat or miss rows at page boundaries; sort (as the provider does) and drop
    repeats by id.
14. **Test a new API key from the session before relying on the nightly job.** A network
    secret on the session environment lets the proxy add the key without Claude seeing it;
    run the builder with a placeholder variable. It found the 503 and the working route in
    minutes, before GitHub was involved.
15. **When a hand export becomes an API, stop tracking the export's age.** Otherwise the
    old file's age is carried forward and raises "refresh due" for a file no longer used.
16. **Curated research: verify on the publisher's own page before showing Stuart.** Web
    search summaries contained an unsupported victim count, a government attribution and
    dates that the cited sources did not state; they were removed. Allow the publisher's
    host in the environment and read the page.
17. **The Play button is slow on the test machine's software renderer.** Tests must wait for
    a state change (up to 15 s), not sleep a fixed time.

