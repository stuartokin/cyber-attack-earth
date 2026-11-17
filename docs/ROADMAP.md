# Roadmap

Open work, decisions and questions. Update with every session.

## Done
- 2026-11-17 — Test rig extended: curated-file and workflow-rule checks, search / data
  status / Play / flat map in the browser test. `docs/HANDOVER.md`, `tests/README.md`,
  README written.
- 2026-11-17 — CISSM automatic via API; both hand exports refreshed; ONS/CMC estimates and
  six landmark incidents added (provisional).
- 2026-11-17 — Phase 1 (review fixes) and Phase 2 (scheduled workflow redesign). See
  CHANGELOG.

## Waiting on Stuart
1. **EuRepoC API token.** Ask EuRepoC for API access (their site: "contact us for special
   requirements (including API access)"). Their Python package (`eurepoc` on PyPI) uses a
   Bearer token against `strapi.eurepoc.eu/api/incidents`. With it, Claude adds a
   connector and the TableView download stops. Store as secret `EUREPOC_API_TOKEN`.
2. **CISSM API key** — done 2026-11-17. Secret set; first GitHub run fetched all 17,753
   events. Hand export removed from the repo. Tell Dr Harry: getDataset returns 503,
   and the entities route seemed to answer without checking the key.
3. **CISSM redistribution** — resolved by the API: no raw file in the repo now (it remains
   in git history from July–November 2026; say if Dr Harry wants that purged).
4. Until EuRepoC grants API access: refresh the TableView export monthly (MAINTENANCE
   §2b). Last refreshed 2026-11-17; due by 27 December 2026.

## Held back for checking (2026-11-17)
Drafted landmark incidents whose sources could not be opened here. Check each, then add
to `impact_overlay.csv` / `impact_figures.csv` (Stuart approved option "a": add only
confirmed ones).
- **Asahi ransomware (Sep 2025)** — https://www.asahigroup-holdings.com/newsroom/detail/20251127-0204.html (site refused automated access)
- **F5 source-code theft (Oct 2025)** — CISA Emergency Directive 26-01, https://www.cisa.gov/news-events/directives/ed-26-01-mitigate-vulnerabilities-f5-devices (site refused automated access)
- **Stryker (Mar 2026)** — needs the 8-K on SEC EDGAR instead of press coverage
Also: Singapore telecoms (added) has no scores, so it is not on the impact chart.

## Next (planned, not started)
- **Phase 3 — more history (2000–2009 is thin: ~540 incidents).** In order of value:
  MITRE ATT&CK campaigns (already downloaded; ~57 from 2009), US HHS OCR breach portal
  (2009+, public domain), US state AG breach lists, then CFR Cyber Operations Tracker
  (2005+) and the DCID dataset (2000–2020) — both need permission first. CSIS and
  Wikipedia lists as checklists for the curated overlay only.
- **Phase 4 — insights on the fly**, copying energy-resilience's pattern:
  - Deterministic, no AI: the nightly build writes factual sentences into the pack
    (what changed this week, top movers by country/sector/group, unusual spikes,
    coverage caveats).
  - Optional "Ask the analyst" panel: visitor's own Gemini key kept in their browser;
    grounded only on facts the app computed; never adds numbers or attribution; never
    in totals; every answer labelled unverified. No cost to Stuart, no Cloudflare step.

## Open questions for Stuart
- Mark the new estimates / incidents `verified` once you have read them on the publishers'
  pages (tell Claude which).
- Singapore telecoms has no scores, so is not on the impact chart — add a judgement?
- 15 incidents are labelled on the impact chart; the guide says about 7 fit. Keep or trim?
- SEC review queue: 54 candidates, none decided.
- Remove old CISSM exports from git history too? (only if Dr Harry asks)

## Smaller follow-ups
- Repo growth: the pack is still committed nightly (~27 MB of single-line JSON). Sorting
  fixed most churn; if it still grows fast, publish the pack via Pages artefact or an
  orphan `data` branch instead.
- Remove dead code paths in `index.html` (old flat-pack loader, remote EuRepoC/VCDB
  fallbacks).
- Three different totals on the welcome screen (documented incidents vs mapped routes vs
  manifest total) — explain or align.
- Small touch targets on window buttons (32×25).

## Decisions
- 2026-11-17 — Hand exports are not scraped; wait for official API keys.
- 2026-11-17 — Data cadence: fast sources nightly, everything weekly, full by hand.
- 2026-11-17 — No CDNs; libraries in `vendor/`.
