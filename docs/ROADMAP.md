# Roadmap

Open work, decisions and questions. Update with every session.

## Done
- 2026-11-17 — Phase 1 (review fixes) and Phase 2 (scheduled workflow redesign). See
  CHANGELOG.

## Waiting on Stuart
1. **EuRepoC API token.** Ask EuRepoC for API access (their site: "contact us for special
   requirements (including API access)"). Their Python package (`eurepoc` on PyPI) uses a
   Bearer token against `strapi.eurepoc.eu/api/incidents`. With it, Claude adds a
   connector and the TableView download stops. Store as secret `EUREPOC_API_TOKEN`.
2. **CISSM API key** from Dr Charles Harry (expected since July 2026). Add as secret
   `CISSM_API_KEY`; the builder already supports it (`x-api-key` on
   `cybereventsdatabase.org/api/functions/api/getDataset` — the builder's Base44 path may
   need adjusting to this endpoint once a key exists).
3. **CISSM redistribution.** Confirm with Dr Harry that keeping the raw export in this
   public repo, and publishing description/url fields in the pack, is covered by the
   permission. ATTRIBUTION.md records it as an open question.
4. Until 1 and 2 arrive: refresh both exports monthly (MAINTENANCE §2a/2b). The current
   CISSM was refreshed on 2026-11-17 (to September 2026); EuRepoC TableView is still July 2026.

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
