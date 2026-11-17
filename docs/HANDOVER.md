# Handover — how Cyber Attack Earth works

For a new session or a new maintainer. Read with `MAINTENANCE.md` (the operating guide),
`docs/LESSONS.md`, `docs/ROADMAP.md` and the newest entry in `docs/CHANGELOG.md`.

State at the last update (2026-11-17): app **v94**, builder **3.19.3**, 17 sources all
"ok", 59,335 incident rows in the pack, both formerly-manual sources current.

## 1. What it is

A single static page on GitHub Pages: a globe (or flat map) of publicly documented cyber
incidents from 2000 to today, playable through time, with charts, a data-status panel and
honest caveats. Personal, non-commercial project by Stuart Okin.

## 2. The pieces

| Path | What it is | Who changes it |
|---|---|---|
| `index.html` | The whole app (≈9,500 lines, HTML+CSS+JS). `APP_VERSION` and the in-app `CHANGELOG` array live in it. | Claude |
| `vendor/` | Self-hosted globe.gl, d3, topojson-client, fflate, world atlas, Earth textures. No CDNs. | Claude (rarely) |
| `build_cyber_data.py` | Python builder. One `@source` connector per source; writes `cyber_data/`. Version history at the top. | Claude |
| `cyber_data/` | The data pack the app loads: `manifest.json` plus one JSON file per table. Never hand-edited. | The workflow |
| `impact_overlay.csv`, `impact_figures.csv` | Curated landmark incidents and their figures. | Stuart (Claude drafts) |
| `estimates.csv` | Published estimates of what is *not* recorded (ONS, DSIT, Cyber Monitoring Centre). Never summed. | Stuart (Claude drafts) |
| `manual_sources/` | EuRepoC TableView export (hand download) and the SEC review queue. | Stuart |
| `.github/workflows/update-cyber-data.yml` | Scheduled data build (nightly fast / weekly full / by hand). | Claude |
| `.github/workflows/tests.yml` | Runs the tests on every app, builder, test or curated-file change. | Claude |
| `tests/` | The test rig — see `tests/README.md`. | Claude |
| `automation.json` | This repo's kill switch. Master switch is in stuartokin.github.io. | Stuart |

## 3. Data flow

1. **The workflow** (`update-cyber-data.yml`) starts with the `switch` job (kill switches),
   then picks a cadence: nightly runs only fast sources via `ONLY_SOURCES`; weekly and
   manual runs do everything with `RWLIVE_FULL=1`.
2. **The builder** runs each connector. For each source it either writes fresh files, or —
   if the source failed, was held by the shrink guard (<90% of last time's rows), or was not
   scheduled — keeps the previous files *and* their manifest entry (`carry_forward`).
   Problems raise one `data-guard` issue; stale hand exports raise a `data-refresh` issue.
3. **The pack is checked** (`test_pack.py`, `test_curated.py`, `test_builder.py`) before the
   commit; the commit is rebased and retried if `main` moved.
4. **The app** reads `cyber_data/manifest.json`, loads every file it lists, maps rows to
   routes (country centroids cached by ISO code), de-duplicates across sources by date,
   country and a normalised victim name, and draws them.

## 4. Sources (17)

Incidents: EuRepoC Global Dataset (Zenodo, newest release auto-detected), EuRepoC TableView
(provisional, hand export), VCDB, CISSM (API key since 2026-11-17), Ransomware.live
(attacker claims — drawn hollow). Context, never counted: KEV, EPSS, CVE/NVD, MITRE ATT&CK,
ICS advisories, CISA advisories, HIBP, SEC 8-K review queue, curated reports, the impact
overlay, published estimates. Licences: `ATTRIBUTION.md`.

**CISSM:** Base44 entities endpoint for `CyberEvent`, `api_key` header, pages of 5,000
sorted `-event_date` (Dr Harry's sample R code). The documented `getDataset` endpoint
returned 503 on 2026-11-17 and is only a fallback. Secret: `CISSM_API_KEY`.

**EuRepoC:** the dyadic file has no `incident_type`; the builder rebuilds it from the
one-column-per-type flags, turns `"['Health']"` list text into `Health`, and reads
`weighted_intensity`. The 1.3 `economic_impact_value` is deliberately ignored (no unit).

## 5. Honesty rules the code enforces

- Counts are of *documented* incidents; the page says so.
- Status chip turns amber when any hand export is past 40 days, a source is showing
  earlier data, or a source returned too few rows. Tooltip says where verified coverage
  ends; the timeline shows "Claims only after <month>" past that point.
- Leak-site claims, provisional EuRepoC coding, and AI-free curated judgements are labelled.
- Estimates are never summed; every row needs a URL and a method.
- Curated rows stay `provisional` until Stuart has seen the figure on the publisher's page.

## 6. Environment notes (cloud sessions)

- The session's network only reaches hosts the environment allows. The `cyber-attack-earth`
  environment allows EuRepoC, Zenodo, CISSM/Base44 and the publishers used to check curated
  figures (ONS, GOV.UK, Cyber Monitoring Centre, CISA, NCA, CERT Polska, CSA Singapore,
  SEC, Microsoft, Google Cloud, Asahi, Coupang, NCSC). GitHub runners have open internet.
- A CISSM key is also saved as a network secret on that environment (for testing only);
  GitHub's `CISSM_API_KEY` secret is the one the build uses.
- Pushing git **tags** from a session was refused; make backups as **branches** via the
  GitHub API (`backup/YYYY-MM-DD-what`).
- Playwright and Chromium are preinstalled in sessions; the tests use them directly.

## 7. Releasing a change

1. Edit; bump `APP_VERSION` + in-app changelog (app) or `BUILDER_VERSION` + history (builder).
2. `cd tests && npm test` — everything must pass. Look at `npm run shots`.
3. Update `docs/CHANGELOG.md` (and LESSONS/ROADMAP as needed).
4. Commit and push to `main`; check the Tests workflow and, for builder changes, run the data
   workflow by hand and read its log.
