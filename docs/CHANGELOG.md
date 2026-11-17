# Changelog

Newest first. App versions are `APP_VERSION` in `index.html` (also shown in the in-app
changelog under Help); builder versions are `BUILDER_VERSION` in `build_cyber_data.py`
(full history at the top of that file).

## 2026-11-17 — builder 3.19.1: new CISSM export

- `manual_sources/cyber_events_2026-11-17.csv` replaces the July export: 17,753 events
  (+584), event dates to September 2026 (was June). All rows usable.
- New EuRepoC TableView export (`eurepoc_tableview_2026-11-17.csv`). This one covers
  all years (4,960 incidents); the builder keeps only those after 2024-12-31, which
  gives 1,321 provisional incidents (was 992), running to November 2026. 533 have
  finished coding, 788 are still open. Both hand exports are now current.

## 2026-11-17 — app v94, builder 3.19.0: review fixes and new data cadence

Backup before this release: branch `backup/2026-11-17-pre-review-fixes` (the proxy
refused a tag, so it is a branch). To undo, reset `main` to it.

**Data honesty**
- The status chip no longer says "Data OK" while the CISSM and EuRepoC TableView exports
  are past their 40-day limit; it turns amber and says how old they are.
- A timeline note ("Claims only after Jul 2026") marks the months where only ransomware
  leak-site claims are recorded.
- A source that fails overnight keeps showing its last good data ("showing earlier
  data") instead of vanishing from the map. Shrink guard holds back any result under
  90% of the previous run and raises a `data-guard` issue.

**Fixes**
- EuRepoC: real sectors (health, finance, telecoms…) and techniques; previously one
  filter option was raw list text and every incident said "Not categorised".
  Intensity scores now read (≈4,200 rows). The 1.3 release's economic value is
  deliberately not read: it has no stated unit.
- The Zenodo EuRepoC release no longer borrows the TableView export's "refresh due" label.
- Start-up: country centroids cached (was ~3.7 s of work); phones no longer download
  the ATT&CK and KEV files from a CDN when the data pack already has them.
- Libraries and textures self-hosted in `vendor/`; startup check uses our own manifest,
  not the CDN.
- "Lighter settings" now only for two-core / 2 GB devices, and its notice sits above
  the timeline rather than over Play.
- Folded Fold: tool bar stays on one row; windows are pushed below it if it grows.
- Details → Regional coverage fills in. Welcome screen is `inert` once closed.
  Missing labels added. `prefers-reduced-motion` respected.
- SEC review file keeps earlier rows and their decisions, and links to the readable
  filing page. ICS advisories use the newest 60 files. CISSM export matched by name;
  the estimates and review files can never be read as CISSM.

**Workflow**
- Nightly: fast sources, and ransomware claims for the last three months plus the
  current month (it used to skip the current month and re-download 82 months).
- Weekly (Sunday): everything, with a full ransomware re-sweep.
- 45-minute timeout, one run at a time, pack checked before commit, rebase-and-retry push.
- New `tests.yml` runs the tests on every app or builder change.

**Tests (new)** — `tests/`: 11 builder unit checks, a data pack check, and a browser
smoke test on five screen sizes with every other site blocked (60 checks).

**Moved** — hand exports now in `manual_sources/` (they were in the repo root).
