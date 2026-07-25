# Cyber Attack Earth — maintenance guide

Everything here is done through the GitHub website. No terminal, no local Python.

- **Live site:** https://stuartokin.github.io/cyber-attack-earth/
- **App:** `index.html` (one self-contained file)
- **Builder:** `build_cyber_data.py` (runs nightly via GitHub Actions)
- **Data pack:** `cyber_data/` (written by the Action — never edit by hand)
- **Curated impact layer:** `impact_overlay.csv` + `impact_figures.csv` (yours to edit)

---

## 1. The five-minute weekly check

Open **`cyber_data/manifest.json`** and look at three things:

| Field | What you want to see |
|---|---|
| `"builder"` | The version you last deployed. If it is older, your upload did not take effect. |
| `"tables" → "incidents" → "total"` | Roughly the same as last week, or higher. A sharp drop means a source failed. |
| `"sources"` → each `"status"` | `"ok"` everywhere. Anything else is explained below. |

Then open the site and confirm the welcome screen shows the version you expect.

That is the whole routine when nothing is wrong.

---

## 2. The monthly pass (about 30 minutes)

### 2a. Refresh the CISSM export (~5 min)

CISSM has no open API, so the dataset arrives as a manual download.

1. Go to https://cybereventsdatabase.org and use **Download Dataset**.
2. Save as `.csv` or `.json` — **not** `.xlsx`, which the builder cannot read.
3. In GitHub, **Add file → Upload files**, drop it in the repo root, commit.
4. **Delete the previous CISSM export in the same commit.**

> **Why deleting matters:** when several unnamed exports are present the builder takes
> the **largest**, not the newest. Leaving an old file behind can silently pin you to
> stale data. Name the file with `cissm` in it and this ambiguity disappears entirely.

Filenames the builder understands:

- anything containing `cissm` → the CISSM export
- anything containing `eurepoc` → the EuRepoC TableView export
- anything containing `impact` → the curated overlay (never treated as incident data)

### 2b. Refresh the EuRepoC TableView export (~5 min)

The static EuRepoC release stops at **31 December 2024**. The TableView export is the
only source of EuRepoC incidents after that date, so it goes stale quickly.

1. Go to https://eurepoc.eu/table-view/ and export the table as CSV.
2. Upload it with `eurepoc` in the filename; delete the previous one.

> These rows are **provisional** — most are still coded "Open" and their scores can
> change on review. The app marks them as *Provisional coding* under **Provenance**,
> and the impact chart draws them hollow. That is deliberate: do not quote a
> provisional intensity score as settled.

### 2c. Review the impact queue (~10 min)

*(Available once the review-queue phase is built. Until then, skip to 2d.)*

The builder writes candidate impact figures it found but will not publish unaided.

1. Open `impact_review.csv` on GitHub — it renders as a table.
2. For each row with a blank `decision`, put `y` or `n`. Correct the `value` if you
   disagree with it.
3. Commit. Accepted rows are merged on the next build; rejected rows are never
   proposed again.

**Do not delete rows you have decided on** — the decision column is what stops the
builder re-proposing them.

### 2d. Sanity-check the curated overlay (~10 min)

Open `cyber_data/manifest.json`, find the `impact_overlay` source entry and read its
`warnings` array. Every rejected figure and skipped row is listed there with a reason.
Fix anything listed, or accept it deliberately.

Then spot-check one or two figures against their source URLs. Financial losses and
people-affected counts get revised upward for **years** — if a figure's `as_of` is more
than a year old and the incident is still in the news, it is probably out of date.

---

## 3. Editing the curated impact layer

Two files, deliberately normalised so you only ever **append** when you learn something
new, rather than re-editing rows that were already right.

### `impact_overlay.csv` — one row per incident

| Column | Notes |
|---|---|
| `id` | Stable slug, e.g. `notpetya-2017`. **Never change it** — the figures file points at it. |
| `name` | Display name. |
| `year`, `month` | Start of the incident. Year must be 2000 or later. |
| `victim_country` | Plain English country name. |
| `sector`, `type` | Anything; unknown values become their own filter option. |
| `severity` | `Critical` / `High` / `Medium` / `Low`. |
| `summary` | One or two sentences. Keep under ~900 characters. |
| `source_name`, `source_url` | The incident's main citation. |
| `notable` | `y` labels it on the chart. Use sparingly — about 7 labels fit. |
| `review_status` | `verified` once you have checked it against the source. |
| `last_checked` | `YYYY-MM-DD`. |
| `notes` | Free text, for you. |

### `impact_figures.csv` — one row per figure

| Column | Notes |
|---|---|
| `incident_id` | Must match an `id` above, or the row is rejected. |
| `dimension` | `intensity` (0–8), `disruption` (0–4), `data` (0–3), `novelty` (0–3), `financial` (USD), `people` (count). |
| `value` | Plain number. Commas and `$` are tolerated. |
| `unit` | Documentation only, e.g. `usd`, `count`, `scale-0-8`. |
| `source_url` | **Mandatory.** No URL, no figure — the builder rejects it. |
| `as_of` | `YYYY-MM`. When the figure was reported. |
| `confidence` | `coded` for a scored judgement, `reported` for a published number. |
| `note` | Shown under the figure in the app. Use it to hedge. |

**To add a figure:** append one line. Nothing else changes.

### What the builder rejects (and tells you about)

- A figure with no `source_url`, or one not starting with `http`
- A value outside its dimension's range
- An unknown `dimension`
- A figure pointing at an unknown `incident_id`
- Duplicate `id` values (the later row is ignored)
- A year outside 2000–2100

Rejections never break the build. They appear in the run log and in the manifest.

### Editing in Excel — read this first

Excel mangles CSVs. If you use it:

- Format the `as_of` and `last_checked` columns as **Text** before typing, or Excel
  will rewrite `2026-07` as a date.
- Save as **CSV UTF-8**.
- Avoid commas inside `summary` and `note` unless you are confident about quoting.

Editing directly in the GitHub web editor avoids all of this, and gives you a diff
before committing.

---

## 4. Deploying a new app or builder version

1. **Add file → Upload files**, drop the file in, commit.
2. Rename to exactly `index.html` (app) or `build_cyber_data.py` (builder). The Action
   looks for that exact builder filename.
3. For the app, load the site with a cache-buster: `...?v=2`, `?v=3`, and so on.
4. Confirm the welcome screen shows the new version number.

For the builder, wait for the nightly Action or trigger it from the **Actions** tab,
then check `"builder"` in the manifest matches what you uploaded.

**Repository settings that must stay as they are:**

- Settings → Actions → General → Workflow permissions → **Read and write**
- Settings → Secrets and variables → Actions → `NVD_API_KEY`, `CISSM_API_KEY`
- The workflow file lives at `.github/workflows/update-cyber-data.yml`

---

## 5. When a source fails

Find the source in `manifest.json` → `sources` and read its `status`.

| Status | What it means | What to do |
|---|---|---|
| `failed: HTTP 403` / `429` | Rate-limited or blocked | Usually transient. If it persists for days, the endpoint has probably changed. |
| `failed: missing 1 required positional argument` | A code fault, not a data fault | Report it. This pattern has bitten twice: a decorator separated from its function. |
| `failed: connector returned an empty result` | The fetch worked but parsed to nothing | The source's format has changed. |
| `skipped (no key)` | An API key is absent | Check the repository secret still exists. |
| `expected 17169, rows 0` for `cissm` | No usable export in the repo | Do step 2a. |
| `ok with N warning(s)` for `impact_overlay` | Build fine, some rows rejected | Read the `warnings` array. |

A failing source **does not** wipe its previous output — the last good file stays in
place, so the site keeps working on slightly older data.

---

## 6. Licence obligations — and one open question

| Source | Terms | What that requires of you |
|---|---|---|
| EuRepoC | CC BY-NC 4.0 | Attribution, **non-commercial use only**. A personal-capacity site is fine; a commercial one is not. |
| ICS Advisory Project | ODbL v1.0 | Attribution **and share-alike** — derived data must stay openly licensed. |
| Ransomware.live | Free community API, fair use | Do not hammer it; review terms before any organisational use. |
| CISA KEV, NVD, HHS OCR | US Government works | Public domain. No restriction. |
| VERIS Community Database | Repository terms | Attribution. |
| CISSM | Granted on request — **do not redistribute raw records** | See below. |
| Vendor reports | Copyright of publishers | Links only. Never reproduce text. |

`ATTRIBUTION.md` carries the public credits. Keep it current when adding a source.

> **Open question worth resolving.** The CISSM terms recorded in the builder say the raw
> records should not be redistributed. Committing the export to a **public** repository,
> and publishing a derived pack to GitHub Pages, is arguably exactly that. I have not
> resolved this — it depends on the terms you actually agreed with CISSM. Three options:
> confirm with CISSM that publication of derived records is acceptable; publish only
> aggregates from that source rather than per-incident rows; or keep the repository
> private and publish only the built pack. Given the day job, this is worth settling
> before the site gets much attention.

---

## 7. Reading the data honestly

Points the tool makes on screen, repeated here because they matter when the work is
quoted:

- **Counts are of *documented* incidents, not incidents.** Rises can reflect better
  disclosure law as much as more attacks.
- **Ransomware leak-site claims are assertions by criminals.** They can be false or
  double-counted. They are tagged *Claimed by the attacker* and drawn hollow.
- **Attribution is thin.** Origin points are analytical proxies, not proven launch
  locations, and most incidents have no attribution at all.
- **Impact coverage is sparse and uneven.** Only EuRepoC-reviewed incidents and the
  curated landmarks are scored, so the impact chart shows the documented heavy hitters,
  not a ranking of all harm.
- **Financial figures are estimates**, frequently contested, better read as orders of
  magnitude than as accounts.
- **Novelty is an editorial judgement**, labelled as such and kept separate from the
  measured dimensions.
- **The year-end projection is a straight line**, not a forecast.

---

*Maintained by Stuart Okin, Director of Cyber Regulation and Emerging Technologies,
Ofgem. Published in a personal capacity; views are his own and not those of Ofgem.*
