# Cyber Attack Earth — maintenance guide

Everything here is done through the GitHub website. No terminal, no local Python.

- **Live site:** https://stuartokin.github.io/cyber-attack-earth/
- **App:** `index.html` (one self-contained file)
- **Builder:** `build_cyber_data.py` (runs nightly via GitHub Actions)
- **Data pack:** `cyber_data/` (written by the Action — never edit by hand)
- **Curated impact layer:** `impact_overlay.csv` + `impact_figures.csv` (yours to edit)
- **Published estimates:** `estimates.csv` (yours to edit — what is *not* recorded)
- **Review queue:** `manual_sources/sec_review.csv` (candidates awaiting your decision)
- **Hand-downloaded exports:** `manual_sources/` (CISSM, EuRepoC TableView)

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

**Also worth a glance, now that more is automated:**

* **Help → Waiting for review** — how many SEC disclosures have piled up. If it is
  climbing past thirty, spend ten minutes on section 2e.
* **Any open GitHub issue labelled `data-refresh`** — the build raises one when a
  hand-downloaded export goes past forty days, and closes it when you refresh.
* The build summary's **Manual exports** block, which prints the age of each one.

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

### 2e. Work the SEC review queue (~10 min, monthly)

Since December 2023, US-listed companies must file an 8-K when they conclude a cyber
incident is **material**. The nightly build searches EDGAR for those filings and writes
candidates to `manual_sources/sec_review.csv`.

**Nothing in that file is in the tool.** It is not counted, not mapped, not totalled.
These are suggestions awaiting your judgement, and they exist because the alternative —
merging them automatically — would double-count incidents that are already in the tables
under a different name.

**What to do:**

1. Open `manual_sources/sec_review.csv` in the GitHub web editor.
2. For each row, follow the `url` to the filing.
3. Put `y` in the `review_status` column if it is a genuine incident worth adding,
   `n` if it is a duplicate, immaterial, or already present.
4. Commit. Decisions are preserved across nightly runs, keyed on the company's CIK
   number and the filing date, so you never see the same row twice once decided.
5. For anything marked `y` that deserves a full entry, add it to `impact_overlay.csv`
   by hand in the usual way. Accepting a row does **not** move it automatically — that
   remains deliberate.

**How to see how many are waiting:** Help → *Waiting for review* in the app.

**Two limits worth knowing.** Many companies file under Item 8.01 (voluntary) rather
than 1.05 precisely to avoid asserting materiality, so this undercounts; both are
searched and the `item` column records which found it. And it is US-listed companies
only — a large and wealthy slice of the world, not the world.

---

### 2f. Keep the estimates layer current (~15 min, a few times a year)

`estimates.csv` holds published figures for what is **not** recorded — survey estimates,
modelled event costs — each with its own source, scope and method. They power the
*What is not recorded* panel and the *Recorded here vs. what surveys find* chart.

Unlike the other manual files this one does **not** go stale as a file: a 2017 figure
stays correct forever. What goes stale is **coverage**. The publications to watch:

| Publication | Who | When |
|---|---|---|
| Cyber Security Breaches Survey | DSIT / Home Office | Annually, usually April |
| Crime in England and Wales (computer misuse) | ONS | Quarterly bulletins, annual detail in July |
| Event assessments | Cyber Monitoring Centre | Per event, irregular |

**The rules, enforced by the builder:**

* Every row needs a **source URL** and a **stated method**, or it is rejected outright.
* Nothing is ever **summed**. These figures count different populations over different
  periods with incompatible definitions. A combined total would look authoritative and
  mean nothing — and it would be *your* number rather than any publisher's.
* Mark a row `verified` only when you have seen the figure on the publisher's own page.
  Anything from secondary coverage stays `provisional`.

**Do not rename this file with a date.** Two files matching one source is a trap: the
builder picks the larger, which is arbitrary, and an old renamed copy can silently
outrank a fresh one. Keep exactly one `estimates.csv`. (It warns you if it finds more.)

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

### Repository secrets

Settings → Secrets and variables → Actions. All optional; the build degrades cleanly
without them.

| Secret | What it does | Without it |
|---|---|---|
| `NVD_API_KEY` | Free key from nvd.nist.gov. Raises the CVE and vulnerability request rate. | Backfill is much slower but still works. |
| `SEC_CONTACT` | `Your Project Name you@example.com`. SEC refuses requests without a contact email in the User-Agent. | The SEC connector is **skipped**, not failed. |
| `CISSM_API_KEY` | For when Charles issues the key. | Falls back to the manual export. |

`SEC_CONTACT` is a secret rather than a line in the source deliberately: this
repository is public, and an email address in the code is a durable spam magnet.

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

## 6. Licence obligations

| Source | Terms | What that requires of you |
|---|---|---|
| EuRepoC | CC BY-NC 4.0 | Attribution, **non-commercial use only**. A personal-capacity site is fine; a commercial one is not. |
| ICS Advisory Project | ODbL v1.0 | Attribution **and share-alike** — derived data must stay openly licensed. |
| Ransomware.live | Free community API, fair use | Do not hammer it; review terms before any organisational use. |
| CISA KEV, NVD, HHS OCR | US Government works | Public domain. No restriction. |
| VERIS Community Database | Repository terms | Attribution. |
| CISSM / GoTech | **Use confirmed** by Dr Charles Harry, July 2026 | Cite Harry, C. & Gallagher, N. (2018), *Classifying Cyber Events*, Journal of Information Warfare 17(3), 17–31. |
| Have I Been Pwned | Free catalogue endpoint | Attribution to Have I Been Pwned. Held as its own table, never merged into incidents. |
| SEC EDGAR | US Government work | Public domain. Requires a User-Agent with a contact email (see `SEC_CONTACT`). |
| Cyber Monitoring Centre | Published assessments | Cite the specific assessment; figures belong to CMC. |
| ONS / DSIT | Official statistics, Open Government Licence | Attribution. |
| Vendor reports | Copyright of publishers | Links only. Never reproduce text. |

`ATTRIBUTION.md` carries the public credits. Keep it current when adding a source.

> **Resolved, July 2026.** Dr Charles Harry confirmed that use of the Cyber Events
> Database in this project is permitted, and an API is expected. Until it arrives the
> monthly manual export continues. When the key is issued, add it as the repository
> secret `CISSM_API_KEY` — the builder already has that path and the manual step
> simply stops being used. Keep the Harry & Gallagher citation wherever the data is
> described.

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
