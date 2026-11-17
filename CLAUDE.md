# CLAUDE.md — read this first

This repo is **Cyber Attack Earth — Escalation Atlas**: publicly documented cyber incidents from 2000 to today,
from five independent sources, on a globe you can play through time. Owner: Stuart Okin (GitHub `stuartokin`).
Live: https://stuartokin.github.io/cyber-attack-earth/ (GitHub Pages from `main`). A card on the hub (https://stuartokin.github.io/).

Read, in order: **`MAINTENANCE.md`** (the full guide: sources, cadence, review queue, secrets, fixes),
`docs/LESSONS.md`, `docs/ROADMAP.md` (open work and questions for Stuart), the latest entry in
`docs/CHANGELOG.md`, and `ATTRIBUTION.md` (licences of every source).

## How it is built

- `index.html`: the whole app in one file. Edit directly. Bump `APP_VERSION` and add to `CHANGELOG` (in-app) each release.
- `vendor/`: self-hosted map libraries and textures. No CDNs; keep it that way.
- `build_cyber_data.py`: builds the data pack. Its version is `BUILDER_VERSION` (with a history at the top of the
  file); bump it with every change and check `cyber_data/manifest.json` → `"builder"` after the next run.
- `cyber_data/`: written by the workflow (or by running the builder). **Never edit by hand.**
  A source that fails, is held by the shrink guard, or is not scheduled keeps its previous files
  in the manifest (`carry_forward`).
- Stuart's curated files: `impact_overlay.csv`, `impact_figures.csv`, `estimates.csv`, `manual_sources/`.
- `.github/workflows/update-cyber-data.yml`: fast sources nightly (02:17 UTC), everything weekly (Sunday), no AI.
  Commits as `data-pack-bot`. Optional secrets `CISSM_API_KEY`, `NVD_API_KEY`, `SEC_CONTACT` (GitHub secrets only;
  never in files: the repo is public). `.github/workflows/tests.yml` runs the tests on every app/builder push.
- **Tests:** `cd tests && npm test` — `test_builder.py` (unit checks, no network), `test_pack.py` (manifest and
  every listed file), `smoke.js` (Playwright, five screens, all other sites blocked). All must pass before a push.
  Add a check whenever you fix a bug.
- CISSM comes by API (secret `CISSM_API_KEY`, since 2026-11-17). The EuRepoC TableView is still a hand export in
  `manual_sources/` with the date in the filename, until EuRepoC grants API access (see ROADMAP).
- Disclosed incidents are a small, uneven fraction of what happened; the page says so. Keep that honesty.

<!-- STANDARD:BEGIN v1 — the same block is in every one of Stuart's repos. Master copy:
     stuartokin/stuartokin.github.io docs/STANDARDS.md. Change it there, then everywhere. -->
## Working standard (all of Stuart's repos)

**Stuart** owns this. British English; short, plain replies. He does not read or edit code:
you make every change, test it, push it, and tell him what to check. Plan first for big
things; when he says "go ahead", build without further proofs.

**Personal capacity.** Never name his employer or job title anywhere: pages, docs, commit
messages, articles. Byline: *Stuart Okin*. Where a disclaimer is needed: *"Written in a
personal capacity and do not represent the position of any organisation I am engaged with."*
Citing an organisation as a source is fine.

**Delivering changes.** Commit and push straight to `main` yourself. Don't send zips or ask
him to upload; older instructions in this repo that say so are superseded. Before anything
major (deleting or restructuring, rewriting a core file, changing workflows or agents,
migrating data) push a backup tag first:
`git tag backup/YYYY-MM-DD-<what> origin/main && git push origin backup/YYYY-MM-DD-<what>`.
To undo, reset `main` to that tag; say in your reply that a backup exists. Never commit
secrets: keys live only in GitHub secrets.

**Tests.** Run the repo's tests before every push; all must pass. Fix a bug, add a check so
it stays fixed. If the repo has no tests yet, add at least a smoke test the next time you
change it.

**Automation.** Any workflow that runs on its own (schedule, issues, comments, other
workflows) must start with the kill-switch `switch` job, reading `automation.json` here and
the master in stuartokin.github.io (see its docs/KNOWLEDGE-BASE.md §15). Don't add an AI
agent without saying what it costs, what it can change and how to switch it off.

**"Wrap up".** When Stuart says "wrap up", and before you finish any session that changed
something:
1. Run the tests; fix or report any failure.
2. Update the docs: how the app works (knowledge base or handover), `LESSONS` (what went
   wrong or surprised you), `ROADMAP` (done, next, open questions for Stuart, decisions with
   dates) and `CHANGELOG` (bump the version if the app changed). Create them if missing.
3. If a lesson would help the other repos, add it to `docs/SHARED-LESSONS.md` in
   stuartokin.github.io.
4. Commit and push to `main` (backup tag first if major). Check the deploy or workflow run.
5. Reply with what changed, the version, what was and wasn't tested, a short numbered list of
   things for Stuart to try, and anything waiting on him.

A new session must be able to carry on from the repo alone. If it couldn't, the wrap-up
isn't done.
<!-- STANDARD:END -->
