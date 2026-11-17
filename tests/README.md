# Test rig

Run everything before every push:

```bash
cd tests
npm test            # all of the below, browser test on five screens (~6 min)
npm run test:quick  # same, browser test on laptop, folded Fold and phone only
npm run shots       # browser test plus screenshots in tests/out/ — look at them
```

No install step in a Claude cloud session: Playwright and Chromium are already there.
On GitHub, `.github/workflows/tests.yml` installs them and runs the same files.

| File | What it checks | Network |
|---|---|---|
| `test_builder.py` | 13 unit checks on `build_cyber_data.py`: EuRepoC parsing (type, sector, intensity, no unit-less money), shrink guard, carry-forward of failed/unscheduled sources (incl. an end-to-end `main()` run), ransomware.live incremental fetch with capped retries and sorted rows, CISSM paging (sorted, de-duplicated) and API-mode export ages, manual-file matching, SEC links. | None — every fetch is faked |
| `test_pack.py` | The committed `cyber_data/`: manifest schema, every source has a status, every listed file exists and parses, incident total adds up, core layers present. Pass a path to check another pack. | None |
| `test_curated.py` | Stuart's CSVs: unique ids, valid years/months/severity, every figure points at a real incident and sits in range, every estimate has a URL and a method, SEC decisions are y/n/blank, no e-mail addresses (public repo). | None |
| `test_workflows.py` | Every self-starting workflow has the kill-switch `switch` job reading both `automation.json` files and every other job waits for it; every job has a timeout; no literal secrets; the data workflow checks the pack before committing. Needs PyYAML. | None |
| `smoke.js` | Playwright on desktop 1908×950, laptop 1366×768, phone 390×844, Fold folded 344×882 and open 884×1104, **with every other website blocked**: welcome screen ready and then inert, data pack loads (20k+ routes), never wider than the screen, EuRepoC sectors and techniques real, status chip honest about stale exports, claims-only note, Controls close button reachable, search finds NotPetya and opens it, data-status panel lists every source, Play advances the clock, flat map draws, no script errors, nothing fetched from a CDN. | Local only |

Options for `smoke.js`: `--quick`, `--shots`, `--url=https://stuartokin.github.io/cyber-attack-earth/`
(test the live site).

**Rule:** fix a bug → add a check here so it stays fixed.
