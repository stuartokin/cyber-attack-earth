# Attribution, sources and licences

**Cyber Attack Earth** visualises publicly documented cyber incidents in order to show
how the volume of recorded attacks has changed over time. It is built entirely from
third-party open data. This file records every source used, the licence it is made
available under, and the credit each requires.

Built as a personal project. Nothing here represents the views of any employer or
organisation. No trackers, no analytics, no advertising.

---

## Licensing of this repository — read this first

**This repository is not under a single licence.** The data pack combines sources with
incompatible terms, so each part is governed separately.

| Part | Licence |
|---|---|
| **Application code** — `index.html`, `build_cyber_data.py`, workflows | MIT |
| **EuRepoC-derived records** in `cyber_data/incidents/eurepoc*.json` | **CC BY-NC 4.0 — non-commercial use only** |
| **All other data** in `cyber_data/` | **Open Database Licence (ODbL) v1.0** |

### Why the split

EuRepoC changed its licence to **CC BY-NC 4.0 on 2 April 2025**, restricting the data
to non-commercial use. ODbL, by contrast, expressly permits commercial use. The two
cannot be combined under one notice: offering EuRepoC-derived records under ODbL would
grant permissions that were never given. The EuRepoC files are therefore carved out and
remain non-commercial.

The ODbL portion exists because the ICS Advisory Project publishes under ODbL v1.0, a
share-alike licence: a derived database built from it must be released on the same
terms. That obligation applies to the ICS-derived material and the other openly
licensed sources packaged alongside it — not to the EuRepoC files.

**If you reuse this data pack:** you may use the ODbL portion commercially provided you
attribute the sources below and release any derived database under ODbL. You may
**not** use the EuRepoC-derived files for commercial purposes at all.

The visualisation itself is a "Produced Work" under ODbL terms and is offered under
MIT, together with the attribution notice displayed in the application and reproduced
here.

ODbL text: https://opendatacommons.org/licenses/odbl/1-0/
CC BY-NC 4.0 text: https://creativecommons.org/licenses/by-nc/4.0/

---

## Data sources

### Mapped incidents

**EuRepoC — European Repository of Cyber Incidents** — **CC BY-NC 4.0, non-commercial only**
Expert-coded political and strategic cyber incidents, assessed against 60 variables by
an interdisciplinary team.
Site: https://eurepoc.eu/ · Dataset: https://zenodo.org/records/14965395
Citation: Zettl-Schabath, K., Bund, J., Müller, M., Borrett, C., Hemmelskamp, J.,
Alibegovic, A., Bajra, E., Jazxhi, A., Kellenter, E., Sachs, A., & Shelley, C. (2025).
*Global Dataset of Cyber Incidents* (1.3.2) [Data set]. European Repository of Cyber
Incidents. https://doi.org/10.5281/zenodo.14965395

Two EuRepoC layers may appear, and they are not equivalent:

- **Static release (v1.3)** — fully expert-reviewed. Covers incidents starting between
  1 January 2000 and **31 December 2024**. This is the authoritative layer.
- **TableView export** *(optional, only if an export has been supplied)* — the current
  working data, which EuRepoC explicitly describes as **not fully expert-reviewed**. It
  is used only to cover the period after the static release ends, and is labelled as
  provisional wherever it appears in the application.

**VERIS Community Database (VCDB)**
Publicly disclosed breaches and security incidents, coded to the VERIS schema.
Site: https://verisframework.org/vcdb.html · Repository: https://github.com/vz-risk/VCDB
Licence: as stated in the repository.

**Ransomware.live** — maintained by Julien Mousqueton
Ransomware leak-site victim claims and group tracking.
Site: https://www.ransomware.live/ · Methodology: https://www.ransomware.live/about
Licence: free community API under fair use. Organisational or commercial use may require
a paid subscription — review the terms before reusing this layer.
Note: leak-site listings are *attacker assertions*, not verified breaches. Some claimed
victims dispute them. They are placed at country level with no attacker origin asserted.

**CISSM Cyber Events Database — University of Maryland** *(optional layer)*
Academically coded public cyber events from 2014 onwards.
Site: https://cybereventsdatabase.org
Access is granted on request; there is no public bulk download, and this project does
not scrape the portal or use third-party mirrors. The layer is present only if the
operator has supplied their own authorised export. Raw records are not redistributed.
Required citation: Harry, C., & Gallagher, N. (2018). *Classifying Cyber Events*.
Journal of Information Warfare, 17(3), 17–31.

**Curated incident layer** — compiled for this project
Around ninety documented incidents with direct primary or official references, embedded
so the map works without network access. Attribution notes and confidence levels are
recorded per incident.

### Vulnerability and technique reference data

**CISA Known Exploited Vulnerabilities (KEV) Catalog**
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
US Government work — public domain.

**EPSS — Exploit Prediction Scoring System, FIRST**
https://www.first.org/epss/
Free to use; attribution to FIRST expected. Scores are a daily snapshot recalculated
continuously — they are not a historical time series.

**National Vulnerability Database (NVD), NIST**
https://nvd.nist.gov/
US Government work — public domain. Only monthly counts of published CVEs are stored,
retrieved via the public API. No CVE records are redistributed.

**MITRE ATT&CK®**
https://attack.mitre.org/
© The MITRE Corporation. Used under the MITRE ATT&CK Terms of Use; attribution required.
ATT&CK® is a registered trademark of The MITRE Corporation. This project is not
affiliated with, or endorsed by, MITRE.

### Operational technology advisories

**ICS Advisory Project** — in partnership with Industrial Data Works
CISA ICS advisories cleaned and published in CSV form.
Site: https://www.icsadvisoryproject.com/ · Repository: https://github.com/icsadvprj/ICS-Advisory-Project
**Licence: Open Database Licence (ODbL) v1.0 — attribution and share-alike.**
Original advisories are published by CISA:
https://www.cisa.gov/news-events/cybersecurity-advisories

### Base map and libraries

**World Atlas TopoJSON** (Natural Earth derived) — https://github.com/topojson/world-atlas
Natural Earth data is public domain.
**globe.gl**, **D3**, **TopoJSON**, **fflate** — see each project for its licence.

### Threat reports referenced

Reports by Microsoft, Google/Mandiant, CrowdStrike, IBM X-Force, Palo Alto Networks
Unit 42, Recorded Future, Dragos, ENISA, NCSC, WEF and Verizon are **linked only**. They
remain the copyright of their publishers. No content from them is reproduced, scraped or
redistributed by this project.

---

## How to cite this visualisation

> Cyber Attack Earth (2026). Visualisation of publicly documented cyber incidents,
> 2000–present. Built from EuRepoC, VCDB, Ransomware.live, CISA KEV, NVD, EPSS (FIRST),
> MITRE ATT&CK and the ICS Advisory Project.

---

## Important limitations

These matter more than the licences, and anyone using this data should read them.

1. **This shows documented incidents, not all attacks.** The overwhelming majority of
   cyber attacks are never publicly disclosed or catalogued.

2. **Growth partly reflects better recording.** Disclosure regimes, breach notification
   laws and dataset coverage all expanded over the period shown. Some of the rise in the
   chart is real; some is improved measurement. The two cannot be cleanly separated.

3. **Severity trends are shaped by which source is doing the coding.** Only the EuRepoC
   and curated layers ever assign *Critical*; VCDB caps at High, and Ransomware.live
   entries are Medium unless widely reported. Because the expert-coded static release
   ends on 31 December 2024 while recent volume is dominated by ransomware leak-site
   claims, the share of Critical and High **appears to fall in the most recent years even
   if severe incidents have not**. This is a measurement artefact. The "Where the data
   comes from, by year" chart in the application shows the composition directly.

4. **Coverage is uneven by geography.** Countries with mandatory disclosure and active
   research communities appear far more often. Sparse regions on the map indicate sparse
   *reporting*, not safety.

5. **Attacker origins are frequently proxies.** Where a country is shown as an origin it
   usually reflects public attribution, an indictment, sanctions, or an ecosystem
   association — not a verified launch location. Unattributed attacks launch from a
   neutral ocean anchor and can be filtered out entirely.

6. **Leak-site claims are unverified.** They are the attacker's own account.

7. **Vulnerability counts are context, not attacks.** CVE and KEV series measure attack
   surface and known exploitation, not incidents.

---

*This file states the licensing position as understood by the project maintainer. It is
not legal advice. Where a source's terms are ambiguous, the maintainer's practice is to
ask the publisher rather than assume.*
