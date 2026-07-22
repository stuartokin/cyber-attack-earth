# Attribution, sources and licences

**Cyber Attack Earth** visualises publicly documented cyber incidents as a way of
showing the growth in recorded attacks over time. It is built entirely from
third-party open data. This file records every source used, the licence it is
made available under, and the credit each requires.

Built as a personal project. Nothing here represents the views of any employer
or organisation. No trackers, no analytics, no advertising.

---

## Licence of this repository

| Part | Licence |
|---|---|
| **Data pack** — everything under `cyber_data/` | **Open Database Licence (ODbL) v1.0** |
| **Application code** — `index.html`, `build_cyber_data.py`, workflows | MIT (unless stated otherwise in the file) |

The data pack is a *derived database*. It contains material derived from the ICS
Advisory Project, which is published under ODbL v1.0 — a share-alike licence. To
respect that condition, the whole of `cyber_data/` is offered under the same
licence. You are free to use, modify and redistribute it, provided you attribute
the original sources listed below and release any derived database under ODbL.

The visualisation itself is a "Produced Work" under ODbL terms and is offered
under the MIT licence, together with the attribution notice displayed in the
application and reproduced here.

Full ODbL text: https://opendatacommons.org/licenses/odbl/1-0/

---

## Data sources

### Mapped incidents

**EuRepoC — European Repository of Cyber Incidents**
Expert-reviewed political and strategic cyber incidents.
Site: https://eurepoc.eu/ · Dataset: https://zenodo.org/records/14965395
Licence: see the terms on the Zenodo record.

**VERIS Community Database (VCDB)**
Publicly disclosed breaches and security incidents, coded to the VERIS schema.
Site: https://verisframework.org/vcdb.html · Repository: https://github.com/vz-risk/VCDB
Licence: as stated in the repository.

**Ransomware.live** — maintained by Julien Mousqueton
Ransomware leak-site victim claims and group tracking.
Site: https://www.ransomware.live/ · Methodology: https://www.ransomware.live/about
Licence: free community API under fair use. Organisational or commercial use may
require a paid subscription — review the terms before reusing this layer.
Note: leak-site listings are *attacker assertions*, not verified breaches. Some
claimed victims dispute them. They are shown at country level with no attacker
origin asserted.

**CISSM Cyber Events Database — University of Maryland** *(optional layer)*
Academically coded public cyber events from 2014 onwards.
Site: https://cissm.umd.edu/cyber-events-database
Access is granted on request to researchers and public officials; there is no
public bulk download, and this project does not scrape it or use third-party
mirrors. The layer is only present if the operator has supplied their own
authorised export. Raw records are not redistributed.
Required citation: Harry, C., & Gallagher, N. (2018). *Classifying Cyber Events*.
Journal of Information Warfare, 17(3), 17–31.

**Curated incident layer** — compiled for this project
Around ninety documented incidents with direct primary or official references,
embedded so the map works without network access. Attribution notes and
confidence levels are recorded per incident.

### Vulnerability and technique reference data

**CISA Known Exploited Vulnerabilities (KEV) Catalog**
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
US Government work — public domain.

**EPSS — Exploit Prediction Scoring System, FIRST**
https://www.first.org/epss/
Free to use; attribution to FIRST expected. Scores are a daily snapshot and are
recalculated continuously — they are not a historical time series.

**National Vulnerability Database (NVD), NIST**
https://nvd.nist.gov/
US Government work — public domain. This project stores only monthly counts of
published CVEs, retrieved via the public API. No CVE records are redistributed.

**MITRE ATT&CK®**
https://attack.mitre.org/
© The MITRE Corporation. Used under the MITRE ATT&CK Terms of Use; attribution
required. ATT&CK® is a registered trademark of The MITRE Corporation. This
project is not affiliated with or endorsed by MITRE.

### Operational technology advisories

**ICS Advisory Project** — in partnership with Industrial Data Works
CISA ICS advisories cleaned and published in CSV form.
Site: https://www.icsadvisoryproject.com/ · Repository: https://github.com/icsadvprj/ICS-Advisory-Project
**Licence: Open Database Licence (ODbL) v1.0 — attribution and share-alike.**
Original advisories are published by CISA: https://www.cisa.gov/news-events/cybersecurity-advisories

### Base map and libraries

**World Atlas TopoJSON** (Natural Earth derived) — https://github.com/topojson/world-atlas
Natural Earth data is public domain.
**globe.gl**, **D3**, **TopoJSON**, **fflate** — see each project for its licence.

### Threat reports referenced

Reports by Microsoft, Google/Mandiant, CrowdStrike, IBM X-Force, Palo Alto
Networks Unit 42, Recorded Future, Dragos, ENISA, NCSC, WEF and Verizon are
**linked only**. They remain the copyright of their publishers. No content from
them is reproduced, scraped or redistributed by this project.

---

## How to cite this visualisation

> Cyber Attack Earth (2026). Visualisation of publicly documented cyber
> incidents, 2000–present. Built from EuRepoC, VCDB, Ransomware.live, CISA KEV,
> NVD, EPSS (FIRST), MITRE ATT&CK and the ICS Advisory Project.

---

## Important limitations

These matter more than the licences, and anyone using this data should read them.

1. **This shows documented incidents, not all attacks.** The overwhelming
   majority of cyber attacks are never publicly disclosed or catalogued.
2. **Growth partly reflects better recording.** Disclosure regimes, breach
   notification laws and dataset coverage all expanded over the period shown.
   Some of the rise in the chart is real; some is improved measurement. The two
   cannot be cleanly separated.
3. **Coverage is uneven by geography.** Countries with mandatory disclosure and
   active research communities appear far more often. Sparse regions on the map
   indicate sparse *reporting*, not safety.
4. **Attacker origins are frequently proxies.** Where a country is shown as an
   origin it usually reflects public attribution, an indictment, sanctions, or an
   ecosystem association — not a verified launch location. Unattributed attacks
   launch from a neutral ocean anchor and can be filtered out entirely.
5. **Leak-site claims are unverified.** They are the attacker's own account.
6. **Vulnerability counts are context, not attacks.** CVE and KEV series measure
   attack surface and known exploitation, not incidents.
