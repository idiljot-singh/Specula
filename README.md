<div align="center">

# Specula

**Threat-informed CVE prioritisation.**
From every CVE in the world to the few that matter to *your* organisation, with a reason for every decision.

![Python](https://img.shields.io/badge/python-3.14-3ee6a8?logo=python&logoColor=white&labelColor=0a101b)
![License](https://img.shields.io/badge/license-MIT-3ee6a8?labelColor=0a101b)
![STIX 2.1](https://img.shields.io/badge/STIX-2.1-5aa9ff?labelColor=0a101b)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-ff4d5e?labelColor=0a101b)

</div>

*Specula* is Latin for a watchtower. It watches the global vulnerability feed and tells you what, in your estate, needs action now, and why.

## Why

About 40,000 CVEs are published every year. Most teams rank them by CVSS, which measures how bad a flaw *could* be, not whether anyone is using it against *you*. Specula answers three questions instead:

1. **Do we run it?** Owned assets are matched to every CVE by product (CPE) and version.
2. **Do our suppliers run it?** MSPs, SaaS and partners are scored by blast radius: the data they hold and the access they have.
3. **Are the attackers who target us using it?** Known exploitation (CISA KEV), predicted exploitation (FIRST EPSS), and the adversary groups in your threat profile (MITRE ATT&CK + CTID mappings).

The result is a ranked, explainable list in four SSVC decision tiers: **Act** (within 48 h) · **Attend** · **Track** · **Ignore**.

## Features

| | |
|---|---|
| **Full CTI lifecycle** | Direction → Collection → Processing → Analysis → Dissemination → Feedback, one module per stage |
| **Explainable scoring** | `risk = likelihood × impact`. Every term is written out next to each finding; all weights live in one YAML file |
| **Deterministic** | The same inputs give a byte-identical ranking. An optional LLM only writes the management brief and never scores |
| **Third-party risk** | Supplier CVEs are weighted by data access and privileged access |
| **Five outputs** | Analyst dashboard, Markdown report, management brief, CSV, and a **STIX 2.1** bundle for MISP, OpenCTI or Sentinel |
| **Console** | A local web interface that walks through each stage, runs the real code and streams its output |
| **Secure by design** | Localhost-only console with CSRF and DNS-rebinding protection, secrets in the OS credential store, hash-pinned dependencies, TLP:AMBER marking, feed-poisoning guards |
| **Small** | About 1,100 lines of plain Python, 4 dependencies, SQLite, no servers |

## Quick start

```bash
pip install --require-hashes -r requirements.txt
python test_pipeline.py                         # offline self-check: prints "ok"
python run.py --example --since 2026-01-01      # try it on the bundled Example Organisation -> out/example/

copy profile.example.yaml profile.yaml          # your organisation and threat profile
copy assets.example.csv assets.csv              # the software you run
copy third_parties.example.csv third_parties.csv   # your suppliers (optional)
copy exceptions.example.csv exceptions.csv      # analyst decisions (optional)
# Linux/macOS: use cp instead of copy

python app.py                                   # console at http://127.0.0.1:8765
```

In the console, open **Collection → Quick sync** to download the feeds, then **Analysis → Re-rank**. On the command line:

```bash
python run.py --since 2026-01-01        # quick: only CVEs changed since a date
python run.py                           # full NVD history the first time, then incremental
python run.py --skip-collect            # re-rank without downloading
python run.py --suggest-cpe exchange    # find the NVD product name for the cpe column
```

## Documentation

| Document | Read it to… |
|---|---|
| [CUSTOMISE.md](CUSTOMISE.md) | Set Specula up for **your** organisation, step by step, with a checklist |
| [WALKTHROUGH.md](WALKTHROUGH.md) ([PDF](WALKTHROUGH.pdf)) | Understand how every stage works and why |
| [SECURITY.md](SECURITY.md) | Report a vulnerability in Specula |

## How it works

| CTI stage | Module | What it does |
|---|---|---|
| Direction | `profile.yaml` | Organisation, Priority Intelligence Requirements, threat groups, weights, tiers |
| Collection | `cti/collect.py` | NVD (every CVE), CISA KEV, FIRST EPSS, MITRE ATT&CK, CTID KEV→ATT&CK into `cve.db` |
| Processing | `cti/process.py` | Owned assets and suppliers → CPE + version matching; optional Microsoft Defender inventory |
| Analysis | `cti/analyse.py` | Risk score, threat-profile overlap, ATT&CK techniques, SSVC tier |
| Dissemination | `cti/disseminate.py` | `report.md`, `report.csv`, `dashboard.html`, `brief.md`, STIX 2.1 `bundle.json` |
| Feedback | `exceptions.csv` | Patched, mitigated or accepted decisions that expire and come back for review |

```
likelihood = 0.4·EPSS + 0.3·inKEV + 0.1·ransomware + 0.2·threat_overlap
impact     = CVSS/10 · criticality (or supplier blast radius) · 1.5 if internet-facing
risk       = likelihood · impact
```

## Your data stays yours

Specula runs entirely on your machine. `profile.yaml`, the asset, supplier and exception lists, the database and all outputs are **git-ignored**: they describe where your organisation is vulnerable. Only public feeds are downloaded; nothing about your estate is sent anywhere unless you enable a cloud LLM for the brief, and even then the input is redacted.

## Author

**Specula** is created and maintained by **Diljot Singh Johal**.

If you use it in research or in your organisation, please cite it (see [CITATION.cff](CITATION.cff)).

## License

[MIT](LICENSE) © 2026 Diljot Singh Johal.
Feed data belongs to its publishers: NIST NVD, CISA, FIRST, MITRE and the Center for Threat-Informed Defense. Check their terms before redistributing it.
