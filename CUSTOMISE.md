# Customising Specula for your organisation

Everything organisation-specific lives in **four data files** and **one profile**. For most organisations you don't need to touch any code. Work through the steps in order. Each one ends with a check, so you know it worked before you move on.

| File | What it describes | In git? |
|---|---|---|
| `profile.yaml` | Who you are, who targets you, how to score | No (copied from `profile.example.yaml`) |
| `assets.csv` | Software you run | No (copied from `assets.example.csv`) |
| `third_parties.csv` | Suppliers who run software for you | No (copied from `third_parties.example.csv`) |
| `exceptions.csv` | Analyst decisions: patched, accepted, and so on | No (copied from `exceptions.example.csv`) |

Your copies are **git-ignored on purpose**. Together they are a map of where your organisation is vulnerable. Never commit them to a public repository. The `*.example.*` files are templates, and the test suite reads `profile.example.yaml`, so leave the examples unchanged.

> You can do every step below either in a text editor or in the Specula console (`python app.py`), which has an editor for each file and refuses to save a file that would break the pipeline.

---

## Step 0: Install and self-check (5 minutes)

```bash
pip install --require-hashes -r requirements.txt
python test_pipeline.py            # must print: ok
```
Needs Python 3.14 or newer. On Linux or macOS, use `cp` instead of `copy` in the commands below.

---

## Step 1: Profile, the Direction stage (30 minutes)

```bash
copy profile.example.yaml profile.yaml
```

### 1a. Organisation
```yaml
organisation:
  name: Your Organisation Ltd
  sector: Healthcare
  country: Germany
```
The name appears in reports and in the STIX identity. Only the sector and country are ever sent to an optional cloud LLM; the name never is.

### 1b. Priority Intelligence Requirements (PIRs)
These are the questions leadership wants answered. The four defaults suit most organisations. Rewrite them in your own words if management uses different ones: they appear in the console and anchor the reports.

### 1c. Threat groups: the most important customisation
List the adversaries that realistically target **your sector and region**, as MITRE ATT&CK group IDs:
```yaml
threat_groups:
  G0007: APT28
  G1024: Akira
```
How to choose them:
1. Read your **national CERT/NCSC annual threat review** and your **sector ISAC** reports. Note every named group.
2. Look each one up at <https://attack.mitre.org/groups/>. The ID is the `Gxxxx` code on its page.
3. Add ransomware groups that are active in your country, even if they aren't sector-specific. They are the most likely attackers for most organisations.
4. Aim for 5–15 groups. Too many dilutes the threat-profile signal.

**Check:** after the first run, a warning lists any ID that isn't in ATT&CK (a typo or a retired ID). Fix it or remove it.

### 1d. Weights, exposure and tiers (optional)
The defaults are reasonable. Change them when your risk appetite differs:

| Setting | Raise it when… | Lower it when… |
|---|---|---|
| `weights.kev` | You want "proven exploited" to dominate | You have a mature patching programme for KEV already |
| `weights.threat_profile` | Your threat groups are well researched | Your group list is a rough guess |
| `exposure.internet` | You have a large internet-facing footprint | Almost everything sits behind a VPN |
| `tiers.attend_epss` | The Attend tier is too noisy | Too little reaches Attend |
| `third_party.recent_days` | Suppliers are slow to disclose | You want only fresh supplier alerts |

The four `weights` should add up to 1.0, so that likelihood stays between 0 and 1.

**Check:** open the console → **Analysis** → **Re-rank**, and look at whether the top 10 matches your intuition. If it doesn't, adjust one setting at a time.

---

## Step 2: Assets, the Processing stage (1–2 hours the first time)

```bash
copy assets.example.csv assets.csv
```
One row per product you run (not per machine):

| Column | Meaning | Example |
|---|---|---|
| `name` | Your label, shown in reports | `Mail server (Exchange 2019)` |
| `cpe` | NVD product name: `cpe:2.3:<a/o/h>:<vendor>:<product>` | `cpe:2.3:a:microsoft:exchange_server` |
| `version` | Installed version; leave it blank if unknown (then every CVE counts) | `2019` |
| `criticality` | 1 = low, 2 = important, 3 = crown jewel | `3` |
| `internet_facing` | `y` or `n` | `y` |

### Finding the CPE name
You don't need to guess. Ask the database:
```bash
python run.py --suggest-cpe fortios
```
Or use **Processing → CPE lookup** in the console. Pick the prefix with the most CVEs. `a` = application, `o` = operating system, `h` = hardware.

### Where to get the list
- **Microsoft Defender for Endpoint:** Specula can pull the inventory automatically (Step 6).
- Otherwise, use your CMDB or asset register, a software-inventory export, or the licence list. Start with internet-facing systems and crown jewels. A short, accurate list beats a long, vague one.

**Check:** run `python run.py --skip-collect` (after Step 5's first data sync). A row with a bad `cpe` is rejected with its name, and each asset should produce findings.

---

## Step 3: Suppliers, third-party risk (30 minutes)

```bash
copy third_parties.example.csv third_parties.csv
```

| Column | Meaning |
|---|---|
| `name` | Supplier + service, e.g. `Backup provider (Acronis Cyber Protect)` |
| `cpe` | The product they run for you |
| `version` | Usually blank: you can't see their patch level. Then only recent CVEs count |
| `type` | Free text: `MSP`, `SaaS`, `Backup`, `Partner`… |
| `data_access` | `none`, `internal` or `confidential`: the most sensitive data they hold |
| `privileged` | `y` if they have admin or remote access into your network |
| `internet_facing` | `y` if the service is reachable from the internet |

Prioritise MSP remote-access tools, file-transfer services, backup providers and identity providers. These are where supply-chain attacks happen. The file is optional; delete it to skip third-party risk.

---

## Step 4: Exceptions, the Feedback stage (ongoing)

```bash
copy exceptions.example.csv exceptions.csv
```
Delete the example rows, then add one row per analyst decision:

| Column | Meaning |
|---|---|
| `cve` | The CVE ID |
| `asset` | The exact asset `name`, or `*` for all assets |
| `status` | `patched`, `mitigated`, `accepted`, `false_positive` or `not_affected` |
| `until` | Optional expiry `YYYY-MM-DD`. After this date the finding comes back for review |
| `note` | Who decided, and why |

Rule of thumb: every `accepted` or `mitigated` row gets an `until` date, so no risk is silenced forever.

---

## Step 5: First data sync

```bash
python run.py --since 2026-01-01     # quick test: only CVEs changed since a date (a few minutes)
python run.py                        # full NVD history; the first time takes about 15 minutes without an API key
```
After this, each run fetches only the changes, which takes 1–2 minutes.

**Get a free NVD API key** (about 10× faster): request one at <https://nvd.nist.gov/developers/request-an-api-key>, then store it in the operating system's credential store, never in a file:
```bash
python -c "import keyring; keyring.set_password('specula', 'NVD_API_KEY', input('key: '))"
```

---

## Step 6: Optional integrations

### Microsoft Defender for Endpoint (automatic inventory)
Follow the numbered steps at the top of `cti/defender.py`: a read-only app registration with a certificate, not a client secret. Then fill the `defender:` block in `profile.yaml` and set `enabled: true`. Defender's own per-device vulnerability data then replaces version guessing for managed devices. Keep `assets.csv` for things Defender can't see: firewalls, appliances and network gear.

### LLM-written management brief
Set `llm.provider` in `profile.yaml`: `none` (default, offline template), `ollama` (local model; data never leaves the machine), `azure_openai` (your own tenant) or `anthropic`. Store keys with the same `keyring` command (`AZURE_OPENAI_KEY`, `ANTHROPIC_API_KEY`). The LLM only writes prose; scores and tiers are always deterministic. Cloud providers get redacted input: no hostnames, IPs, asset names or the organisation's name.

---

## Step 7: Run it every day

**Windows** (Task Scheduler, as a dedicated low-privilege service account):
```powershell
schtasks /Create /TN "Specula" /SC DAILY /ST 06:00 /RU "DOMAIN\svc-specula" /RP * `
  /TR "\"C:\Program Files\Python314\python.exe\" \"C:\Specula\run.py\""
```
**Linux** (cron, as a dedicated user): `0 6 * * * /usr/bin/python3 /opt/specula/run.py`

Every run appends one line to `run.log`, including failures. Store secrets while logged in as the service account, because credential stores are per-user.

---

## Step 8: Harden the installation

The data folder holds a map of your weaknesses:
1. **Restrict the folder** to the service account, the analyst group and administrators.
   Windows (as admin):
   ```powershell
   $p = "C:\Specula"
   icacls $p /inheritance:r
   icacls $p /grant:r "DOMAIN\svc-specula:(OI)(CI)M" "DOMAIN\CTI-Analysts:(OI)(CI)R" "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
   ```
   Linux: `chown -R svc-specula:cti-analysts /opt/specula && chmod -R o-rwx /opt/specula`
2. **Encrypt the disk** (BitLocker, LUKS or FileVault).
3. **Keep the console local.** `app.py` listens on `127.0.0.1` only. Don't expose it on a network without adding authentication and HTTPS in front of it.
4. **Treat outputs as TLP:AMBER.** Share them on a need-to-know basis.

---

## Changing code (advanced)

Only needed when the data files can't express what you need:

| Want to… | Change | Where |
|---|---|---|
| Change the decision-tier logic | `tier()` | `cti/analyse.py` |
| Add a term to the risk score | `score()` (+ a weight in the profile) | `cti/analyse.py` |
| Change the TLP label | `BANNER`, and `TLP_AMBER` in `write_stix` | `cti/disseminate.py` |
| Add another feed | a `sync_*()` function + a table in `SCHEMA` | `cti/collect.py` |
| Add a report section | `write_reports()` | `cti/disseminate.py` |
| Change the console's port | `PORT` | `app.py` |

After any code change, run `python test_pipeline.py`. It must still print `ok`. Add an `assert` for your new behaviour next to the existing ones.

---

## Checklist

- [ ] `python test_pipeline.py` prints `ok`
- [ ] `profile.yaml`: organisation, PIRs, 5–15 threat groups for your sector and region
- [ ] `assets.csv`: internet-facing systems and crown jewels, with CPE names checked
- [ ] `third_parties.csv`: MSPs, file transfer, backup, identity providers
- [ ] `exceptions.csv`: example rows deleted
- [ ] First full sync done, NVD API key stored
- [ ] The top 10 in **Analysis** looks right to an analyst
- [ ] Daily schedule under a service account
- [ ] Folder permissions and disk encryption in place
