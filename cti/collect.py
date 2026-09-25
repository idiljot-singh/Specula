"""CTI stage 2 - Collection: pull global CVE, KEV, EPSS and ATT&CK feeds into cve.db."""
import csv, gzip, json, re, sqlite3, time
from datetime import datetime, timedelta, timezone

import requests

from cti.vault import secret

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CTID_API = "https://api.github.com/repos/center-for-threat-informed-defense/mappings-explorer/contents/mappings/kev"
MIN_KEV, MIN_EPSS = 1000, 100_000  # smaller feed = broken/poisoned download, refuse it
MIN_TECHNIQUES, MIN_MAPPINGS = 500, 500

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve  (id TEXT PRIMARY KEY, published TEXT, modified TEXT, cvss REAL,
                                 cwe TEXT, cpes TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS kev  (id TEXT PRIMARY KEY, date_added TEXT, ransomware INTEGER, vendor TEXT, product TEXT);
CREATE TABLE IF NOT EXISTS epss (id TEXT PRIMARY KEY, epss REAL, percentile REAL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS technique       (id TEXT PRIMARY KEY, name TEXT, tactics TEXT);
CREATE TABLE IF NOT EXISTS actor           (id TEXT PRIMARY KEY, name TEXT, aliases TEXT);
CREATE TABLE IF NOT EXISTS actor_technique (actor TEXT, technique TEXT, PRIMARY KEY (actor, technique));
CREATE TABLE IF NOT EXISTS actor_cve       (actor TEXT, cve TEXT, PRIMARY KEY (actor, cve));
CREATE TABLE IF NOT EXISTS cve_technique   (cve TEXT, technique TEXT, mapping_type TEXT, PRIMARY KEY (cve, technique, mapping_type));
"""
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def connect(path="cve.db"):
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    return db


def check_size(name, rows, minimum):
    if len(rows) < minimum:
        raise ValueError(f"{name} feed has {len(rows)} rows, expected >= {minimum}; keeping old data")


def parse_nvd(item):
    """One NVD 'vulnerabilities[]' item -> cve row."""
    c = item["cve"]
    m = c.get("metrics", {})
    cvss = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            cvss = m[key][0]["cvssData"]["baseScore"]
            break
    cwe = sorted({d["value"] for w in c.get("weaknesses", []) for d in w["description"]})
    cpes = [{k: v for k, v in match.items() if k != "matchCriteriaId"}
            for conf in c.get("configurations", []) for node in conf["nodes"]
            for match in node["cpeMatch"] if match["vulnerable"]]
    desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
    return (c["id"], c["published"], c["lastModified"], cvss, ",".join(cwe), json.dumps(cpes), desc)


def sync_nvd(db, api_key=None, since=None):
    """Full load on first run, then incremental by lastModified. `since` (datetime) overrides."""
    delay = 0.7 if api_key else 6.5  # NVD: 50 req/30s with key, 5 req/30s without
    headers = {"apiKey": api_key} if api_key else {}
    last = db.execute("SELECT value FROM meta WHERE key='nvd_sync'").fetchone()
    start = since or (datetime.fromisoformat(last[0]) if last else None)
    now = datetime.now(timezone.utc)

    # NVD allows max 120 days per lastMod window; no window at all = full dump
    windows = [None] if start is None else []
    while start and start < now:
        end = min(start + timedelta(days=120), now)
        windows.append((start, end))
        start = end

    for win in windows:
        params = {"resultsPerPage": 2000, "startIndex": 0}
        if win:
            params["lastModStartDate"], params["lastModEndDate"] = (d.isoformat() for d in win)
        while True:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
            if r.status_code in (403, 429, 503):  # rate limited / NVD hiccup: back off and retry
                time.sleep(30)
                continue
            r.raise_for_status()
            data = r.json()
            db.executemany("INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?,?,?)",
                           [parse_nvd(v) for v in data["vulnerabilities"]])
            db.commit()
            params["startIndex"] += data["resultsPerPage"]
            print(f"  NVD {params['startIndex']}/{data['totalResults']}")
            if params["startIndex"] >= data["totalResults"]:
                break
            time.sleep(delay)

    if since is None:  # a --since test run must not mark the full backfill as done
        db.execute("INSERT OR REPLACE INTO meta VALUES ('nvd_sync', ?)", (now.isoformat(),))
        db.commit()


def sync_kev(db):
    vulns = requests.get(KEV_URL, timeout=60).json()["vulnerabilities"]
    check_size("KEV", vulns, MIN_KEV)
    rows = [(v["cveID"], v["dateAdded"], v.get("knownRansomwareCampaignUse") == "Known",
             v["vendorProject"], v["product"]) for v in vulns]
    with db:
        db.execute("DELETE FROM kev")
        db.executemany("INSERT INTO kev VALUES (?,?,?,?,?)", rows)
    return len(rows)


def sync_epss(db):
    raw = gzip.decompress(requests.get(EPSS_URL, timeout=120).content).decode()
    lines = [l for l in raw.splitlines() if not l.startswith("#")]  # first line is model_version comment
    rows = [(r["cve"], float(r["epss"]), float(r["percentile"])) for r in csv.DictReader(lines)]
    check_size("EPSS", rows, MIN_EPSS)
    with db:
        db.execute("DELETE FROM epss")
        db.executemany("INSERT INTO epss VALUES (?,?,?)", rows)
    return len(rows)


def parse_attack(objects):
    """ATT&CK STIX objects -> (techniques, actors, actor_technique, actor_cve) rows."""
    ext = lambda o: next((r["external_id"] for r in o.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), None)
    live = {o["id"]: o for o in objects if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    techniques = [(ext(o), o["name"], ",".join(p["phase_name"] for p in o.get("kill_chain_phases", [])))
                  for o in live.values() if o["type"] == "attack-pattern"]
    actors = {sid: o for sid, o in live.items() if o["type"] == "intrusion-set"}

    # campaign -> groups it is attributed to, so campaign activity counts for the group
    attributed = {}
    for o in live.values():
        if o["type"] == "relationship" and o["relationship_type"] == "attributed-to" and o["target_ref"] in actors:
            attributed.setdefault(o["source_ref"], set()).add(o["target_ref"])
    who = lambda ref: {ref} if ref in actors else attributed.get(ref, set())

    a_tech, a_cve = set(), set()
    for o in live.values():
        if o["type"] == "relationship" and o["relationship_type"] == "uses":
            for actor in who(o["source_ref"]):
                target = live.get(o["target_ref"])
                if target and target["type"] == "attack-pattern":
                    a_tech.add((ext(actors[actor]), ext(target)))
                for cve in CVE_RE.findall(o.get("description", "")):  # "APT28 exploited CVE-2023-23397 ..."
                    a_cve.add((ext(actors[actor]), cve))
        elif o["type"] in ("intrusion-set", "campaign"):
            for actor in who(o["id"]):
                for cve in CVE_RE.findall(o.get("description", "")):
                    a_cve.add((ext(actors[actor]), cve))
    actor_rows = [(ext(o), o["name"], ",".join(o.get("aliases", []))) for o in actors.values()]
    return techniques, actor_rows, sorted(a_tech), sorted(a_cve)


def sync_attack(db):
    techniques, actors, a_tech, a_cve = parse_attack(requests.get(ATTACK_URL, timeout=120).json()["objects"])
    check_size("ATT&CK techniques", techniques, MIN_TECHNIQUES)
    with db:
        for t in ("technique", "actor", "actor_technique", "actor_cve"):
            db.execute(f"DELETE FROM {t}")
        db.executemany("INSERT INTO technique VALUES (?,?,?)", techniques)
        db.executemany("INSERT INTO actor VALUES (?,?,?)", actors)
        db.executemany("INSERT INTO actor_technique VALUES (?,?)", a_tech)
        db.executemany("INSERT INTO actor_cve VALUES (?,?)", a_cve)
    return len(techniques), len(actors), len(a_cve)


def latest_ctid_url():
    """CTID publishes KEV->ATT&CK mappings in dated folders; pick the newest ATT&CK and KEV release."""
    ls = lambda url: requests.get(url, timeout=30).json()
    attack = max((d for d in ls(CTID_API) if d["type"] == "dir"), key=lambda d: [int(x) for x in re.findall(r"\d+", d["name"])])
    kev = max(ls(f"{CTID_API}/{attack['name']}"), key=lambda d: datetime.strptime(d["name"][4:], "%m.%d.%Y"))
    files = ls(f"{CTID_API}/{attack['name']}/{kev['name']}/enterprise")
    return next(f["download_url"] for f in files if f["name"].endswith(".json"))


def sync_ctid(db):
    maps = requests.get(latest_ctid_url(), timeout=120).json()["mapping_objects"]
    rows = {(m["capability_id"], m["attack_object_id"], m["mapping_type"]) for m in maps if m.get("attack_object_id")}
    check_size("CTID KEV mappings", rows, MIN_MAPPINGS)
    with db:
        db.execute("DELETE FROM cve_technique")
        db.executemany("INSERT INTO cve_technique VALUES (?,?,?)", rows)
    return len(rows)


def main(db_path="cve.db", since=None):
    db = connect(db_path)
    print(f"KEV:  {sync_kev(db)} known-exploited CVEs")
    print(f"EPSS: {sync_epss(db)} scored CVEs")
    t, a, c = sync_attack(db)
    print(f"ATT&CK: {t} techniques, {a} groups, {c} group->CVE links")
    print(f"CTID: {sync_ctid(db)} CVE->technique mappings")
    print("NVD:  syncing (first full run takes ~15 min without an API key)")
    sync_nvd(db, secret("NVD_API_KEY"), since)
    print(f"NVD:  {db.execute('SELECT COUNT(*) FROM cve').fetchone()[0]} CVEs in db")
