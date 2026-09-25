"""CTI stage 3 - Processing: match every CVE in cve.db to the assets we own and the suppliers we use."""
import collections, csv, json, re
from datetime import date, timedelta

YES = ("y", "yes", "true", "1")


def load_assets(path, third_party=False):
    """assets.csv (owned) or third_parties.csv (vendors, SaaS, MSPs) -> list of dicts."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for a in rows:
        a["cpe"] = a["cpe"].strip().rstrip(":")  # cpe:2.3:<part>:<vendor>:<product>
        if a["cpe"].count(":") != 4:
            raise ValueError(f"{a['name']}: cpe must look like cpe:2.3:a:vendor:product, got {a['cpe']!r}")
        a["version"] = a["version"].strip()
        a["internet_facing"] = a["internet_facing"].strip().lower() in YES
        a["third_party"] = third_party
        if third_party:
            a["data_access"] = a["data_access"].strip().lower()
            a["privileged"] = a["privileged"].strip().lower() in YES
        else:
            a["criticality"] = int(a["criticality"])
    return rows


EXCEPTION_STATUS = ("patched", "mitigated", "accepted", "false_positive", "not_affected")


def load_exceptions(path):
    """exceptions.csv: analyst decisions that feed back into the next run (CTI stage 6 - Feedback)."""
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for e in rows:
        e["status"] = e["status"].strip().lower()
        if e["status"] not in EXCEPTION_STATUS:
            raise ValueError(f"exceptions.csv: {e['cve']}: status must be one of {', '.join(EXCEPTION_STATUS)}")
        e["asset"] = e["asset"].strip() or "*"
        e["until"] = e.get("until", "").strip()
    return rows


def apply_exceptions(ranked, exceptions, today=None):
    """-> (kept, suppressed). An exception past its `until` date stops applying: risk comes back for review."""
    today = (today or date.today()).isoformat()
    live = [e for e in exceptions if not e["until"] or e["until"] >= today]
    kept, suppressed = [], []
    for r in ranked:
        hit = next((e for e in live if e["cve"] == r["cve"] and e["asset"] in ("*", r["asset"]["name"])), None)
        (suppressed if hit else kept).append({**r, "exception": hit} if hit else r)
    return kept, suppressed


def suggest_cpe(db, term):
    """Which vendor:product names does NVD use for `term`? Helps fill the cpe column once per asset."""
    counts = collections.Counter()
    for (cpes,) in db.execute("SELECT cpes FROM cve WHERE cpes LIKE ?", (f"%{term}%",)):
        for m in json.loads(cpes):
            prefix = ":".join(m["criteria"].split(":")[:5])
            if term.lower() in prefix.lower():
                counts[prefix] += 1
    return counts.most_common(15)


def vkey(v):
    """'10.0.17763.5000' -> comparable tuple. Numbers compare as numbers, text as text."""
    # ponytail: generic version compare, vendor-specific schemes (e.g. '2.8_mr10') compare as text
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.\-_]", v.lower()) if p]


def affects(m, version):
    """Does one NVD cpeMatch entry cover this asset version?"""
    if not version:
        return True  # unknown version: assume affected, report says so
    v = m["criteria"].split(":")[5]
    if v not in ("*", "-"):
        # ponytail: CPE 'update' field (e.g. Exchange cumulative_update_14) ignored -> may over-match within a release
        return vkey(v) == vkey(version)
    x = vkey(version)
    return not (
        ("versionStartIncluding" in m and x < vkey(m["versionStartIncluding"]))
        or ("versionStartExcluding" in m and x <= vkey(m["versionStartExcluding"]))
        or ("versionEndIncluding" in m and x > vkey(m["versionEndIncluding"]))
        or ("versionEndExcluding" in m and x >= vkey(m["versionEndExcluding"]))
    )


def match(db, assets, recent_days=90, today=None):
    """-> list of findings: one per (asset, CVE), joined with KEV and EPSS.

    Third party with unknown version: we can't see their patch level, so only CVEs published or
    added to KEV in the last `recent_days` count, the "is my supplier under attack now?" question.
    """
    # ponytail: one LIKE full-scan per asset (~0.5 s each); add a cpe index table past ~100 assets
    cutoff = ((today or date.today()) - timedelta(days=recent_days)).isoformat()
    findings = []
    for a in assets:
        sql = """
            SELECT c.id, c.cvss, c.cwe, c.cpes, c.description, e.epss, k.id IS NOT NULL, k.ransomware
            FROM cve c LEFT JOIN epss e USING(id) LEFT JOIN kev k USING(id) WHERE """
        defender = a.get("only_cves")  # Defender already decided which CVEs apply at this patch level
        if defender is not None:
            if not defender:
                continue
            sql += f"c.id IN ({','.join('?' * len(defender))})"
            params = sorted(defender)
        else:
            sql += "c.cpes LIKE ?"
            params = [f'%"{a["cpe"]}:%']
        if a["third_party"] and not a["version"]:
            sql += " AND (c.published >= ? OR k.date_added >= ?)"
            params += [cutoff, cutoff]
        rows = db.execute(sql, params)
        for cid, cvss, cwe, cpes, desc, epss, in_kev, ransomware in rows:
            if defender is not None or any(m["criteria"].startswith(a["cpe"] + ":") and affects(m, a["version"])
                                           for m in json.loads(cpes)):
                findings.append({"asset": a, "cve": cid, "cvss": cvss, "cwe": cwe, "description": desc,
                                 "epss": epss or 0.0, "kev": bool(in_kev), "ransomware": bool(ransomware)})
    return findings
