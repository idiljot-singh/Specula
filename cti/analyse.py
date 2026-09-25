"""CTI stage 4 - Analysis: explainable risk score, threat profile and SSVC tier per finding.

likelihood = w.epss*EPSS + w.kev*inKEV + w.ransomware*ransomware + w.threat_profile*overlap
             overlap = 1.0 if a profiled group is known to exploit the CVE
                     = 0.5 if the CVE enables ATT&CK techniques a profiled group uses
impact     = CVSS/10 * weight * exposure
             weight = criticality (1-3) for owned assets
                    = blast radius (1-3) for third parties: data access x privileged
risk       = likelihood * impact
All weights and thresholds come from profile.yaml.
"""
CVSS_UNKNOWN = 5.0  # NVD not yet scored: assume medium, say so in the reasons


def load_threat(db, profile):
    """Everything the threat profile needs, read once from cve.db."""
    groups = profile["threat_groups"]
    q = ",".join("?" * len(groups))
    known = {g for (g,) in db.execute(f"SELECT id FROM actor WHERE id IN ({q})", list(groups))}
    unknown = set(groups) - known
    if unknown and db.execute("SELECT COUNT(*) FROM actor").fetchone()[0]:
        print(f"  warning: not in ATT&CK, ignored: {', '.join(sorted(unknown))}")

    cited = {}  # cve -> [group names that exploited it]
    for g, cve in db.execute(f"SELECT actor, cve FROM actor_cve WHERE actor IN ({q})", list(groups)):
        cited.setdefault(cve, []).append(groups[g])
    used = {}   # technique -> [profiled group names using it]
    for g, t in db.execute(f"SELECT actor, technique FROM actor_technique WHERE actor IN ({q})", list(groups)):
        used.setdefault(t, []).append(groups[g])
    techniques = {}  # cve -> [(technique id, name, tactics)]
    for cve, tid, name, tactics in db.execute("""
            SELECT DISTINCT m.cve, t.id, t.name, t.tactics
            FROM cve_technique m JOIN technique t ON t.id = m.technique"""):
        techniques.setdefault(cve, []).append((tid, name, tactics))
    return {"cited": cited, "used": used, "techniques": techniques}


def blast_radius(a, p):
    tp = p["third_party"]
    return tp["data_access"][a["data_access"]] * (tp["privileged"] if a["privileged"] else 1.0)


def tier(f, weight, exploited, p):
    t = p["tiers"]
    if exploited and (f["asset"]["internet_facing"] or weight >= 3):
        return "Act"
    if exploited or f["epss"] >= t["attend_epss"]:
        return "Attend"
    if f["epss"] >= t["track_epss"] or (f["cvss"] or 0) >= t["track_cvss"]:
        return "Track"
    return "Ignore"


def score(f, p, threat):
    a, w = f["asset"], p["weights"]
    cited = threat["cited"].get(f["cve"], [])
    techs = threat["techniques"].get(f["cve"], [])
    shared = sorted({g for tid, _, _ in techs for g in threat["used"].get(tid, [])})
    overlap = 1.0 if cited else 0.5 if shared else 0.0

    likelihood = w["epss"] * f["epss"] + w["kev"] * f["kev"] + w["ransomware"] * f["ransomware"] + w["threat_profile"] * overlap
    cvss = f["cvss"] if f["cvss"] is not None else CVSS_UNKNOWN
    weight = blast_radius(a, p) if a["third_party"] else a["criticality"]
    impact = cvss / 10 * weight * p["exposure"]["internet" if a["internet_facing"] else "internal"]

    why = [f"EPSS {f['epss']:.2f}"]
    if f["kev"]: why.append("KEV: exploited in the wild")
    if f["ransomware"]: why.append("used by ransomware")
    if cited: why.append(f"exploited by {', '.join(sorted(set(cited)))} (threat profile)")
    elif shared: why.append(f"enables techniques used by {len(shared)} profiled groups")
    why.append(f"CVSS {f['cvss']}" if f["cvss"] is not None else "CVSS n/a (assumed 5.0)")
    if a["third_party"]:
        why.append(f"third party ({a['type']}, {a['data_access']} data"
                   f"{', privileged access' if a['privileged'] else ''}): blast radius {weight:g}")
    else:
        why.append(f"criticality {a['criticality']}")
    if a["internet_facing"]: why.append("internet-facing")
    if not a["version"]:
        why.append(f"version unknown: recent CVEs only ({p['third_party']['recent_days']} days)" if a["third_party"]
                   else "version unknown: assumed affected")

    return {**f, "likelihood": round(likelihood, 3), "impact": round(impact, 3),
            "risk": round(likelihood * impact, 3), "tier": tier(f, weight, f["kev"] or bool(cited), p),
            "cited_by": sorted(set(cited)), "techniques": techs, "why": "; ".join(why)}


def rank(findings, p, threat):
    return sorted((score(f, p, threat) for f in findings), key=lambda r: (-r["risk"], r["cve"]))
