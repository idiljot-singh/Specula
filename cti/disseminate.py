"""CTI stage 5 - Dissemination: CSV (tools), Markdown (people), STIX 2.1 (sharing), HTML dashboard."""
import collections, csv, html, json, uuid
from datetime import date
from pathlib import Path

import stix2

BANNER = "**TLP:AMBER**: limited disclosure, organisation and clients on a need-to-know basis only."
TIERS = ["Act", "Attend", "Track", "Ignore"]
TIER_ACTION = {"Act": "patch or mitigate within 48 h", "Attend": "next patch cycle",
               "Track": "watch for exploitation", "Ignore": "no action"}


def table(rows, top):
    md = ["| # | Tier | Risk | CVE | Asset | Why |", "|---|---|---|---|---|---|"]
    md += [f"| {i} | {r['tier']} | {r['risk']} | [{r['cve']}](https://nvd.nist.gov/vuln/detail/{r['cve']}) | {r['asset']['name']} | {r['why']} |"
           for i, r in enumerate(rows[:top], 1)]
    return md if rows else ["None."]


def write_reports(ranked, out_dir, profile, top=50, suppressed=(), expired=()):
    out = Path(out_dir)
    out.mkdir(exist_ok=True)

    with open(out / "report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rank", "tier", "risk", "cve", "asset", "source", "kev", "ransomware", "epss", "cvss",
                    "likelihood", "impact", "exploited_by", "techniques", "why"])
        for i, r in enumerate(ranked, 1):
            w.writerow([i, r["tier"], r["risk"], r["cve"], r["asset"]["name"],
                        "third-party" if r["asset"]["third_party"] else "owned", r["kev"], r["ransomware"],
                        r["epss"], r["cvss"], r["likelihood"], r["impact"], ";".join(r["cited_by"]),
                        ";".join(t[0] for t in r["techniques"]), r["why"]])

    owned = [r for r in ranked if not r["asset"]["third_party"]]
    third = [r for r in ranked if r["asset"]["third_party"]]
    tiers = collections.Counter(r["tier"] for r in ranked)
    urgent = [r for r in ranked if r["tier"] in ("Act", "Attend")]

    per_asset = collections.defaultdict(collections.Counter)
    for r in ranked:
        per_asset[r["asset"]["name"]][r["tier"]] += 1

    # ATT&CK view: what an attacker achieves through our urgent CVEs
    tactics = collections.defaultdict(set)
    for r in urgent:
        for tid, name, tacs in r["techniques"]:
            for tac in filter(None, tacs.split(",")):
                tactics[tac].add(f"{tid} {name}")
    cited = collections.Counter(g for r in ranked for g in r["cited_by"])

    org = profile["organisation"]
    md = [f"# CVE Priority Report: {org['name']}, {date.today()}", "", BANNER, "",
          f"Threat profile: {org['sector']}, {org['country']}; {len(profile['threat_groups'])} tracked threat groups.", "",
          "## Decision summary", "", "| Tier | Findings | Action |", "|---|---|---|"]
    md += [f"| **{t}** | {tiers[t]} | {TIER_ACTION[t]} |" for t in TIERS]
    md += ["", f"- **Owned assets:** {len(owned)} CVEs, and {sum(r['kev'] for r in owned)} of them are known-exploited (KEV).",
           f"- **Third parties:** {len(third)} recent CVEs in supplier products, and {sum(r['kev'] for r in third)} of them are known-exploited.",
           "", "## Per asset", "", "| Asset | " + " | ".join(TIERS) + " |", "|---|---|---|---|---|"]
    md += [f"| {name} | " + " | ".join(str(c[t]) for t in TIERS) + " |"
           for name, c in sorted(per_asset.items(), key=lambda x: (-x[1]["Act"], -x[1]["Attend"]))]
    md += ["", "## Threat profile hits", "",
           "Profiled groups known (per MITRE ATT&CK) to exploit CVEs present in our estate:", ""]
    md += [f"- **{g}**: {n} finding(s)" for g, n in cited.most_common()] or ["- None."]
    md += ["", "## ATT&CK view of Act + Attend findings", "",
           "What an attacker could achieve through our urgent vulnerabilities (CTID KEV→ATT&CK mappings):", "",
           "| Tactic | Techniques |", "|---|---|"]
    md += [f"| {tac} | {', '.join(sorted(ts))} |" for tac, ts in sorted(tactics.items())] or ["| n/a | no mapped techniques |"]
    md += ["", f"## Owned assets: top {top} by risk", ""] + table(owned, top)
    md += ["", "## Third-party risk", "",
           "CVEs in products our suppliers run for us. We can't patch these ourselves. "
           "**Action:** ask the supplier to confirm the patch status, and restrict their access until they do.", ""]
    md += table(third, top)
    md += ["", "## Feedback: exceptions", "",
           f"{len(suppressed)} findings suppressed by analyst decisions in `exceptions.csv`.", ""]
    if suppressed:
        md += ["| CVE | Asset | Status | Until | Note |", "|---|---|---|---|---|"]
        md += [f"| {r['cve']} | {r['asset']['name']} | {r['exception']['status']} | {r['exception']['until'] or 'no expiry'} "
               f"| {r['exception'].get('note', '')} |" for r in suppressed]
    if expired:
        md += ["", f"**{len(expired)} exception(s) expired; those findings are back in the ranking for review:** "
               + ", ".join(f"{e['cve']} ({e['asset']}, until {e['until']})" for e in expired)]
    (out / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def write_brief(text, source, out_dir, profile):
    """Management brief. LLM output is display-only: it is labelled as such and nothing reads it back."""
    label = ("Generated from a fixed template (no AI)." if source.startswith("template")
             else f"**AI-generated draft ({source}). Verify against report.md before sending.**")
    md = [f"# Weekly CVE Brief: {profile['organisation']['name']}, {date.today()}", "", BANNER, "", label, "", text, ""]
    (Path(out_dir) / "brief.md").write_text("\n".join(md), encoding="utf-8")


# --- STIX 2.1 ---------------------------------------------------------------
NS = uuid.UUID("6f0c2b43-2a55-4c1e-9d3e-5b1c1a7e2f10")  # fixed namespace -> same object, same id every run


def sid(kind, key):
    """Deterministic STIX id, so re-importing into MISP/OpenCTI updates objects instead of duplicating them."""
    return f"{kind}--{uuid.uuid5(NS, key)}"


def write_stix(ranked, out_dir, profile, tiers=("Act", "Attend")):
    org = profile["organisation"]
    me = stix2.Identity(id=sid("identity", org["name"]), name=org["name"], identity_class="organization",
                        object_marking_refs=[stix2.TLP_AMBER])
    common = {"created_by_ref": me.id, "object_marking_refs": [stix2.TLP_AMBER]}
    group_ids = {name: gid for gid, name in profile["threat_groups"].items()}
    objs, rels = {me.id: me}, {}

    def add(obj):
        objs.setdefault(obj.id, obj)
        return obj.id

    def rel(src, kind, dst, **kw):
        r = stix2.Relationship(id=sid("relationship", f"{src}|{kind}|{dst}"), source_ref=src,
                               relationship_type=kind, target_ref=dst, **common, **kw)
        rels.setdefault(r.id, r)

    for r in (r for r in ranked if r["tier"] in tiers):
        vuln = add(stix2.Vulnerability(
            id=sid("vulnerability", r["cve"]), name=r["cve"], description=(r["description"] or "")[:1000],
            external_references=[{"source_name": "cve", "external_id": r["cve"]}], **common))
        a = r["asset"]
        owner = f"Supplier-operated ({a['type']})" if a["third_party"] else "Owned"
        infra = add(stix2.Infrastructure(id=sid("infrastructure", a["name"]), name=a["name"],
                                         description=f"{owner}: {a['cpe']} {a['version']}".strip(), **common))
        rel(infra, "has", vuln, description=f"{r['tier']} | risk {r['risk']} | {r['why']}")
        for g in r["cited_by"]:
            ref = [{"source_name": "mitre-attack", "external_id": group_ids[g]}] if g in group_ids else None
            rel(add(stix2.IntrusionSet(id=sid("intrusion-set", g), name=g, external_references=ref, **common)), "targets", vuln)
        for tid, name, _ in r["techniques"]:
            ap = stix2.AttackPattern(id=sid("attack-pattern", tid), name=name, **common,
                                     external_references=[{"source_name": "mitre-attack", "external_id": tid}])
            rel(add(ap), "targets", vuln)

    bundle = stix2.Bundle(objects=[stix2.TLP_AMBER, *objs.values(), *rels.values()])
    (Path(out_dir) / "bundle.json").write_text(bundle.serialize(pretty=True), encoding="utf-8")
    return len(objs) + len(rels)


# --- HTML dashboard ---------------------------------------------------------
def write_dashboard(ranked, out_dir, profile):
    rows = [{"tier": r["tier"], "risk": r["risk"], "cve": r["cve"], "asset": r["asset"]["name"],
             "source": "third-party" if r["asset"]["third_party"] else "owned", "kev": r["kev"],
             "epss": round(r["epss"], 3), "cvss": r["cvss"], "groups": ", ".join(r["cited_by"]), "why": r["why"]}
            for r in ranked]
    # data goes into a <script> block: escape "</" so hostile feed text can't close the tag
    data = json.dumps(rows).replace("</", "<\\/")
    page = (DASHBOARD.replace("__ORG__", html.escape(profile["organisation"]["name"]))
            .replace("__DATE__", str(date.today())).replace("__DATA__", data))
    (Path(out_dir) / "dashboard.html").write_text(page, encoding="utf-8")


DASHBOARD = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
