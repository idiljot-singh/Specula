"""Stenwatch: run the CTI pipeline.

python run.py                        collect feeds, match assets.csv (+ third_parties.csv), write out/
python run.py --skip-collect         reuse cve.db as-is (fast, for trying out assets.csv or profile.yaml changes)
python run.py --example              run the bundled Example Organisation (*.example.* files) into out/example/
python run.py --since 2026-09-01     only pull CVEs modified since that date (quick test)
python run.py --suggest-cpe exchange which NVD product names match 'exchange'? (fills the cpe column)
"""
import argparse, collections
from datetime import datetime, timezone
from pathlib import Path

import yaml

from cti import analyse, collect, disseminate, llm, process

ROOT = Path(__file__).parent  # files live next to run.py, wherever it's launched from
DB, OUT, LOG = ROOT / "cve.db", ROOT / "out", ROOT / "run.log"
ASSETS, THIRD, PROFILE = ROOT / "assets.csv", ROOT / "third_parties.csv", ROOT / "profile.yaml"
EXCEPTIONS = ROOT / "exceptions.csv"


def audit(line):
    """One line per run in run.log, success or failure: when, what data, what came out."""
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {line}\n")


def pipeline(args):
    if not args.skip_collect:
        since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc) if args.since else None
        collect.main(DB, since=since)

    if not ASSETS.exists():
        raise SystemExit(f"No {ASSETS.name}: copy assets.example.csv to assets.csv and list your software")

    if not PROFILE.exists():
        raise SystemExit(f"No {PROFILE.name}: copy profile.example.yaml to profile.yaml and describe your organisation (see CUSTOMISE.md)")
    profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    db = collect.connect(DB)
    assets = process.load_assets(ASSETS)
    if profile.get("defender", {}).get("enabled"):
        from cti import defender
        live = defender.fetch_assets(profile["defender"])
        print(f"Defender: {len(live)} software/version groups from the device fleet")
        assets += live
    if THIRD.exists():
        assets += process.load_assets(THIRD, third_party=True)
    print(f"Processing: matching {len(assets)} assets and suppliers against {db.execute('SELECT COUNT(*) FROM cve').fetchone()[0]} CVEs")
    findings = process.match(db, assets, profile["third_party"]["recent_days"])
    print(f"Analysis: scoring {len(findings)} findings against the threat profile")
    ranked = analyse.rank(findings, profile, analyse.load_threat(db, profile))

    print("Feedback: applying exceptions.csv")
    exceptions = process.load_exceptions(EXCEPTIONS)
    ranked, suppressed = process.apply_exceptions(ranked, exceptions)
    expired = [e for e in exceptions if e["until"] and e["until"] < str(datetime.now().date())]
    print(f"Dissemination: writing {len(ranked)} ranked findings ({len(suppressed)} suppressed)")
    disseminate.write_reports(ranked, OUT, profile, suppressed=suppressed, expired=expired)
    n = disseminate.write_stix(ranked, OUT, profile)
    disseminate.write_dashboard(ranked, OUT, profile)
    o = profile["organisation"]
    text, source = llm.brief(ranked, profile.get("llm", {}), names=[a["name"] for a in assets] + [o["name"]],
                             org=f"a {o['sector']} organisation in {o['country']}")
    disseminate.write_brief(text, source, OUT, profile)
    print(f"Report: {len(ranked)} findings -> {OUT}: report.md, report.csv, dashboard.html, bundle.json, brief.md")

    count = lambda t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    tiers = collections.Counter(r["tier"] for r in ranked)
    audit(f"OK collect={'skipped' if args.skip_collect else 'yes'} "
          f"feeds=cve:{count('cve')},kev:{count('kev')},epss:{count('epss')},attack:{count('technique')},ctid:{count('cve_technique')} "
          f"assets={len(assets)} findings={len(ranked)} "
          f"tiers=" + ",".join(f"{t}:{tiers[t]}" for t in disseminate.TIERS) +
          f" suppressed={len(suppressed)} expired={len(expired)} stix={n} brief={source}")


p = argparse.ArgumentParser()
p.add_argument("--since", help="only pull CVEs modified since this date (skip the full NVD backfill)")
p.add_argument("--skip-collect", action="store_true")
p.add_argument("--suggest-cpe", metavar="TERM")
p.add_argument("--example", action="store_true")
args = p.parse_args()
if args.example:
    ASSETS, THIRD, PROFILE, EXCEPTIONS = (f.with_name(f.name.replace(".", ".example.", 1)) for f in (ASSETS, THIRD, PROFILE, EXCEPTIONS))
    OUT = OUT / "example"

if args.suggest_cpe:
    for prefix, n in process.suggest_cpe(collect.connect(DB), args.suggest_cpe):
        print(f"{n:6}  {prefix}")
    raise SystemExit

try:
    pipeline(args)
except BaseException as e:  # a scheduled run that dies must leave a trace
    if not (isinstance(e, SystemExit) and e.code in (0, None)):
        audit(f"FAILED {type(e).__name__}: {e}")
    raise
