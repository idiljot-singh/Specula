"""CTI stage 2 - Collection: owned assets straight from Microsoft Defender for Endpoint.

Replaces hand-maintained assets.csv rows with the live software inventory, and uses Defender's own
per-device vulnerability list so already-patched CVEs drop out.

One-time setup (tenant admin):
  1. Entra ID > App registrations > New: "stenwatch"
  2. API permissions > APIs my organization uses > WindowsDefenderATP > Application:
     Software.Read.All, Vulnerability.Read.All, Machine.Read.All  (read-only) > Grant admin consent
  3. Certificates & secrets > upload a certificate (no client secret). Keep the private key readable
     only by the service account that runs the pipeline.
  4. Fill the `defender:` block in profile.yaml and set enabled: true
"""
import collections

import requests

API = "https://api.securitycenter.microsoft.com/api"
SCOPE = ["https://api.securitycenter.microsoft.com/.default"]
DEVICE_VALUE = {"Low": 1, "Normal": 2, "High": 3}  # Defender "device value" -> our criticality
INTERNET_TAG = "internet-facing"                      # tag internet-facing devices in Defender with this


def token(cfg):
    import msal  # only needed when Defender is enabled
    with open(cfg["certificate"], encoding="utf-8") as f:
        key = f.read()
    app = msal.ConfidentialClientApplication(
        cfg["client_id"], authority=f"https://login.microsoftonline.com/{cfg['tenant_id']}",
        client_credential={"private_key": key, "thumbprint": cfg["thumbprint"]})
    result = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in result:
        raise RuntimeError(f"Defender auth failed: {result.get('error_description', result)}")
    return result["access_token"]


def get_all(url, headers):
    """Follow @odata.nextLink paging."""
    rows = []
    while url:
        r = requests.get(url, headers=headers, timeout=120)
        r.raise_for_status()
        body = r.json()
        rows += body["value"]
        url = body.get("@odata.nextLink")
    return rows


def to_assets(machines, inventory, vulns):
    """Defender rows -> asset dicts, one per (vendor, product, version) across the fleet.

    Defender names software '<vendor>-_-<product>' in the same vocabulary as NVD CPEs,
    so microsoft / exchange_server maps straight to cpe:2.3:a:microsoft:exchange_server.
    """
    dev = {m["id"]: m for m in machines}
    cves = collections.defaultdict(set)
    for v in vulns:
        cves[(v["softwareVendor"], v["softwareName"], v["softwareVersion"])].add(v["cveId"])

    groups = collections.defaultdict(set)
    for row in inventory:
        groups[(row["softwareVendor"], row["softwareName"], row["softwareVersion"])].add(row["deviceId"])

    assets = []
    for (vendor, name, version), devices in sorted(groups.items()):
        ms = [dev[d] for d in devices if d in dev]
        # ponytail: part guessed from the name ('o' for Windows OS, else 'a'); fine for Microsoft estates
        part = "o" if name.startswith("windows") else "a"
        assets.append({
            "name": f"{name} {version} ({len(devices)} devices)",  # no hostnames: they never leave Defender
            "cpe": f"cpe:2.3:{part}:{vendor}:{name}", "version": version or "",
            "criticality": max((DEVICE_VALUE.get(m.get("deviceValue"), 2) for m in ms), default=2),
            "internet_facing": any(INTERNET_TAG in [t.lower() for t in m.get("machineTags", [])] for m in ms),
            "third_party": False,
            "only_cves": cves.get((vendor, name, version), set()),  # Defender knows the patch level
        })
    return assets


def fetch_assets(cfg):
    headers = {"Authorization": f"Bearer {token(cfg)}"}
    machines = get_all(f"{API}/machines", headers)
    inventory = get_all(f"{API}/machines/SoftwareInventoryByMachine?pageSize=100000", headers)
    vulns = get_all(f"{API}/machines/SoftwareVulnerabilitiesByMachine?pageSize=100000", headers)
    return to_assets(machines, inventory, vulns)
