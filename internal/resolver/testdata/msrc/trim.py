"""Trim real MSRC CVRF monthly documents into small test fixtures.

Usage: python3 trim.py <dir with <YYYY-Mon>.json from
https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-Mon>> <output dir>

Keeps the Windows OS products, a few CVEs per product per month (greedy
coverage, plus the anomalies the harness needs) and only Vendor Fix
remediations. The output feeds windows_harness_test.go.
"""
import json, sys, os, re

SRC, OUT = sys.argv[1], sys.argv[2]
MONTHS = ["2023-Jan", "2023-Oct", "2023-Dec", "2024-Oct", "2025-Dec", "2026-Jul", "2026-Aug", "2026-Sep", "2026-Oct"]
# Forced CVEs per month: anomalies the harness must cover.
FORCE = {
    "2023-Oct": ["CVE-2023-35349"],  # Windows 10 21H2 fixed as 10.0.19041.x
    "2023-Dec": ["CVE-2023-35639"],  # Windows 11 23H2 fixed as 10.0.22621.x
    "2025-Dec": ["CVE-2025-64679"],  # regular update only, in a hotpatch month
}
SKIP_KEYS = re.compile(r"hlk|adk|driver_kit|windows_rt|windows_server_(1903|1909|2004|20h2)")
PER_KEY = 2

def osprods(doc):
    out = {}
    for p in doc["ProductTree"]["FullProductName"]:
        cpe = p.get("CPE") or ""
        parts = cpe.split(":")
        if len(parts) < 12 or parts[2] != "o" or parts[3] != "microsoft" or not parts[4].startswith("windows"):
            continue
        key = parts[4].lower()
        if SKIP_KEYS.search(key):
            continue
        out[p["ProductID"]] = (key, p)
    return out

def fixes(v, prods):
    """(pid, remediation) pairs for Windows OS vendor fixes with a FixedBuild."""
    res = []
    for r in v.get("Remediations") or []:
        if r.get("Type") != 2 or not (r.get("FixedBuild") or "").strip():
            continue
        for pid in r.get("ProductID") or []:
            if pid in prods:
                res.append((pid, r))
    return res

for m in MONTHS:
    doc = json.load(open(os.path.join(SRC, m + ".json")))
    prods = osprods(doc)
    keys = sorted({k for k, _ in prods.values()})
    vulns = {v["CVE"]: v for v in doc["Vulnerability"] if (v.get("CVE") or "").startswith("CVE-")}
    chosen = list(FORCE.get(m, []))
    count = {k: 0 for k in keys}
    def credit(cve):
        for k in {prods[pid][0] for pid, _ in fixes(vulns[cve], prods)}:
            count[k] += 1
    for c in chosen:
        credit(c)
    want_hot = m in ("2026-Aug", "2025-Dec")
    # Prefer CVEs with hotpatch rows in hotpatch months, then broad coverage,
    # plus one CVE that has a regular fix but no hotpatch fix for 24H2.
    def score(cve):
        fx = fixes(vulns[cve], prods)
        ks = {prods[pid][0] for pid, _ in fx}
        gain = sum(1 for k in ks if count[k] < PER_KEY)
        hot = any("otpatch" in (r.get("SubType") or "") for _, r in fx)
        return (gain, hot if want_hot else 0, cve)
    cands = sorted(vulns)
    while any(c < PER_KEY for k, c in count.items() if any(prods[p][0] == k for p, _ in sum((fixes(vulns[x], prods) for x in cands), []))):
        best = max((c for c in cands if c not in chosen), key=score, default=None)
        if best is None or score(best)[0] == 0:
            break
        chosen.append(best)
        credit(best)
    if m == "2023-Dec":
        # An IE Cumulative "1.003" style FixedBuild on Server 2012.
        for cve in cands:
            if cve not in chosen and any(r.get("FixedBuild", "").startswith("1.") for _, r in fixes(vulns[cve], prods)):
                chosen.append(cve)
                break
    if m == "2026-Jul":
        # Listed for Server 2022 Desktop Experience but not Server Core.
        core = {p for p, (k, pp) in prods.items() if k == "windows_server_2022" and "Server Core" in pp["Value"]}
        full = {p for p, (k, pp) in prods.items() if k == "windows_server_2022" and "Server Core" not in pp["Value"]}
        for cve in cands:
            pids = {p for p, _ in fixes(vulns[cve], prods)}
            if cve not in chosen and pids & full and not pids & core:
                chosen.append(cve)
                break
    used = set()
    out_v = []
    for cve in chosen:
        v = vulns[cve]
        rems = []
        for r in v.get("Remediations") or []:
            if r.get("Type") != 2:
                continue
            pids = [p for p in r.get("ProductID") or [] if p in prods]
            if not pids:
                continue
            used.update(pids)
            rems.append({k: r.get(k) for k in ("Description", "URL", "Supercedence", "ProductID", "Type", "SubType", "FixedBuild", "RestartRequired")} | {"ProductID": pids})
        threats = []
        for t in v.get("Threats") or []:
            if t.get("Type") != 3:
                continue
            pids = [p for p in t.get("ProductID") or [] if p in prods]
            if pids:
                threats.append({"Type": 3, "Description": t["Description"], "ProductID": pids})
        out_v.append({"Title": v.get("Title"), "CVE": cve, "ReleaseDate": v.get("ReleaseDate"), "Threats": threats, "Remediations": rems})
    tree = [{"ProductID": p, "CPE": prods[p][1]["CPE"], "Value": prods[p][1]["Value"]} for p in sorted(used)]
    out = {
        "DocumentTracking": {"Identification": {"ID": {"Value": m}}, "CurrentReleaseDate": doc["DocumentTracking"]["CurrentReleaseDate"]},
        "ProductTree": {"FullProductName": tree},
        "Vulnerability": out_v,
    }
    with open(os.path.join(OUT, m + ".json"), "w") as f:
        json.dump(out, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")
    print(m, len(chosen), "cves", len(tree), "products", sorted(count.items()))
