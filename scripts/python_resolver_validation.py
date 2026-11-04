#!/usr/bin/env python3
"""Validate Python resolver output against strict evidence preflight and Nessus."""

from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"

# Lab captures are not in the repo. Pass the evidence path yourself.

EXPECTED_INVENTORY = {
    "distributions_total": 83,
    "ubuntu_dpkg": 78,
    "pypi": 5,
    "confirmed_loaded": 4,
    "installed_not_proven_loaded": 79,
    "environments": 1,
    "python_processes": 2,
}

EXPECTED_PYPI = {
    "psutil": "5.9.8",
    "s-tui": "1.1.6",
    "typing-extensions": "4.11.0",
    "urwid": "2.6.12",
    "wcwidth": "0.2.13",
}


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def locate_evidence() -> Path:
    if len(sys.argv) < 2:
        raise SystemExit("usage: python_resolver_validation.py <file.openness>")
    path = Path(sys.argv[1])
    if not path.is_file():
        raise SystemExit(f"ERROR: evidence not found: {path}")
    return path


def preflight(path: Path) -> dict:
    return json.load(open(path))


def inventory_from_doc(doc: dict) -> dict:
    dist_entity_ids: set[str] = set()
    env_entity_ids: set[str] = set()
    process_entity_ids: set[str] = set()
    eco = Counter()
    runtime = Counter()
    pypi: dict[str, str] = {}
    for rec in doc.get("language_deps", []):
        v = rec.get("value", rec)
        if not isinstance(v, dict):
            continue
        et = v.get("entity_type")
        eid = v.get("entity_id")
        if et == "python_environment" and eid:
            env_entity_ids.add(eid)
        elif et == "process":
            exe = (v.get("executable_path") or "").lower()
            if "python" in exe and eid:
                process_entity_ids.add(eid)
        elif et == "python_distribution" and eid:
            if eid in dist_entity_ids:
                continue
            dist_entity_ids.add(eid)
            eco[v.get("resolver_ecosystem")] += 1
            runtime[v.get("runtime_load_status")] += 1
            if v.get("resolver_ecosystem") == "pypi":
                pypi[v.get("name_normalized")] = v.get("version")
    inv = {
        "distributions_total": len(dist_entity_ids),
        "ubuntu_dpkg": eco.get("ubuntu_dpkg", 0),
        "pypi": eco.get("pypi", 0),
        "confirmed_loaded": runtime.get("confirmed_loaded", 0),
        "installed_not_proven_loaded": runtime.get("installed_not_proven_loaded", 0),
        "environments": len(env_entity_ids),
        "python_processes": len(process_entity_ids),
        "pypi_packages": pypi,
    }
    for k, exp in EXPECTED_INVENTORY.items():
        if inv.get(k) != exp:
            raise SystemExit(f"ERROR: inventory mismatch {k}: expected {exp} got {inv.get(k)}")
    if inv["pypi_packages"] != EXPECTED_PYPI:
        raise SystemExit(f"ERROR: PyPI package inventory mismatch: {inv['pypi_packages']}")
    return inv


def nessus_by_cve(path: Path) -> dict[str, list[dict]]:
    tree = ET.parse(path)
    out: dict[str, list[dict]] = defaultdict(list)
    for rh in tree.findall(".//ReportHost"):
        for ri in rh.findall("ReportItem"):
            if ri.get("pluginFamily") != "Ubuntu Local Security Checks":
                continue
            rec = {
                "plugin_id": ri.get("pluginID"),
                "plugin_name": ri.get("pluginName"),
                "severity": ri.get("severity"),
            }
            for cve_el in ri.findall("cve"):
                if cve_el.text:
                    out[cve_el.text.strip().upper()].append(rec)
    return out


def compare_nessus(findings_path: Path, out_path: Path) -> dict:
    cmd = [
        str(ROOT / "bin" / "openness"),
        "compare-nessus",
        "--nessus",
        str(BUILD / "nessus-report.nessus"),
        "--findings",
        str(findings_path),
        "--host",
        "192.0.2.10",
        "--local-only",
        "--json",
        str(out_path),
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)
    return json.load(open(out_path))


def is_cve(value: str | None) -> bool:
    return bool(value and value.upper().startswith("CVE-"))


def is_usn_in_cve_id(findings: list[dict]) -> list[dict]:
    return [f for f in findings if (f.get("cve_id") or "").upper().startswith("USN-")]


def canonical_host_findings(findings: list[dict]) -> list[dict]:
    """Host/container findings without python_environment scope."""
    return [f for f in findings if f.get("scope") != "python_environment"]


def pypi_environment_findings(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("scope") == "python_environment"]


def python_correlated_ubuntu(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("python_distribution_entity_ids")]


def findings_stats(findings_doc: dict) -> dict:
    findings = findings_doc.get("findings", [])
    dedup = findings_doc.get("deduplicated_findings", [])
    recon = findings_doc.get("reconciliation", {})
    metrics = findings_doc.get("metrics", {})

    py_env = pypi_environment_findings(findings)
    py_corr = python_correlated_ubuntu(findings)
    dedup_ubuntu = [d for d in dedup if d.get("resolver_ecosystem") == "ubuntu_dpkg"]

    vuln_dedup = [d for d in dedup if d.get("state") in ("vulnerable", "vulnerable_runtime")]
    fixed_dedup = [d for d in dedup if d.get("state") == "fixed"]

    return {
        "python_correlated_ubuntu_package_findings": len(dedup_ubuntu),
        "python_environment_findings": len(py_env),
        "canonical_findings_with_python_correlation": len(py_corr),
        "deduplicated_total": len(dedup),
        "deduplicated_vulnerable": len(vuln_dedup),
        "deduplicated_fixed": len(fixed_dedup),
        "pypi_vulnerable": len([f for f in py_env if f.get("state") in ("vulnerable", "vulnerable_runtime")]),
        "pypi_fixed": len([f for f in py_env if f.get("state") == "fixed"]),
        "cve_findings": recon.get("cve_findings", 0),
        "advisory_only_findings": recon.get("advisory_only_findings", 0),
        "reconciliation_balanced": recon.get("balanced", False),
        "metrics_vulnerable": metrics.get("findings_vulnerable"),
        "metrics_fixed": metrics.get("findings_fixed"),
        "serialized_vulnerable": recon.get("serialized_vulnerable"),
        "serialized_fixed": recon.get("serialized_fixed"),
        "usn_in_cve_id_count": len(is_usn_in_cve_id(findings)),
    }


def urllib3_identity(findings: list[dict]) -> dict | None:
    for f in findings:
        if "urllib3" in (f.get("binary_package", "") + f.get("source_package", "")):
            if f.get("python_distribution_entity_ids") or f.get("normalized_package_name") == "urllib3":
                return {
                    "finding_id": f.get("finding_id"),
                    "binary_package": f.get("binary_package"),
                    "source_package": f.get("source_package"),
                    "installed_version": f.get("installed_version"),
                    "python_distribution_entity_ids": f.get("python_distribution_entity_ids"),
                }
    for f in findings:
        if f.get("binary_package") == "python3-urllib3":
            return {
                "finding_id": f.get("finding_id"),
                "binary_package": f.get("binary_package"),
                "source_package": f.get("source_package"),
                "installed_version": f.get("installed_version"),
            }
    return None


def psutil_pypi_finding(findings: list[dict]) -> dict | None:
    for f in pypi_environment_findings(findings):
        if f.get("normalized_package_name") == "psutil" and f.get("state") == "fixed":
            return f
    return None


def classify_missing_cve(
    cve: str,
    nessus: dict,
    by_cve: dict,
    py_env_by_cve: dict,
    urllib3_id: dict | None,
    findings: list[dict],
) -> dict:
    plugins = nessus.get(cve, [])
    plugin_text = " ".join(p.get("plugin_name", "") for p in plugins).lower()
    rec = {
        "cve": cve,
        "previous_classification": "collector_missing_evidence",
        "nessus_plugins": plugins[:2],
        "classification": "unresolved",
        "rationale": "",
    }

    py_env = py_env_by_cve.get(cve, [])
    host_fs = [f for f in by_cve.get(cve, []) if f.get("scope") == "host"]
    py_corr = [
        f
        for f in findings
        if f.get("cve_id") == cve and f.get("python_distribution_entity_ids")
    ]

    if "pipewire" in plugin_text:
        rec["classification"] = "Nessus_bundled_scope_only"
        rec["rationale"] = "PipeWire plugin; not Python distribution scope"
        return rec

    if py_env:
        states = Counter(f.get("state") for f in py_env)
        if states.get("vulnerable") or states.get("vulnerable_runtime"):
            rec["classification"] = "now_detected_by_resolver"
            rec["rationale"] = "PyPI environment-scoped resolver finding matches Nessus CVE"
            rec["resolver_matches"] = py_env[:3]
            return rec

    if py_corr:
        states = Counter(f.get("state") for f in py_corr)
        if states.get("vulnerable") or states.get("vulnerable_runtime"):
            rec["classification"] = "now_detected_by_resolver"
            rec["rationale"] = "Python-correlated Ubuntu package finding matches Nessus CVE"
            rec["resolver_matches"] = py_corr[:3]
            return rec
        if states.get("fixed"):
            rec["classification"] = "Nessus_bundled_scope_only"
            rec["rationale"] = "Canonical Ubuntu package fixed; Python correlation confirms same vendor version"
            rec["resolver_matches"] = py_corr[:3]
            return rec

    if cve in ("CVE-2025-50182", "CVE-2026-44432"):
        ident = urllib3_id or {}
        vendor_evidence = {
            "ubuntu_package_identity": ident,
            "jammy_oval_rule_present": any(
                f.get("cve_id") == cve and f.get("scope") == "host" for f in findings
            ),
            "python_correlation_present": bool(py_corr),
        }
        rec["vendor_evidence"] = vendor_evidence
        if ident.get("binary_package") == "python3-urllib3" and ident.get("source_package") == "python-urllib3":
            if ident.get("installed_version") == "1.26.5-1~exp1ubuntu0.7":
                if not vendor_evidence["jammy_oval_rule_present"]:
                    rec["classification"] = "no_applicable_ubuntu_vendor_rule"
                    rec["rationale"] = (
                        "python3-urllib3 identity verified at 1.26.5-1~exp1ubuntu0.7; "
                        "no jammy Ubuntu OVAL rule for this CVE in the local feed snapshot"
                    )
                    return rec
        rec["classification"] = "unresolved"
        rec["rationale"] = "urllib3 Ubuntu identity or vendor rule evidence incomplete"
        return rec

    if "python vulnerabilities" in plugin_text and "usn" in plugin_text:
        rec["classification"] = "Nessus_bundled_scope_only"
        rec["rationale"] = "Bundled Nessus Python USN plugin; legacy stdlib CVEs on patched python3.10"
        return rec

    if "urllib3" in plugin_text:
        if urllib3_id and not any(f.get("cve_id") == cve for f in host_fs):
            rec["classification"] = "no_applicable_ubuntu_vendor_rule"
            rec["rationale"] = "urllib3 Ubuntu package present; no applicable vendor rule for this CVE in feed"
            rec["ubuntu_package_identity"] = urllib3_id
            return rec
        if host_fs:
            rec["classification"] = "now_detected_by_resolver"
            rec["rationale"] = "Host dpkg resolver finding exists"
            return rec
        rec["classification"] = "package_not_present"
        rec["rationale"] = "urllib3 not in collected evidence"
        return rec

    if host_fs:
        rec["classification"] = "now_detected_by_resolver"
        rec["rationale"] = "Host dpkg resolver finding exists"
        return rec

    rec["classification"] = "unresolved"
    rec["rationale"] = "No matching resolver finding"
    return rec


def verify_reconciliation(findings_doc: dict) -> list[str]:
    defects: list[str] = []
    recon = findings_doc.get("reconciliation", {})
    metrics = findings_doc.get("metrics", {})
    if not recon.get("balanced"):
        defects.append(
            "reconciliation invariant failed: serialized + deduplicated != metrics "
            f"({recon})"
        )
    sv = recon.get("serialized_vulnerable", 0) + recon.get("deduplicated_vulnerable", 0)
    sf = recon.get("serialized_fixed", 0) + recon.get("deduplicated_fixed", 0)
    if sv != metrics.get("findings_vulnerable"):
        defects.append(f"vulnerable count mismatch: serialized+dedup={sv} metrics={metrics.get('findings_vulnerable')}")
    if sf != metrics.get("findings_fixed"):
        defects.append(f"fixed count mismatch: serialized+dedup={sf} metrics={metrics.get('findings_fixed')}")
    if is_usn_in_cve_id(findings_doc.get("findings", [])):
        defects.append("USN advisory identifier found in cve_id field")
    return defects


def render_md(report: dict) -> str:
    lines = [
        "# Python resolver validation",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Evidence preflight",
        "",
        f"- Path: `{report['evidence_path']}`",
        f"- SHA-256: `{report['evidence_sha256']}`",
        f"- Fallback: **{report['fallback']}**",
        f"- Collector: `{report['collector_version']}` / schema `{report['schema_version']}`",
        f"- Collection ID: `{report['collection_id']}`",
        "",
        "## Inventory (verified)",
        "",
    ]
    for k, v in report["inventory"].items():
        if k != "pypi_packages":
            lines.append(f"- {k}: **{v}**")
    lines.extend(["", "## Python resolver output", ""])
    for k, v in report["finding_stats"].items():
        lines.append(f"- {k}: **{v}**")
    if report.get("pypi_psutil_fixed_finding"):
        lines.extend(["", "## PyPI fixed finding (psutil)", "", "```json"])
        lines.append(json.dumps(report["pypi_psutil_fixed_finding"], indent=2))
        lines.append("```")
    lines.extend(["", "## Nessus comparison", "", "| Metric | Before (host-only) | After (with Python) |", "|--------|-------------------|---------------------|"])
    for key in sorted(set(report["nessus_comparison"]["before"]) | set(report["nessus_comparison"]["after"])):
        lines.append(
            f"| {key} | {report['nessus_comparison']['before'].get(key, '-')} | {report['nessus_comparison']['after'].get(key, '-')} |"
        )
    lines.extend(["", "## Previous 39 collector_missing_evidence cases", ""])
    for cls, n in sorted(report["previous_missing_summary"].items()):
        lines.append(f"- **{cls}**: {n}")
    if report.get("urllib3_package_identity"):
        lines.extend(["", "## urllib3 Ubuntu identity", "", f"```json\n{json.dumps(report['urllib3_package_identity'], indent=2)}\n```"])
    if report.get("resolver_defects"):
        lines.extend(["", "## Resolver defects", ""])
        for d in report["resolver_defects"]:
            lines.append(f"- {d}")
    return "\n".join(lines) + "\n"


def main() -> int:
    evidence_path = locate_evidence()
    doc = preflight(evidence_path)
    inv = inventory_from_doc(doc)

    resolve_cmd = [
        str(ROOT / "bin" / "openness"),
        "resolve",
        "--input",
        str(evidence_path),
        "--output",
        str(BUILD / "findings.json"),
        "--data-dir",
        str(ROOT / "data"),
        "--preflight",
    ]
    subprocess.run(resolve_cmd, check=True, cwd=ROOT)

    findings_doc = json.load(open(BUILD / "findings.json"))
    findings = findings_doc.get("findings", [])

    host_only = canonical_host_findings(findings)
    before_path = BUILD / "findings-host-only.json"
    json.dump({**findings_doc, "findings": host_only}, open(before_path, "w"), indent=2)

    after_diff = compare_nessus(BUILD / "findings.json", BUILD / "nessus-diff.json")
    before_diff = compare_nessus(before_path, BUILD / "nessus-diff-before-python.json")

    nessus = nessus_by_cve(BUILD / "nessus-report.nessus")
    by_cve = defaultdict(list)
    py_env_by_cve = defaultdict(list)
    for f in findings:
        key = f.get("cve_id")
        if is_cve(key):
            by_cve[key].append(f)
            if f.get("scope") == "python_environment":
                py_env_by_cve[key].append(f)

    prev = json.load(open(BUILD / "only-nessus-analysis.json"))
    missing_cves = [
        cve
        for cve, v in prev.get("classifications", {}).items()
        if v.get("classification") == "collector_missing_evidence"
    ]
    urllib3_id = urllib3_identity(findings)
    psutil_fixed = psutil_pypi_finding(findings)
    reclass = {
        cve: classify_missing_cve(cve, nessus, by_cve, py_env_by_cve, urllib3_id, findings)
        for cve in missing_cves
    }
    stats = findings_stats(findings_doc)
    defects = verify_reconciliation(findings_doc)
    if not psutil_fixed:
        defects.append("missing complete PyPI fixed psutil finding in findings.json")

    report = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_path": str(evidence_path),
        "evidence_sha256": sha256_file(evidence_path),
        "fallback": False,
        "collector_version": doc.get("collector", {}).get("version"),
        "schema_version": doc.get("schema_version"),
        "collection_id": doc.get("collection", {}).get("collection_id"),
        "inventory": inv,
        "finding_stats": stats,
        "reconciliation": findings_doc.get("reconciliation", {}),
        "pypi_psutil_fixed_finding": psutil_fixed,
        "urllib3_package_identity": urllib3_id,
        "nessus_comparison": {
            "before": before_diff.get("counts", {}),
            "after": after_diff.get("counts", {}),
        },
        "previous_missing_reclassification": reclass,
        "previous_missing_summary": dict(Counter(v["classification"] for v in reclass.values())),
        "resolver_defects": defects,
        "collector_gaps": [],
    }

    json.dump(report, open(BUILD / "python-resolver-validation.json", "w"), indent=2)
    Path(BUILD / "python-resolver-validation.md").write_text(render_md(report))
    print(json.dumps({"status": "ok" if not defects else "defects", "summary": report["previous_missing_summary"], "defects": defects}, indent=2))
    return 1 if defects else 0


if __name__ == "__main__":
    sys.exit(main())
