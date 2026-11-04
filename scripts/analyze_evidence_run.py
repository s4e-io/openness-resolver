#!/usr/bin/env python3
"""Analyze one resolver evidence run and compare before/after update snapshots."""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"


def inventory_from_evidence(path: Path) -> dict:
    """Derive Python inventory counts only from the given .openness file."""
    doc = json.load(open(path))
    dist_entity_ids: set[str] = set()
    env_entity_ids: set[str] = set()
    process_entity_ids: set[str] = set()
    eco = Counter()
    runtime = Counter()
    confirmed_samples: list[dict] = []

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
            status = v.get("runtime_load_status") or ""
            runtime[status] += 1
            if status == "confirmed_loaded" and len(confirmed_samples) < 5:
                confirmed_samples.append(
                    {
                        "entity_id": eid,
                        "name_normalized": v.get("name_normalized"),
                        "environment_id": v.get("environment_id"),
                    }
                )

    return {
        "distributions": len(dist_entity_ids),
        "environments": len(env_entity_ids),
        "processes": len(process_entity_ids),
        "confirmed_loaded": runtime.get("confirmed_loaded", 0),
        "installed_not_proven_loaded": runtime.get("installed_not_proven_loaded", 0),
        "ecosystems": dict(eco),
        "confirmed_loaded_samples": confirmed_samples,
    }


def findings_by_state(findings: list[dict]) -> Counter:
    return Counter(f.get("state") for f in findings)


def host_vulnerable_count(findings: list[dict]) -> int:
    return sum(
        1 for f in findings if f.get("scope") == "host" and f.get("state") == "vulnerable"
    )


def metrics_vulnerable(doc: dict) -> int:
    return doc.get("metrics", {}).get("findings_vulnerable", 0)


def host_vulnerable_by_source(findings: list[dict]) -> Counter:
    out = Counter()
    for f in findings:
        if f.get("scope") == "host" and f.get("state") == "vulnerable":
            out[f.get("source_package") or ""] += 1
    return out


def resolve_evidence(evidence: Path, output: Path) -> dict:
    cmd = [
        str(ROOT / "bin" / "openness"),
        "resolve",
        "--input",
        str(evidence),
        "--output",
        str(output),
        "--data-dir",
        str(ROOT / "data"),
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)
    return json.load(open(output))


def compare_states(before: Counter, after: Counter) -> dict:
    return {
        "before_states": dict(before),
        "after_states": dict(after),
        "vulnerable_delta": after.get("vulnerable", 0) - before.get("vulnerable", 0),
        "fixed_delta": after.get("fixed", 0) - before.get("fixed", 0),
        "vulnerable_resolved": before.get("vulnerable", 0) - after.get("vulnerable", 0),
        "vulnerable_new": max(0, after.get("vulnerable", 0) - before.get("vulnerable", 0)),
        "fixed_new": max(0, after.get("fixed", 0) - before.get("fixed", 0)),
        "fixed_lost": max(0, before.get("fixed", 0) - after.get("fixed", 0)),
    }


def render_md(report: dict) -> str:
    inv = report["python_inventory"]
    cmp = report["compare_to_before_update"]
    lines = [
        f"# {report['prefix']} analysis",
        "",
        f"- Evidence: `{report['evidence']}`",
        f"- Collector: `{report['collector_version']}` / schema `{report['schema_version']}`",
        f"- Collection ID: `{report['collection_id']}`",
        f"- Host: `{report.get('host', '')}`",
        "",
        "## Python inventory (from .openness only)",
        f"- distributions: {inv['distributions']}",
        f"- environments: {inv['environments']}",
        f"- processes: {inv['processes']}",
        f"- confirmed_loaded: {inv['confirmed_loaded']}",
        f"- ecosystems: `{inv['ecosystems']}`",
        "",
        "### confirmed_loaded",
    ]
    if inv["confirmed_loaded_samples"]:
        for s in inv["confirmed_loaded_samples"]:
            lines.append(f"- {s['name_normalized']} ({s['entity_id']})")
    else:
        lines.append("- (none)")
    lines.extend(
        [
            "",
            "## Findings by state",
        ]
    )
    for state, n in sorted(report["findings_by_state"].items()):
        lines.append(f"- {state}: {n}")
    lines.extend(
        [
            "",
            "## Compare to before-update",
            f"- vulnerable (all findings): {cmp['before_states'].get('vulnerable', 0)} → {cmp['after_states'].get('vulnerable', 0)} (Δ {cmp['vulnerable_delta']})",
            f"- fixed (all findings): {cmp['before_states'].get('fixed', 0)} → {cmp['after_states'].get('fixed', 0)} (Δ {cmp['fixed_delta']:+d})",
            f"- host vulnerable: {cmp.get('before_host_vulnerable', 0)} → {cmp.get('after_host_vulnerable', 0)} (Δ {cmp.get('host_vulnerable_delta', 0)})",
            f"- metrics vulnerable: {cmp.get('before_metrics_vulnerable', 0)} → {cmp.get('after_metrics_vulnerable', 0)}",
            f"- vulnerable resolved (gone): {cmp['vulnerable_resolved']}",
            f"- vulnerable new: {cmp['vulnerable_new']}",
            f"- fixed new: {cmp['fixed_new']}",
            "",
            f"Full findings: `{report['prefix']}-findings.json`",
        ]
    )
    return "\n".join(lines) + "\n"


def analyze(evidence: Path, before: Path | None = None) -> dict:
    prefix = evidence.stem

    doc = json.load(open(evidence))
    findings_doc = resolve_evidence(evidence, BUILD / f"{prefix}-findings.json")
    findings = findings_doc.get("findings", [])
    states = findings_by_state(findings)

    report = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "prefix": prefix,
        "evidence": evidence.name,
        "collector_version": doc.get("collector", {}).get("version"),
        "schema_version": doc.get("schema_version"),
        "collection_id": doc.get("collection", {}).get("collection_id"),
        "host": doc.get("asset", {}).get("hostname"),
        "python_inventory": inventory_from_evidence(evidence),
        "findings_by_state": dict(states),
        "metrics": findings_doc.get("metrics", {}),
        "reconciliation": findings_doc.get("reconciliation", {}),
        "findings_total": len(findings),
        "host_vulnerable_by_source": dict(host_vulnerable_by_source(findings)),
        "host_vulnerable_total": sum(
            1 for f in findings if f.get("scope") == "host" and f.get("state") == "vulnerable"
        ),
    }

    if before is not None:
        before_path = BUILD / f"{before.stem}-findings.json"
        if not before_path.exists():
            before_doc = resolve_evidence(before, before_path)
        else:
            before_doc = json.load(open(before_path))
        before_states = findings_by_state(before_doc.get("findings", []))
        report["compare_to_before_update"] = compare_states(before_states, states)
        report["compare_to_before_update"]["before_metrics_vulnerable"] = metrics_vulnerable(before_doc)
        report["compare_to_before_update"]["after_metrics_vulnerable"] = metrics_vulnerable(findings_doc)
        report["compare_to_before_update"]["before_host_vulnerable"] = host_vulnerable_count(
            before_doc.get("findings", [])
        )
        report["compare_to_before_update"]["after_host_vulnerable"] = report["host_vulnerable_total"]
        report["compare_to_before_update"]["host_vulnerable_delta"] = (
            report["host_vulnerable_total"]
            - report["compare_to_before_update"]["before_host_vulnerable"]
        )

    json_path = BUILD / f"{prefix}-analysis.json"
    md_path = BUILD / f"{prefix}-analysis.md"
    json.dump(report, open(json_path, "w"), indent=2)
    md_path.write_text(render_md(report))
    return report


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: analyze_evidence_run.py <after.openness> <before.openness>")
    after = Path(sys.argv[1])
    before = Path(sys.argv[2])
    prefix = after.stem
    report = analyze(after, before)
    print(json.dumps(
        {
            "prefix": prefix,
            "host_vulnerable_total": report["host_vulnerable_total"],
            "host_vulnerable_by_source": report["host_vulnerable_by_source"],
            "compare": report.get("compare_to_before_update"),
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
