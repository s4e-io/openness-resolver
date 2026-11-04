#!/usr/bin/env python3
"""Generate APK version comparison pairs for the fixture corpus.

Development/CI tool only. Pairs are labeled by native `apk version -t`
inside an Alpine container via generate_apk_corpus.sh.

Usage: generate_apk_corpus.py [path-to-.openness-file] > pairs.txt
"""
import itertools
import json
import random
import sys

random.seed(1819)

CURATED = [
    "1.2.13-r0", "1.2.13-r1", "1.2.13-r2", "1.2.14-r0",
    "1.0", "1.0.1", "1.0-r0", "1.0-r1",
    "1.0_alpha", "1.0_alpha1", "1.0_alpha2", "1.0_beta", "1.0_pre", "1.0_rc1", "1.0_rc2",
    "1.0_p1", "1.0_p2", "1.0_git20230101", "1.0_cvs", "1.0_svn", "1.0_hg",
    "3.0.7-r0", "3.0.7-r2", "3.0.8-r0",
    "1.1.1l-r0", "1.1.1n-r0", "1.1.1t-r1",
    "3.1.4-r0", "3.1.4-r1", "3.1.5-r0",
    "2.14.0-r2", "2.14.0-r5", "2.14.4-r0",
    "1.36.1-r0", "1.36.1-r5", "1.36.1-r15", "1.36.1-r2",
    "1.05", "1.5", "1.005", "1.0005a",
    "0.9", "0.10", "0.99", "1.0a", "1.0b", "1.0z", "1.0a1",
    "20240410.030321", "20230901.000000",
    "6.4_p20230901-r0", "6.4_p20240101-r0",
    "1.2.2-r3", "1.2.2-r7", "1.2.4-r0",
    "3.4.3-r1", "3.4.3-r2", "3.2.0-r16",
    "9.3.0-r2", "10.1.0-r0",
    "1.9.4-r0", "1.10.0-r0",
    "2.38-r0", "2.38.1-r0",
    "0.8.1_rc1-r1", "0.8.1-r0",
]

MUTATIONS = ["-r0", "-r1", "-r99", "_alpha", "_rc1", "_p1", ".1", "a"]


def real_versions(path, limit=100):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    vers = set()
    for rec in doc.get("containers", []):
        for p in rec.get("value", {}).get("packages", []):
            if p.get("package_manager") == "apk" and p.get("raw_version_string"):
                vers.add(p["raw_version_string"])
    vers = sorted(vers)
    random.shuffle(vers)
    return vers[:limit]


def mutate(v):
    out = set()
    out.add(v + random.choice(MUTATIONS))
    if "-r" in v:
        head, _, rev = v.rpartition("-r")
        if rev.isdigit():
            out.add(f"{head}-r{int(rev) + 1}")
            out.add(head)
    return out


def main():
    versions = list(CURATED)
    if len(sys.argv) > 1:
        versions += real_versions(sys.argv[1])

    pairs = set()
    for a, b in itertools.combinations(CURATED, 2):
        pairs.add((a, b))
    for v in versions:
        for m in mutate(v):
            pairs.add((v, m))
        pairs.add((v, v))
    pool = list(versions)
    while len(pairs) < 2200:
        pairs.add((random.choice(pool), random.choice(pool)))

    for a, b in sorted(pairs):
        print(f"{a} {b}")


if __name__ == "__main__":
    main()
