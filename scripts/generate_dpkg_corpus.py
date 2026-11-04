#!/usr/bin/env python3
"""Generate dpkg version comparison pairs for the fixture corpus.

Development/CI tool only (the production resolver is pure Go). The pairs
emitted here are labeled by native `dpkg --compare-versions` inside an
Ubuntu container via generate_dpkg_corpus.sh.

Usage: generate_dpkg_corpus.py [path-to-.openness-file] > pairs.txt
"""
import itertools
import json
import random
import sys

random.seed(42)

# Hand-picked tricky versions covering epoch, tilde, letters, long numerics,
# ubuntu/debian/esm suffixes and dfsg markers.
CURATED = [
    "1:8.9p1-3ubuntu0.15", "1:8.9p1-3ubuntu0.16", "1:8.9p1-3ubuntu0.9",
    "1.2.3~rc1-0ubuntu1", "1.2.3-0ubuntu1", "1.2.3-0ubuntu2",
    "2:1.0-1", "1:99.0-99", "1.0-1ubuntu1", "1.0-1ubuntu2",
    "1.0", "1.0-0", "1.0-1", "1.0~", "1.0~~", "1.0~rc1", "1.0~rc2",
    "1.0a", "1.0b", "1.0+1", "1.0a1", "1.0+b1", "1.0.1",
    "1.01", "1.1", "1.10", "1.9",
    "0.0.1", "0.1", "0:1.0",
    "1.999999999999999999999999998", "1.999999999999999999999999999",
    "3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.16", "3.0.2-0ubuntu1.18",
    "1.13.1+dfsg-1ubuntu0.1~esm1", "1.13.1+dfsg-1ubuntu0.1",
    "2.9.13+dfsg-1ubuntu0.4", "2.9.13+dfsg-1ubuntu0.7",
    "1:1.2.11.dfsg-2ubuntu9.2", "1:1.2.11.dfsg-2ubuntu9",
    "2.35-0ubuntu3.8", "2.35-0ubuntu3.10", "2.35-0ubuntu3",
    "6.8.0-106.108", "6.8.0-99.99", "6.8.0-106.108~22.04.1",
    "5.15.0-1053.58", "5.15.0-1053.58+fips1",
    "1.21.2really1.21.1-0ubuntu1", "1.21.2-0ubuntu1",
    "0ubuntu1", "0ubuntu0.1",
    "2022.02.08", "2022.2.8",
    "1.0-1+deb11u1", "1.0-1+deb12u1", "1.0-1ubuntu1~esm2",
    "9.20160110ubuntu0.2", "9.20160110ubuntu1",
    "1.19.2-2ubuntu0.1", "1.19.2-2build1", "1.19.2-2",
]

MUTATIONS = ["~", "~rc1", "a", "+b1", ".1", "0", "-0", "-1", "+dfsg", "~esm1"]


def real_versions(path, limit=120):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    vers = []
    for rec in doc.get("packages", []):
        v = rec.get("value", {})
        if v.get("package_manager") == "dpkg" and v.get("raw_version_string"):
            vers.append(v["raw_version_string"])
    vers = sorted(set(vers))
    random.shuffle(vers)
    return vers[:limit]


def mutate(v):
    out = set()
    out.add(v + random.choice(MUTATIONS))
    if "-" in v:
        head, _, rev = v.rpartition("-")
        out.add(head + "-" + rev + ".1")
        out.add(head)
    if ":" in v:
        out.add(v.split(":", 1)[1])
    else:
        out.add("1:" + v)
    return out


def main():
    versions = list(CURATED)
    if len(sys.argv) > 1:
        versions += real_versions(sys.argv[1])

    pairs = set()
    # All curated pairwise combinations.
    for a, b in itertools.combinations(CURATED, 2):
        pairs.add((a, b))
    # Each real version against mutations of itself (targeted ordering checks).
    for v in versions:
        for m in mutate(v):
            pairs.add((v, m))
        pairs.add((v, v))  # equality case
    # Random cross pairs from the full pool.
    pool = list(versions)
    while len(pairs) < 2500:
        pairs.add((random.choice(pool), random.choice(pool)))

    for a, b in sorted(pairs):
        print(f"{a} {b}")


if __name__ == "__main__":
    main()
