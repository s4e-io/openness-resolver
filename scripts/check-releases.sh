#!/bin/sh
# Lists the releases each publisher supports and whether their security data answers, to
# compare with docs/releases.md and internal/platform/platform.go. Reads only public URLs.
set -eu

code() { curl -s -o /dev/null -m 20 -w '%{http_code}' "$1"; }

echo "Ubuntu (meta-release, Supported: 1 = still supported by Canonical)"
curl -s -m 20 https://changelogs.ubuntu.com/meta-release https://changelogs.ubuntu.com/meta-release-development |
	awk '/^Dist:/{d=$2} /^Version:/{v=$2} /^Supported:/{s=$2} /^$/{if (d != "" && !seen[d]++) print d, v, s; d=""}' |
	while read -r dist version supported; do
		printf '  %-10s %-8s supported=%s  usn-oval=%s\n' "$dist" "$version" "$supported" \
			"$(code "https://security-metadata.canonical.com/oval/com.ubuntu.$dist.usn.oval.xml.bz2")"
	done

echo "Alpine (releases.json end of life, secdb main.json)"
curl -s -m 20 https://alpinelinux.org/releases.json |
	python3 -I -c 'import json, sys
for b in json.load(sys.stdin)["release_branches"]:
    if b["rel_branch"] != "edge":
        print(b["rel_branch"], b.get("eol_date"))' |
	while read -r branch eol; do
		printf '  %-6s eol=%s  secdb=%s\n' "$branch" "$eol" "$(code "https://secdb.alpinelinux.org/$branch/main.json")"
	done

echo "Debian (releases in the Security Tracker JSON)"
curl -s -m 60 https://security-tracker.debian.org/tracker/data/json |
	python3 -I -c 'import json, sys
seen = set()
for cves in json.load(sys.stdin).values():
    for info in cves.values():
        seen.update(info.get("releases", {}))
print("  " + " ".join(sorted(seen)))'

echo "OSV (advisories for openssl per release; 0 means none published)"
for eco in "Rocky Linux:8" "Rocky Linux:9" "Rocky Linux:10" "AlmaLinux:8" "AlmaLinux:9" "AlmaLinux:10" \
	"Red Hat:enterprise_linux:8::baseos" "Red Hat:enterprise_linux:9::baseos" "Red Hat:enterprise_linux:10::baseos"; do
	n=$(curl -s -m 20 -X POST https://api.osv.dev/v1/query \
		-d "{\"package\":{\"name\":\"openssl\",\"ecosystem\":\"$eco\"}}" |
		python3 -I -c 'import json, sys; print(len(json.load(sys.stdin).get("vulns", [])))')
	printf '  %-40s %s\n' "$eco" "$n"
done
