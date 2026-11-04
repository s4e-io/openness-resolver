package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// releaseFeed builds the advisory sources of one vendor for any release the
// vendor publishes. Releases are derived from the asset instead of being
// enumerated in Registry, so a release needs no code change to be covered.
type releaseFeed struct {
	name      string
	ecosystem string
	format    string
	parser    string
	idPrefix  string
	shape     string
	pattern   *regexp.Regexp
	documents func(release string) []releaseDocument
}

type releaseDocument struct {
	idSuffix string
	url      string
}

var releaseFeeds = map[string]releaseFeed{
	"ubuntu": {
		name:      "Ubuntu USN OVAL",
		ecosystem: "dpkg",
		format:    "oval-xml-bz2",
		parser:    "ubuntu-oval",
		idPrefix:  "ubuntu-oval-usn-",
		shape:     "release codename (jammy, noble, ...)",
		pattern:   regexp.MustCompile(`^[a-z]+$`),
		documents: func(release string) []releaseDocument {
			return []releaseDocument{{
				url: "https://security-metadata.canonical.com/oval/com.ubuntu." + release + ".usn.oval.xml.bz2",
			}}
		},
	},
	"microsoft": {
		name:      "MSRC CVRF",
		ecosystem: "winbuild",
		format:    "cvrf-json",
		parser:    "msrc-cvrf",
		idPrefix:  "msrc-cvrf-",
		shape:     "month (2026-Oct)",
		pattern:   regexp.MustCompile(`^[0-9]{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$`),
		documents: func(release string) []releaseDocument {
			return []releaseDocument{{url: "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + release}}
		},
	},
	"alpine": {
		name:      "Alpine secdb",
		ecosystem: "apk",
		format:    "secdb-json",
		parser:    "alpine-secdb",
		idPrefix:  "alpine-secdb-",
		shape:     "branch (v3.18, v3.19, ...)",
		pattern:   regexp.MustCompile(`^v[0-9]+\.[0-9]+$`),
		documents: func(release string) []releaseDocument {
			return []releaseDocument{
				{url: "https://secdb.alpinelinux.org/" + release + "/main.json"},
				{idSuffix: "-community", url: "https://secdb.alpinelinux.org/" + release + "/community.json"},
			}
		},
	},
	"amazon": {
		name:      "Amazon Linux updateinfo",
		ecosystem: "rpm",
		format:    "updateinfo-mirrorlist",
		parser:    "amazon-updateinfo",
		idPrefix:  "amazon-updateinfo-",
		shape:     "release (2, 2023)",
		pattern:   regexp.MustCompile(`^(2|2023)$`),
		documents: func(release string) []releaseDocument {
			// The mirror list names the current core repository; its
			// repodata/updateinfo.xml.gz lists every ALAS advisory of the
			// release for all architectures.
			path := "al2023/core/mirrors/latest"
			if release == "2" {
				path = "2/core/latest"
			}
			return []releaseDocument{{url: "https://cdn.amazonlinux.com/" + path + "/x86_64/mirror.list"}}
		},
	},
}

// AlpineBranches are the Alpine branches synced by `feed sync --vendor
// alpine` and `--all`. They follow the platform support matrix; a host or
// image on another branch still syncs its own branch through --for.
var AlpineBranches = []string{"v3.14", "v3.15", "v3.16", "v3.17", "v3.18", "v3.19", "v3.20", "v3.21", "v3.22"}

// AmazonReleases are the Amazon Linux releases with an updateinfo source.
var AmazonReleases = []string{"2", "2023"}

// releaseRegistry expands release-derived feeds into registry entries.
func releaseRegistry(vendor string, releases []string) []AdvisorySource {
	var out []AdvisorySource
	for _, r := range releases {
		srcs, err := ReleaseSources(vendor, r)
		if err != nil {
			panic(err) // static release lists; a bad entry is a programming error
		}
		out = append(out, srcs...)
	}
	return out
}

// ReleaseSources returns the advisory sources needed to evaluate one
// (vendor, release) pair. The release is validated before it reaches a URL.
func ReleaseSources(vendor, release string) ([]AdvisorySource, error) {
	v := strings.ToLower(strings.TrimSpace(vendor))
	f, ok := releaseFeeds[v]
	if !ok {
		return nil, fmt.Errorf("vendor %q has no release feed", vendor)
	}
	r := strings.TrimSpace(release)
	if v != "microsoft" {
		r = strings.ToLower(r)
	}
	if !f.pattern.MatchString(r) {
		return nil, fmt.Errorf("%s: invalid release %q, expected %s", v, release, f.shape)
	}
	docs := f.documents(r)
	out := make([]AdvisorySource, 0, len(docs))
	for _, d := range docs {
		out = append(out, AdvisorySource{
			ID:              f.idPrefix + r + d.idSuffix,
			Name:            f.name + " (" + r + ")",
			Ecosystem:       f.ecosystem,
			Vendor:          v,
			URL:             d.url,
			Format:          f.format,
			Priority:        1,
			Enabled:         true,
			Parser:          f.parser,
			RefreshInterval: 24 * time.Hour,
		})
	}
	return out, nil
}

// MSRCMonths returns the last n MSRC monthly document ids ending with the
// month of now (newest first), e.g. ["2026-Oct", "2026-Sep", ...]. Windows
// servicing is cumulative but each month's document lists its own CVEs, so a
// host needs every month since its product shipped; 24 covers two years.
func MSRCMonths(n int, now time.Time) []string {
	if n <= 0 {
		n = 24
	}
	out := make([]string, 0, n)
	t := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		out = append(out, t.Format("2006-Jan"))
		t = t.AddDate(0, -1, 0)
	}
	return out
}

// MSRCSources builds the advisory sources for the last n MSRC months.
func MSRCSources(n int, now time.Time) []AdvisorySource {
	var out []AdvisorySource
	for _, m := range MSRCMonths(n, now) {
		srcs, err := ReleaseSources("microsoft", m)
		if err == nil {
			out = append(out, srcs...)
		}
	}
	return out
}

// distroFeeds maps a host distribution to the single registry source that
// covers every one of its releases.
var distroFeeds = map[string]string{
	"debian":    "debian-security-tracker",
	"rocky":     "osv-rocky",
	"almalinux": "osv-almalinux",
	"rhel":      "osv-rhel",
	"opensuse":  "osv-opensuse",
}

// HostSources returns the advisory sources a host of (distribution,
// release) needs. Distributions published as one document for all releases
// (Debian tracker, vendor OSV archives) return that registry source; others
// fall back to ReleaseSources.
func HostSources(distribution, release string) ([]AdvisorySource, error) {
	d := strings.ToLower(strings.TrimSpace(distribution))
	if id, ok := distroFeeds[d]; ok {
		if strings.TrimSpace(release) == "" {
			return nil, fmt.Errorf("%s: release missing from evidence", d)
		}
		src, ok := SourceByID(id)
		if !ok {
			return nil, fmt.Errorf("%s: registry source %s missing", d, id)
		}
		return []AdvisorySource{src}, nil
	}
	return ReleaseSources(d, release)
}

// mirrorIDs maps the source ids of the openness-backend data mirror (its manifest) to
// registry ids where the two differ.
var mirrorIDs = map[string]string{
	"debian-tracker": "debian-security-tracker",
	"osv-redhat":     "osv-rhel",
	"amazon-al2":     "amazon-updateinfo-2",
	"amazon-al2023":  "amazon-updateinfo-2023",
}

// ImportSource finds the source of `rules import`: a registry id, a release-derived id,
// or a data mirror id. A mirror source may hold several files (Alpine main.json and
// community.json), so the file name picks the document.
func ImportSource(id, fileName string) (AdvisorySource, bool) {
	if branch, ok := strings.CutPrefix(id, "alpine-secdb-"); ok && strings.HasPrefix(strings.ToLower(fileName), "community") && !strings.HasSuffix(branch, "-community") {
		return SourceByID("alpine-secdb-" + branch + "-community")
	}
	if s, ok := SourceByID(id); ok {
		return s, true
	}
	if mapped, ok := mirrorIDs[id]; ok {
		return SourceByID(mapped)
	}
	if month, ok := strings.CutPrefix(id, "msrc-"); ok {
		return SourceByID(releaseFeeds["microsoft"].idPrefix + month)
	}
	return AdvisorySource{}, false
}
