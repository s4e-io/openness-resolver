package rules

import (
	"strings"
	"testing"
)

func TestReleaseSourcesUbuntuAnyCodename(t *testing.T) {
	for _, codename := range []string{"jammy", "noble", "focal", "questing"} {
		srcs, err := ReleaseSources("ubuntu", codename)
		if err != nil {
			t.Fatalf("%s: %v", codename, err)
		}
		if len(srcs) != 1 {
			t.Fatalf("%s: want 1 source, got %d", codename, len(srcs))
		}
		wantID := "ubuntu-oval-usn-" + codename
		if srcs[0].ID != wantID {
			t.Errorf("%s: id=%q want %q", codename, srcs[0].ID, wantID)
		}
		wantURL := "https://security-metadata.canonical.com/oval/com.ubuntu." + codename + ".usn.oval.xml.bz2"
		if srcs[0].URL != wantURL {
			t.Errorf("%s: url=%q want %q", codename, srcs[0].URL, wantURL)
		}
		if srcs[0].Parser != "ubuntu-oval" {
			t.Errorf("%s: parser=%q", codename, srcs[0].Parser)
		}
	}
}

// Derived ids must match the ids Registry already publishes, because the
// downloader keys its ETag cache on them.
func TestReleaseSourceIDsMatchRegistry(t *testing.T) {
	for _, id := range []string{"ubuntu-oval-usn-jammy", "alpine-secdb-v3.18", "alpine-secdb-v3.18-community"} {
		if _, ok := SourceByID(id); !ok {
			t.Fatalf("registry has no %s", id)
		}
	}
	ubuntu, err := ReleaseSources("ubuntu", "jammy")
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := SourceByID("ubuntu-oval-usn-jammy")
	if ubuntu[0].ID != reg.ID || ubuntu[0].URL != reg.URL || ubuntu[0].Parser != reg.Parser || ubuntu[0].Format != reg.Format {
		t.Errorf("derived %+v does not match registry %+v", ubuntu[0], reg)
	}
	alpine, err := ReleaseSources("alpine", "v3.18")
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range alpine {
		got, ok := SourceByID(src.ID)
		if !ok {
			t.Fatalf("registry has no %s", src.ID)
		}
		if src.URL != got.URL || src.Parser != got.Parser || src.Format != got.Format {
			t.Errorf("derived %+v does not match registry %+v", src, got)
		}
	}
}

func TestReleaseSourcesAlpineMainAndCommunity(t *testing.T) {
	srcs, err := ReleaseSources("alpine", "v3.19")
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 2 {
		t.Fatalf("want 2 sources, got %d", len(srcs))
	}
	if srcs[0].ID != "alpine-secdb-v3.19" || srcs[1].ID != "alpine-secdb-v3.19-community" {
		t.Errorf("ids=%q,%q", srcs[0].ID, srcs[1].ID)
	}
	if srcs[1].URL != "https://secdb.alpinelinux.org/v3.19/community.json" {
		t.Errorf("url=%q", srcs[1].URL)
	}
}

func TestReleaseSourcesRejectsUnsafeRelease(t *testing.T) {
	bad := []struct{ vendor, release string }{
		{"ubuntu", ""},
		{"ubuntu", "../../etc/passwd"},
		{"ubuntu", "noble/../jammy"},
		{"ubuntu", "noble?x=1"},
		{"ubuntu", "v3.18"},
		{"alpine", "3.18"},
		{"alpine", "latest"},
		{"debian", "bookworm"},
		{"", "noble"},
	}
	for _, c := range bad {
		if srcs, err := ReleaseSources(c.vendor, c.release); err == nil {
			t.Errorf("%s:%s accepted, produced %d sources", c.vendor, c.release, len(srcs))
		}
	}
}

func TestHostSourcesVendorWideFeeds(t *testing.T) {
	cases := map[string]string{
		"debian":    "debian-security-tracker",
		"rocky":     "osv-rocky",
		"almalinux": "osv-almalinux",
		"rhel":      "osv-rhel",
		"opensuse":  "osv-opensuse",
	}
	for distro, id := range cases {
		srcs, err := HostSources(distro, "9")
		if err != nil || len(srcs) != 1 || srcs[0].ID != id || !srcs[0].Enabled {
			t.Errorf("%s: %+v %v", distro, srcs, err)
		}
		if _, err := HostSources(distro, ""); err == nil {
			t.Errorf("%s: empty release must fail", distro)
		}
	}
	if srcs, err := HostSources("ubuntu", "jammy"); err != nil || srcs[0].ID != "ubuntu-oval-usn-jammy" {
		t.Errorf("ubuntu falls back to release feeds: %+v %v", srcs, err)
	}
	for _, d := range []string{"oracle", "amazon", "centos", "sles"} {
		if _, err := HostSources(d, "9"); err == nil {
			t.Errorf("%s must have no source", d)
		}
	}
}

func TestNewSourcesRegistered(t *testing.T) {
	for _, id := range []string{"debian-security-tracker", "osv-rocky", "osv-almalinux", "osv-rhel", "osv-opensuse"} {
		s, ok := SourceByID(id)
		if !ok || !s.Enabled || s.Priority != 1 {
			t.Errorf("%s: %+v", id, s)
		}
		if !strings.HasPrefix(s.URL, "https://") {
			t.Errorf("%s: url %q", id, s.URL)
		}
	}
}

func TestAmazonReleaseSources(t *testing.T) {
	want := map[string]string{
		"2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
		"2":    "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
	}
	for release, url := range want {
		srcs, err := HostSources("amazon", release)
		if err != nil || len(srcs) != 1 {
			t.Fatalf("%s: %v %v", release, srcs, err)
		}
		s := srcs[0]
		if s.ID != "amazon-updateinfo-"+release || s.URL != url || s.Parser != "amazon-updateinfo" || s.Ecosystem != "rpm" {
			t.Errorf("%s: %+v", release, s)
		}
		if _, ok := SourceByID(s.ID); !ok {
			t.Errorf("%s: registry has no %s", release, s.ID)
		}
	}
	for _, bad := range []string{"", "2018", "2023.6", "../2023"} {
		if _, err := ReleaseSources("amazon", bad); err == nil {
			t.Errorf("release %q must be refused", bad)
		}
	}
}

// Every Alpine branch synced by --vendor alpine has a main and a community
// document in the registry.
func TestRegistryAlpineBranches(t *testing.T) {
	for _, b := range AlpineBranches {
		for _, id := range []string{"alpine-secdb-" + b, "alpine-secdb-" + b + "-community"} {
			s, ok := SourceByID(id)
			if !ok {
				t.Fatalf("registry has no %s", id)
			}
			if !s.Enabled || !strings.HasPrefix(s.URL, "https://secdb.alpinelinux.org/"+b+"/") {
				t.Errorf("%s: %+v", id, s)
			}
		}
	}
	ids := map[string]bool{}
	for _, s := range Registry() {
		if ids[s.ID] {
			t.Errorf("duplicate registry id %s", s.ID)
		}
		ids[s.ID] = true
	}
}

func TestImportSourceMirrorIDs(t *testing.T) {
	cases := []struct{ id, file, want string }{
		{"ubuntu-oval-usn-jammy", "com.ubuntu.jammy.usn.oval.xml.bz2", "ubuntu-oval-usn-jammy"},
		{"debian-tracker", "json", "debian-security-tracker"},
		{"osv-redhat", "all.zip", "osv-rhel"},
		{"osv-rocky", "all.zip", "osv-rocky"},
		{"amazon-al2", "updateinfo.xml.gz", "amazon-updateinfo-2"},
		{"amazon-al2023", "updateinfo.xml.gz", "amazon-updateinfo-2023"},
		{"msrc-2026-Oct", "2026-Oct.json", "msrc-cvrf-2026-Oct"},
		{"msrc-cvrf-2026-Oct", "2026-Oct.json", "msrc-cvrf-2026-Oct"},
		{"alpine-secdb-v3.20", "main.json", "alpine-secdb-v3.20"},
		{"alpine-secdb-v3.20", "community.json", "alpine-secdb-v3.20-community"},
	}
	for _, c := range cases {
		s, ok := ImportSource(c.id, c.file)
		if !ok || s.ID != c.want {
			t.Errorf("ImportSource(%q, %q) = %q, %v; want %q", c.id, c.file, s.ID, ok, c.want)
		}
	}
	if _, ok := ImportSource("nope", "x"); ok {
		t.Error("unknown id must not resolve")
	}
}
