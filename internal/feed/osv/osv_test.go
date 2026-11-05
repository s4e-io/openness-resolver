package osv

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

const twoPackages = `{"id":"GHSA-aaaa","aliases":["CVE-2026-1111"],"affected":[
 {"package":{"ecosystem":"PyPI","name":"Foo_Bar"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2"},{"introduced":"2.0"},{"fixed":"2.1"}]}]},
 {"package":{"ecosystem":"PyPI","name":"baz"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
 {"package":{"ecosystem":"npm","name":"foo"},"ranges":[]}]}`

func writeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "all.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	f.Close()
	return path
}

func TestParseArchive(t *testing.T) {
	path := writeZip(t, map[string]string{
		"GHSA-aaaa.json": twoPackages,
		"PYSEC-old.json": `{"id":"PYSEC-old","withdrawn":"2025-01-01T00:00:00Z","aliases":["CVE-2020-1"],"affected":[{"package":{"ecosystem":"PyPI","name":"foo-bar"}}]}`,
		"NOCVE.json":     `{"id":"GHSA-nocve","affected":[{"package":{"ecosystem":"PyPI","name":"x"}}]}`,
		"bad.json":       `{`,
	})
	res, err := ParseFile(path, rules.FeedSourceMetadata{SourceURL: "u", RawObjectID: "raw"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 2 {
		t.Fatalf("rules %+v", res.Rules)
	}
	byPkg := map[string]rules.PackageVulnerabilityRule{}
	for _, r := range res.Rules {
		byPkg[r.PackageName] = r
	}
	if r := byPkg["foo-bar"]; r.FixedVersion != "2.1" || r.Status != rules.StatusReleased || r.CVEID != "CVE-2026-1111" || r.Distribution != "pypi" || r.Comparator != "pep440" {
		t.Errorf("foo-bar %+v", r)
	}
	if r := byPkg["baz"]; r.FixedVersion != "" || r.Status != rules.StatusNeeded {
		t.Errorf("baz %+v", r)
	}
	if res.Metrics.RejectionReasons["withdrawn"] != 1 || res.Metrics.RejectionReasons["document_decode_error"] != 1 {
		t.Errorf("metrics %+v", res.Metrics)
	}
}

func TestParseArchiveRejectsDamagedDownload(t *testing.T) {
	path := writeZip(t, map[string]string{"a.json": twoPackages})
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, raw[:len(raw)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile(path, rules.FeedSourceMetadata{}); err == nil {
		t.Fatal("a truncated archive must not parse")
	}
}

func TestPublishWritesFullFeed(t *testing.T) {
	dir := t.TempDir()
	store := rules.NewStore(dir)
	res := ParseDocuments([][]byte{[]byte(twoPackages)}, rules.FeedSourceMetadata{})
	if err := Publish(store, res, rules.FeedSourceMetadata{SourceName: SourceID, PackageNames: []string{"old"}}); err != nil {
		t.Fatal(err)
	}
	meta, err := store.LoadMetadata(Vendor, Release)
	if err != nil || meta.SourceName != SourceID || len(meta.PackageNames) != 0 {
		t.Fatalf("meta %+v %v", meta, err)
	}
	got, _ := store.LoadRules(Vendor, Release)
	if len(got) != 2 {
		t.Fatalf("rules %d", len(got))
	}
}
