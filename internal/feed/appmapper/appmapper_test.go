package appmapper

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/s4e-io/openness-resolver/internal/appvuln"
)

func bundle(t *testing.T, version string) []byte {
	t.Helper()
	var raw bytes.Buffer
	cat := `[{"id":"acme.tool","name":"Acme Tool","match":{"name":"^Acme Tool"},"cpe":["acme:tool"],"verified":true}]`
	if err := appvuln.WriteBundle(&raw, version, []byte(cat), []byte(`{"version":"v","products":{}}`), []byte(`{"products":{}}`)); err != nil {
		t.Fatal(err)
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(raw.Bytes())
	zw.Close()
	return z.Bytes()
}

// release serves a fake GitHub release: the bundle and SHA256SUMS, or 404 for both.
func release(t *testing.T, body []byte, sums string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case body == nil:
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
			w.Write([]byte(sums))
		case strings.HasSuffix(r.URL.Path, "/app-mapper.json.gz"):
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sumLine(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]) + "  app-mapper.json.gz\n"
}

func TestSync(t *testing.T) {
	b := bundle(t, "2026.11.05")
	srv := release(t, b, "0000000000000000000000000000000000000000000000000000000000000000  other.bin\n"+sumLine(b))
	url := srv.URL + "/releases/latest/download/app-mapper.json.gz"
	dir := t.TempDir()
	now := time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC)

	// validate: checked, nothing kept
	if _, err := Sync(url, dir, false, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(Path(dir)); err == nil {
		t.Fatal("validate kept the bundle")
	}

	meta, err := Sync(url, dir, true, false, now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := appvuln.ReadMeta(Path(dir))
	if !ok || got != meta || meta.Version != "2026.11.05" || meta.SourceURL != url || !meta.DownloadedAt.Equal(now) ||
		meta.SizeBytes != int64(len(b)) || meta.Format != appvuln.BundleFormat || meta.Source != ID {
		t.Fatalf("meta %+v, read %+v", meta, got)
	}
	d, err := appvuln.LoadFile(Path(dir))
	if err != nil || d.Version != "2026.11.05" {
		t.Fatalf("installed bundle: %v", err)
	}
}

func TestSyncRefuses(t *testing.T) {
	b := bundle(t, "x")
	dir := t.TempDir()
	path := "/releases/latest/download/app-mapper.json.gz"

	bad := release(t, b, strings.Repeat("a", 64)+"  app-mapper.json.gz\n")
	if _, err := Sync(bad.URL+path, dir, true, false, time.Now()); err == nil || !strings.Contains(err.Error(), "does not match SHA256SUMS") {
		t.Errorf("checksum mismatch: %v", err)
	}
	missing := release(t, b, sumLine(b)[:64]+"  other.json.gz\n")
	if _, err := Sync(missing.URL+path, dir, true, false, time.Now()); err == nil || !strings.Contains(err.Error(), "has no sha256 for app-mapper.json.gz") {
		t.Errorf("no checksum line: %v", err)
	}
	notMapper := []byte(`{"format":"other/1"}`)
	wrong := release(t, notMapper, sumLine(notMapper))
	if _, err := Sync(wrong.URL+path, dir, true, false, time.Now()); err == nil || !strings.Contains(err.Error(), `want "openness-app-mapper/1"`) {
		t.Errorf("wrong format: %v", err)
	}
	gone := release(t, nil, "")
	_, err := Sync(gone.URL+path, dir, true, false, time.Now())
	if !errors.Is(err, ErrNotPublished) || !strings.Contains(err.Error(), "not published yet") {
		t.Errorf("404: %v", err)
	}
	if _, err := Sync("ftp://example.org/app-mapper.json.gz", dir, true, false, time.Now()); err == nil {
		t.Error("ftp URL accepted")
	}
	if _, err := os.Stat(Path(dir)); err == nil {
		t.Error("a refused bundle was installed")
	}
}

func TestSumsURL(t *testing.T) {
	if got := SumsURL("https://github.com/s4e-io/openness-catalog/releases/latest/download/app-mapper.json.gz"); got != "https://github.com/s4e-io/openness-catalog/releases/latest/download/SHA256SUMS" {
		t.Error(got)
	}
}

// A mapper older than the synced one or the built-in one is never installed silently.
func TestSyncRefusesDowngrade(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
			w.Write([]byte(sumLine(body)))
			return
		}
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	url := srv.URL + "/releases/latest/download/app-mapper.json.gz"
	dir := t.TempDir()
	now := time.Now()

	body = bundle(t, "2099.01.02")
	if _, err := Sync(url, dir, true, false, now); err != nil {
		t.Fatal(err)
	}
	body = bundle(t, "2099.01.01")
	_, err := Sync(url, dir, true, false, now)
	if !errors.Is(err, ErrOlder) || !strings.Contains(err.Error(), "older than the synced one (2099.01.02)") {
		t.Fatalf("downgrade: %v", err)
	}
	if m, _ := appvuln.ReadMeta(Path(dir)); m.Version != "2099.01.02" {
		t.Fatalf("the current mapper was replaced: %+v", m)
	}
	if _, err := Sync(url, dir, true, true, now); err != nil {
		t.Fatal(err)
	}
	if m, _ := appvuln.ReadMeta(Path(dir)); m.Version != "2099.01.01" {
		t.Fatalf("allowDowngrade did not install: %+v", m)
	}
	// the same version again is not a downgrade
	if _, err := Sync(url, dir, true, false, now); err != nil {
		t.Fatalf("same version: %v", err)
	}

	empty := t.TempDir()
	body = bundle(t, "2000.01.01")
	if _, err := Sync(url, empty, true, false, now); !errors.Is(err, ErrOlder) || !strings.Contains(err.Error(), "older than the built-in one") {
		t.Fatalf("older than built-in: %v", err)
	}
	if _, err := os.Stat(Path(empty)); err == nil {
		t.Fatal("a mapper older than the built-in one was installed")
	}
}
