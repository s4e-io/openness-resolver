package feed

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

// Two sources with the same file name fetched within one second share a
// snapshot directory; neither raw object may replace the other.
func TestFetchKeepsSameNamedObjects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Path))
	}))
	defer srv.Close()
	fixed := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	d := &Downloader{Client: srv.Client(), DataDir: t.TempDir(), Now: func() time.Time { return fixed }}

	a, err := d.Fetch(rules.AdvisorySource{ID: "alpine-secdb-v3.19", Vendor: "alpine", URL: srv.URL + "/v3.19/main.json"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.Fetch(rules.AdvisorySource{ID: "alpine-secdb-v3.20", Vendor: "alpine", URL: srv.URL + "/v3.20/main.json"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Path == b.Path {
		t.Fatalf("both sources wrote %s", a.Path)
	}
	for path, want := range map[string]string{a.Path: "/v3.19/main.json", b.Path: "/v3.20/main.json"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Errorf("%s: %q %v, want %q", path, got, err, want)
		}
	}
}
