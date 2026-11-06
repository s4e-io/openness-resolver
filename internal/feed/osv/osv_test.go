package osv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchPackageUsesEndpointAndHeaders(t *testing.T) {
	var gotHeader, gotName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-OpenNess-License")
		var body struct {
			Package struct{ Name string } `json:"package"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotName = body.Package.Name
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()
	oldE, oldH := Endpoint, Headers
	defer func() { Endpoint, Headers = oldE, oldH }()
	Endpoint = srv.URL + "/data/v1/osv/query"
	Headers = ParseHeaders("X-OpenNess-License: doc\nbroken line\n")

	if _, err := FetchPackage(nil, "requests"); err != nil {
		t.Fatal(err)
	}
	if gotHeader != "doc" || gotName != "requests" {
		t.Fatalf("header %q name %q", gotHeader, gotName)
	}
	if len(Headers) != 1 {
		t.Fatalf("malformed header lines must be skipped: %v", Headers)
	}
}

func TestSyncPackagesRejectsTraversalBeforeWriting(t *testing.T) {
	root := t.TempDir()
	_, _, err := SyncPackages(root, []string{"../../escape"})
	if err == nil {
		t.Fatal("expected invalid package name")
	}
	if _, err := os.Stat(filepath.Join(root, "raw")); !os.IsNotExist(err) {
		t.Fatalf("raw cache created for invalid name: %v", err)
	}
}
